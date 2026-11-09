#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM stack and control-flow opcode bodies (PUSH/DUP/SWAP, JUMP/JUMPI/PC).

Both RELATIVE opcode tables 0x6441210 and 0x6441f00 (index = opcode) name the same bodies.  This tool covers two
families of them and checks both with one evaluator, one comparison loop and one negative-control loop:

* family 1 (prefix ps_), opcodes 0x5f..0x9f: PUSH0..PUSH32, DUP1..DUP16 and SWAP1..SWAP16, 64 bodies (DUP2, body
  0x2995ab0, belongs to the merged packet RE-001-node115-stack-copy and is excluded).  PUSH0 returns 0x2b below spec
  0xa and 0x2d only when the length EQUALS 1024; PUSH1..32 return 0x2d at length >= 1024, else store the big-endian
  immediate and advance the bytecode cursor by n; DUPn returns 0x2d unless n <= length <= 1023 (so underflow is
  reported as 0x2d); SWAPn returns 0x2c below length n + 1 and has no upper check.  Each body's length bound, bias,
  cursor advance and gate are also derived from its decoded bytes and must follow the family rule.
* family 2 (prefix cf_), opcodes 0x00 0x56 0x57 0x58 0x59 0x5b 0xe6 0xe7 0xe8 0xfe and the 102 undefined opcodes
  (inferred names STOP, JUMP, JUMPI, PC, MSIZE, JUMPDEST, DUPN, SWAPN, EXCHANGE, INVALID and the shared
  undefined-opcode body), 11 bodies.  JUMP and JUMPI pop first and then check the destination (saturated to
  2^64 - 1 when a high limb is set) against the code object's jump-destination bitmap (+0x18 bytes, +0x28 bit
  length, LSB first), set the instruction pointer to code base + destination or return 0x2a.  PC pushes
  ip - base - 1, MSIZE pushes memory length - context offset (both panic on an impossible underflow).  DUPN / SWAPN /
  EXCHANGE are gated on the spec byte +0x1a9 >= 0xe, read one immediate byte at the instruction pointer, reject it
  with 0x37 by a SIGNED byte compare and decode it into stack depths; DUPN reports a short stack as 0x2d, SWAPN /
  EXCHANGE as 0x2c.

Both families share the interpreter layout (stack base +0x28, length +0x30, cursor +0x118, spec byte +0x1a9), which
the tool checks once.  It reads every relocation, FDE extent and code byte from the ELF file and evaluates the real
machine code with a small concrete x86-64 evaluator (no external programs, the binary is never executed; the panic
.got target is a boundary).  Every case is compared with the pure-Python reconstruction of its family; negative
controls show that wrong reconstructions, corrupted code bytes and out-of-range inputs are detected.
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
    while code[p] in (0x66, 0x2e, 0xf3, 0xf2, 0x64):  # operand size, segments, rep/repne
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
                0x39, 0x3b, 0x63, 0x84, 0x85, 0x89, 0x8b, 0x8d, 0xd1, 0xff, 0x0fb6, 0x0f10, 0x0f11, 0x0f28, 0x0f29,
                0x0f1f, 0x0f6f, 0x0f7f, 0x0f74, 0x0fdb, 0x0fd7, 0x28, 0xd3, 0x0fb7, 0x0fbc, 0x0fef,
                0x0f6e, 0x0f7e, 0x30, 0x32, 0x0f60, 0x0f76, 0x0faf, 0x0f6c, 0x0ffb, 0x0fa5, 0x0fad, 0x0fa3, 0x0fbd, 0x0feb, 0x0f50, 0x0f54, 0x0f56) or 0x0f40 <= op <= 0x0f4f or 0x0f90 <= op <= 0x0f9f:
        p = modrm(p)
    elif op in (0x0f70, 0x0fc6, 0x0fa4, 0x0fac, 0x0fba):
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
    elif op in (0x04, 0x0c, 0x1c, 0x3c, 0x24):
        form["imm"] = code[p]
        p += 1
    elif op == 0xc6:
        p = modrm(p)
        form["imm"] = code[p]
        p += 1
    elif op == 0xf6:
        p = modrm(p)
        if form["reg"] & 7 in (0, 1):
            form["imm"] = code[p]
            p += 1
        elif form["reg"] & 7 not in (2, 3):
            fail(f"unsupported f6 form at {va:#x}")
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
        elif op == 0x90 or op == 0x0f1f:
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
            kind = f["reg"] & 7
            a = self.get(f["rm"], 8, f, va)
            if kind in (0, 1):
                self.flags_logic(a & f["imm"], 8)
            elif kind == 2:
                self.put(f["rm"], 8, ~a, f, va)
            else:  # neg r/m8
                res = self.flags_sub(0, a, 8)
                self.cf = a != 0
                self.put(f["rm"], 8, res, f, va)
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
            elif kind == 6:  # div: rdx:rax / r/m (quotient overflow and zero raise #DE)
                mask = (1 << size) - 1
                num = (self.regs[2] & mask) << size | (self.regs[0] & mask)
                if a == 0 or num // a > mask:
                    fail(f"divide error at {va:#x}")
                self.set_reg(0, size, num // a, f)
                self.set_reg(2, size, num % a, f)
                self.zf = self.sf = self.cf = self.of = None
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
        elif op == 0x04:
            self.set_reg(0, 8, self.flags_add(self.regs[0] & 0xff, f["imm"], 8), f)
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
            if rm[0] == "r":
                self.xmm[f["reg"]] ^= self.xmm[rm[1]]
            else:
                at = self.ea(rm, f, va)
                if at % 16:
                    fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
                self.xmm[f["reg"]] ^= self.load(at, 16)
        elif op in (0x30, 0x32):  # xor r/m8, r8 / xor r8, r/m8
            a, b = self.get(f["rm"], 8, f, va), self.reg(f["reg"], 8, f)
            res = self.flags_logic(a ^ b, 8)
            if op == 0x30:
                self.put(f["rm"], 8, res, f, va)
            else:
                self.set_reg(f["reg"], 8, res, f)
        elif op == 0x0fa3:  # bt r, r (register bit base only)
            if f["rm"][0] != "r":
                fail(f"unsupported 0fa3 memory form at {va:#x}")
            bit = self.reg(f["reg"], size, f) & (size - 1)
            self.cf = bool((self.get(f["rm"], size, f, va) >> bit) & 1)
        elif op == 0x0fba:  # bt r/m, imm8
            if f["reg"] & 7 != 4:
                fail(f"unsupported 0fba form at {va:#x}")
            self.cf = bool((self.get(f["rm"], size, f, va) >> (f["imm"] & (size - 1))) & 1)
        elif op == 0x0f7e:  # movq/movd r/m, xmm
            if not f["p66"]:
                fail(f"unsupported 0f7e form at {va:#x}")
            bits = 64 if f["rex"] & 8 else 32
            self.put(f["rm"], bits, self.xmm[f["reg"]] & ((1 << bits) - 1), f, va)
        elif op == 0x0f6e:  # movd / movq xmm, r/m (upper lanes cleared)
            if not f["p66"]:
                fail(f"unsupported 0f6e form at {va:#x}")
            self.xmm[f["reg"]] = self.get(f["rm"], 64 if f["rex"] & 8 else 32, f, va)
        elif op == 0x0faf:  # imul r, r/m: low half only; its flags are not modelled
            if f["p66"] or f["rep"]:
                fail(f"unsupported 0faf form at {va:#x}")
            self.set_reg(f["reg"], size, self.reg(f["reg"], size, f) * self.get(f["rm"], size, f, va), f)
            self.of = self.cf = None
        elif op == 0x0f6c:  # punpcklqdq
            if not f["p66"] or f["rm"][0] != "r":
                fail(f"unsupported 0f6c form at {va:#x}")
            self.xmm[f["reg"]] = (self.xmm[f["reg"]] & M64) | (self.xmm[f["rm"][1]] & M64) << 64
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
OP_TABLES = (0x6441210, 0x6441f00)  # RELATIVE opcode tables (index = opcode); both name the same bodies
SLOAD_OP, SLOAD_BODIES = 0x54, (0x2993ff0, 0x2993bd0)  # anchor: slot 0x54 holds an SLOAD handler copy


def sweep_padded(image, lo, hi):
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


# ================================================================ family 1: PUSH0..32 / DUP1..16 / SWAP1..16
PS_BODIES = {  # opcode -> body named by both tables
    0x5f: 0x2997060, 0x60: 0x29967e0, 0x61: 0x2996220, 0x62: 0x2996090, 0x63: 0x29968a0, 0x64: 0x2996560,
    0x65: 0x2996a40, 0x66: 0x2996970, 0x67: 0x29962e0, 0x68: 0x2996790, 0x69: 0x2995ef0, 0x6a: 0x2996720,
    0x6b: 0x2995f50, 0x6c: 0x2996020, 0x6d: 0x29963b0, 0x6e: 0x2996b20, 0x6f: 0x2996490, 0x70: 0x29969e0,
    0x71: 0x2996830, 0x72: 0x29961b0, 0x73: 0x2996150, 0x74: 0x2996630, 0x75: 0x29964f0, 0x76: 0x2995fa0,
    0x77: 0x29960f0, 0x78: 0x2996280, 0x79: 0x2996420, 0x7a: 0x2996aa0, 0x7b: 0x2995e90, 0x7c: 0x29966a0,
    0x7d: 0x29968f0, 0x7e: 0x2996330, 0x7f: 0x29965c0,
    0x80: 0x2995bf0, 0x82: 0x2995cb0, 0x83: 0x2995af0, 0x84: 0x2995db0, 0x85: 0x2995c70,
    0x86: 0x2995a30, 0x87: 0x2995d30, 0x88: 0x2995c30, 0x89: 0x2995b30, 0x8a: 0x29959f0, 0x8b: 0x2995cf0,
    0x8c: 0x2995a70, 0x8d: 0x2995b70, 0x8e: 0x2995bb0, 0x8f: 0x2995d70,
    0x90: 0x2996e10, 0x91: 0x2997020, 0x92: 0x2996f40, 0x93: 0x2996c30, 0x94: 0x2996d70, 0x95: 0x2996cd0,
    0x96: 0x2996e50, 0x97: 0x2996fd0, 0x98: 0x2996c80, 0x99: 0x2996d20, 0x9a: 0x2996be0, 0x9b: 0x2996f80,
    0x9c: 0x2996b90, 0x9d: 0x2996ef0, 0x9e: 0x2996ea0, 0x9f: 0x2996dc0,
}
# DUP2 (opcode 0x81) is excluded: its body is the subject of the merged packet RE-001-node115-stack-copy.
PS_EXCLUDED = {0x81: (0x2995ab0, "RE-001-node115-stack-copy")}
PS_OPS = tuple(sorted(PS_BODIES))
PS_I_STACK_PTR, PS_I_STACK_LEN, PS_I_CODE_PTR, PS_I_SPEC = 0x28, 0x30, 0x118, 0x1a9
PS_R_OK, PS_R_NOT_ACTIVATED, PS_R_UNDERFLOW, PS_R_OVERFLOW = 0x00, 0x2b, 0x2c, 0x2d
PS_LIMIT = 1024
PS_PUSH0_SPEC = 0xa
PS_SAVED_REGS = (3, 5, 12, 13, 14, 15)

PS_INTERP_AT = 0x7d00_0000_0000
PS_INTERP_SIZE = 0x200
PS_STK_AT = 0x7d00_0300_0000
PS_CODE_AT = 0x7d00_0600_0000
PS_WINDOW = 20
PS_TRAIL = 40
PS_STACK_FILL, PS_INTERP_FILL, PS_SLACK_FILL = 0x5a, 0x6b, 0x7c
PS_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]


def ps_kind(op):
    if 0x5f <= op <= 0x7f:
        return "PUSH", op - 0x5f
    if 0x80 <= op <= 0x8f:
        return "DUP", op - 0x7f
    if 0x90 <= op <= 0x9f:
        return "SWAP", op - 0x8f
    fail(f"opcode {op:#x} is not a PUSH/DUP/SWAP opcode")


def ps_name(op):
    fam, n = ps_kind(op)
    return f"{fam}{n}"


# ---------------------------------------------------------------- reconstruction
def ps_model(c, mut=frozenset()):
    """Result code, stack length, code pointer offset and the visible stack words after the handler.

    c["len"] is the stack length, c["words"] maps stack index -> 256-bit word for the top window,
    c["code"] holds the bytecode bytes around the code pointer, which starts at c["ptr"].
    """
    op, spec, n_len, ptr = c["op"], c["spec"], c["len"], c["ptr"]
    words = dict(c["words"])
    fam, n = ps_kind(op)
    same = {"ret": None, "len": n_len, "ptr": ptr, "words": words, "reads": []}
    if fam == "PUSH":
        if n == 0:
            gate = PS_PUSH0_SPEC + 1 if "push0_gate_b" in mut else PS_PUSH0_SPEC
            if spec < gate and "push0_no_gate" not in mut:
                return dict(same, ret=PS_R_NOT_ACTIVATED)
            full = n_len >= PS_LIMIT if "push0_bound_ge" in mut else n_len == PS_LIMIT
            if full:
                return dict(same, ret=PS_R_OVERFLOW)
            value = 0
        else:
            bound = PS_LIMIT if "push_bound_1024" in mut else PS_LIMIT - 1
            if n_len > bound:
                return dict(same, ret=PS_R_OVERFLOW)
            imm = c["code"][ptr:ptr + n]
            order = "little" if "push_little_endian" in mut and n > 1 else "big"
            value = int.from_bytes(imm, order)
            if "push_drop_last_byte" in mut and n == 32:
                value &= ~0xff
            ptr += 0 if "push_no_advance" in mut and n == 7 else n
        words[n_len] = value
        reads = list(range(n + 1 if "push_reads_padded_qword" in mut and n == 5 else n))
        return {"ret": PS_R_OK, "len": n_len + 1, "ptr": ptr, "words": words, "reads": reads}
    if fam == "DUP":
        if not n <= n_len <= PS_LIMIT - 1 or ("dup_upper_1022" in mut and n_len == PS_LIMIT - 1):
            under = n_len < n and "dup_underflow_2c" in mut
            return dict(same, ret=PS_R_UNDERFLOW if under else PS_R_OVERFLOW)
        src = n_len - n - (1 if "dup_off_by_one" in mut and n == 9 else 0)
        words[n_len] = ps_pick(words, src)
        return {"ret": PS_R_OK, "len": n_len + 1, "ptr": ptr, "words": words, "reads": []}
    need = n + 1 + (1 if "swap_need_n2" in mut and n == 5 else 0)
    if n_len < need or ("swap_upper_bound" in mut and n_len > PS_LIMIT):
        return dict(same, ret=PS_R_UNDERFLOW)
    a, b = n_len - 1, n_len - 1 - n
    if "swap_off_by_one" in mut and n == 12:
        b -= 1
    words[a], words[b] = ps_pick(words, b), ps_pick(words, a)
    return {"ret": PS_R_OK, "len": n_len, "ptr": ptr, "words": words, "reads": []}


def ps_pick(words, i):
    if i not in words:
        fail(f"reconstruction reads stack index {i} outside the window")
    return words[i]


def ps_window(c):
    lo = max(0, c["len"] - PS_WINDOW)
    return lo, c["len"] + 2


def ps_stack_image(words, lo, hi):
    return b"".join(words[i].to_bytes(32, "little") if i in words else bytes([PS_SLACK_FILL]) * 32
                    for i in range(lo, hi))


# ---------------------------------------------------------------- harness
class ps_CodeMachine(TraceMachine):
    """TraceMachine that also records which bytecode bytes (relative to the code pointer) are read."""

    def reset(self):
        super().reset()
        self.code_reads, self.code_ptr = set(), 0

    def load(self, at, size):
        at &= M64
        if PS_CODE_AT <= at < PS_CODE_AT + 0x1000:
            self.code_reads.update(range(at - PS_CODE_AT - self.code_ptr, at - PS_CODE_AT - self.code_ptr + size))
        return super().load(at, size)


def ps_run_case(m, c):
    m.reset()
    m.regions[0][2][:] = bytes([PS_STACK_FILL]) * len(m.regions[0][2])
    it = m.add_region(PS_INTERP_AT, PS_INTERP_SIZE, bytes([PS_INTERP_FILL]) * PS_INTERP_SIZE)
    put(it, PS_I_STACK_PTR, 8, PS_STK_AT)
    put(it, PS_I_STACK_LEN, 8, c["len"])
    put(it, PS_I_CODE_PTR, 8, PS_CODE_AT + c["ptr"])
    put(it, PS_I_SPEC, 1, c["spec"])
    lo, hi = ps_window(c)
    stk = m.add_region(PS_STK_AT + 32 * lo, 32 * (hi - lo), ps_stack_image(c["words"], lo, hi))
    m.add_region(PS_CODE_AT, len(c["code"]), c["code"])
    m.code_ptr = c["ptr"]
    before = bytes(it)
    for k, v in zip(PS_SAVED_REGS, PS_SAVED):
        m.regs[k] = v
    m.regs[7] = PS_INTERP_AT
    m.run(PS_BODIES[c["op"]], limit=2000)
    rest = bytearray(it)
    for off in (PS_I_STACK_LEN, PS_I_CODE_PTR):
        rest[off:off + 8] = before[off:off + 8]
    return {"ret": m.regs[0] & 0xff, "len": u(it, PS_I_STACK_LEN, 8), "ptr": u(it, PS_I_CODE_PTR, 8) - PS_CODE_AT,
            "stack_raw": bytes(stk),
            "regs_ok": [m.regs[k] for k in PS_SAVED_REGS] == PS_SAVED and m.regs[4] == STACK_TOP - 0x100,
            "interp_ok": bytes(rest) == before, "code_reads": sorted(m.code_reads), "code_writes": [w for w in m.writes if PS_CODE_AT <= w[0] < PS_CODE_AT + 0x1000]}


def ps_compare(c, want, got):
    lo, hi = ps_window(c)
    return (want["ret"] == got["ret"] and want["len"] == got["len"] and (want["ptr"] & M64) == (got["ptr"] & M64)
            and got["regs_ok"] and got["interp_ok"] and not got["code_writes"] and got["code_reads"] == want["reads"]
            and got["stack_raw"] == ps_stack_image(want["words"], lo, hi))


# ---------------------------------------------------------------- cases
PS_PER_OP = 100
PS_EDGE = (0, 1, 2, 0xff, 0x100, M64, 1 << 64, M128, 1 << 128, 1 << 255, M256, M256 - 1)
PS_SPECS = tuple(range(0x16)) + (0x7f, 0xff)
PS_MODES = ("ok", "ok", "deep", "ok", "edge-low", "ok", "edge-high", "ok", "full", "spec", "beyond", "ok")


def ps_rand_word(s):
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def ps_stack_len(s, op, mode):
    fam, n = ps_kind(op)
    need = 0 if fam == "PUSH" else n if fam == "DUP" else n + 1
    if mode == "ok":
        return need + s.below(30) if s.below(2) else need + s.below(PS_LIMIT - 1 - need)
    if mode == "deep":
        return s.pick((PS_LIMIT - 2, PS_LIMIT - 1, 512, 777))
    if mode == "edge-low":
        return max(0, need + s.pick((-2, -1, -1, 0, 0, 1)))
    if mode == "edge-high":
        return s.pick((PS_LIMIT - 2, PS_LIMIT - 1, PS_LIMIT - 1, PS_LIMIT))
    if mode == "full":
        return PS_LIMIT
    if mode == "beyond":  # breaks the 1024-word stack invariant: shows the exact shape of each length check
        return s.pick((PS_LIMIT + 1, PS_LIMIT + 2, 1500, 4000))
    return s.below(40)


def ps_imm_bytes(s, n):
    k = s.below(5)
    if k == 0:
        return bytes(n)
    if k == 1:
        return b"\xff" * n
    if k == 2:
        return bytes([0]) * min(n, 1 + s.below(3)) + s.take(n)[min(n, 1 + s.below(3)):] if n else b""
    return s.take(n)


def ps_make_case(s, op, k):
    fam, n = ps_kind(op)
    mode = PS_MODES[k % len(PS_MODES)]
    spec = s.pick(PS_SPECS)
    if op == 0x5f and (mode == "spec" or s.below(3) == 0):
        spec = s.pick((0, PS_PUSH0_SPEC - 1, PS_PUSH0_SPEC, PS_PUSH0_SPEC + 1, 0x14, 0xff))
    n_len = ps_stack_len(s, op, mode)
    lo = max(0, n_len - PS_WINDOW)
    words = {}
    for i in range(lo, n_len):
        words[i] = ps_rand_word(s) if s.below(3) else s.pick(PS_EDGE)
    off = s.below(16)
    imm = ps_imm_bytes(s, n) if fam == "PUSH" else b""
    code = s.take(off) + imm + s.take(PS_TRAIL)
    return {"op": op, "spec": spec, "mode": mode, "len": n_len, "words": words, "ptr": off, "code": code}


def ps_all_cases():
    s = Stream("re11-push-dup-swap-115")
    return [ps_make_case(s, op, k) for op in PS_OPS for k in range(PS_PER_OP)]


# ---------------------------------------------------------------- static evidence
PS_CHECKED = (
    (0x2997060, "80 bf a9 01 00 00 0a", "PUSH0: spec byte at interpreter +0x1a9 must be >= 0xa"),
    (0x299706d, "48 3d 00 04 00 00", "PUSH0: length compared with 0x400 for EQUALITY (je), not >="),
    (0x2997080, "0f 57 c0", "PUSH0: xorps zero word, two 16-byte stores"),
    (0x2997096, "b0 2b", "PUSH0: result 0x2b (not activated)"),
    (0x29967e4, "48 3d ff 03 00 00", "PUSH1: length compared with 0x3ff (ja -> 0x2d)"),
    (0x29967ec, "48 8b 8f 18 01 00 00", "PUSH1: code pointer at interpreter +0x118"),
    (0x2996803, "0f b6 11", "PUSH1: one immediate byte, zero-extended"),
    (0x299681b, "48 ff c1", "PUSH1: code pointer advanced by 1"),
    (0x29965e7, "48 0f ca", "PUSH32: bswap of the last immediate qword -> limb 0"),
    (0x2996611, "48 83 c1 20", "PUSH32: code pointer advanced by 0x20"),
    (0x2995bf4, "48 8d 48 ff", "DUP1: rcx = length - 1"),
    (0x2995bf8, "48 81 f9 fe 03 00 00", "DUP1: one unsigned range check 1 <= length <= 1023"),
    (0x2995c27, "b0 2d", "DUP1: both failure sides return 0x2d"),
    (0x2995d74, "48 8d 48 f0", "DUP16: rcx = length - 16"),
    (0x2995d78, "48 81 f9 ef 03 00 00", "DUP16: 16 <= length <= 1023"),
    (0x2996e14, "48 83 f8 02", "SWAP1: length compared with 2 (jb -> 0x2c)"),
    (0x2996e4d, "b0 2c", "SWAP1: result 0x2c (underflow)"),
    (0x2996dc4, "48 83 f8 11", "SWAP16: length compared with 0x11"),
)


def ps_opcode_slots(image):
    rows = {}
    for table in OP_TABLES:
        if image.relative.get(table + 8 * SLOAD_OP) not in SLOAD_BODIES:
            fail(f"opcode table {table:#x} is not anchored by the SLOAD slot")
        for op in list(PS_OPS) + list(PS_EXCLUDED):
            got = image.relative.get(table + 8 * op)
            want = PS_BODIES[op] if op in PS_BODIES else PS_EXCLUDED[op][0]
            if got != want:
                fail(f"opcode table {table:#x} slot {op:#x} is {got}")
            rows[f"{table:#x}+{8 * op:#x}"] = {"opcode": f"{op:#x}", "target": f"{got:#x}",
                                               "excluded": op in PS_EXCLUDED}
    return rows


def ps_mem_disp(fm):
    rm = fm.get("rm")
    return rm[4] if rm and rm[0] == "m" else None


def ps_derive(op, insns):
    """Constants of one body read from its decoded forms (not from the reconstruction)."""
    fam, n = ps_kind(op)
    forms = [fm for _, fm in insns if fm is not None]
    d = {"spec_gate": None, "length_compare": None, "dup_bias": None, "code_advance": None,
         "stack_offsets": sorted({ps_mem_disp(fm) for fm in forms
                                  if fm["op"] in (0x0f10, 0x0f11, 0x89, 0x8b, 0xc7) and ps_mem_disp(fm) is not None
                                  and fm["rm"][2] is not None})}
    for fm in forms:
        if fm["op"] == 0x80 and fm["reg"] & 7 == 7 and ps_mem_disp(fm) == PS_I_SPEC:
            d["spec_gate"] = fm["imm"]
        if fm["op"] == 0x3d or fm["op"] in (0x81, 0x83) and fm["reg"] & 7 == 7 and fm["rm"][0] == "r":
            d["length_compare"] = fm["imm"]
        if fm["op"] == 0x8d and fm["rm"][0] == "m" and fm["rm"][4] < 0:
            d["dup_bias"] = -fm["rm"][4]
        if fm["op"] == 0x83 and fm["reg"] & 7 == 0 and fm["rm"] == ("r", 1):
            d["code_advance"] = fm["imm"]
        if fm["op"] == 0xff and fm["reg"] & 7 == 0 and fm["rm"] == ("r", 1):
            d["code_advance"] = 1
    rets = [fm["imm"] for fm in forms if fm["op"] == 0xb0]
    d["failure_results"] = sorted(set(rets))
    reads_code = any(fm["op"] == 0x8b and ps_mem_disp(fm) == PS_I_CODE_PTR for fm in forms)
    d["reads_code_pointer"] = reads_code
    return d


def ps_check_derived(op, d):
    """The byte-derived constants must agree with the family rules used by model()."""
    fam, n = ps_kind(op)
    if fam == "PUSH":
        want_cmp = PS_LIMIT if n == 0 else PS_LIMIT - 1
        ok = (d["length_compare"] == want_cmp and d["spec_gate"] == (PS_PUSH0_SPEC if n == 0 else None)
              and d["code_advance"] == (n if n else None) and d["reads_code_pointer"] == (n > 0)
              and d["failure_results"] == ([PS_R_NOT_ACTIVATED, PS_R_OVERFLOW] if n == 0 else [PS_R_OVERFLOW]))
    elif fam == "DUP":
        ok = (d["dup_bias"] == n and d["length_compare"] == PS_LIMIT - 1 - n and d["spec_gate"] is None
              and d["failure_results"] == [PS_R_OVERFLOW] and not d["reads_code_pointer"])
    else:
        ok = (d["length_compare"] == n + 1 and d["spec_gate"] is None and d["failure_results"] == [PS_R_UNDERFLOW]
              and not d["reads_code_pointer"] and min(d["stack_offsets"]) == -32 * (n + 1))
    if not ok:
        fail(f"byte-derived constants of {ps_name(op)} disagree with the family rule: {d}")


def ps_static_evidence(image):
    bodies = [PS_BODIES[op] for op in PS_OPS]
    rows = fde_rows(image, bodies)
    decoded, funcs = {}, {}
    for op in PS_OPS:
        f = PS_BODIES[op]
        lo, hi = rows[f]
        decoded[f] = sweep_padded(image, lo, hi)
        calls = [f"{va:#x}" for va, fm in decoded[f] if fm is not None and
                 (fm["op"] in (0xe8, 0xe9) or fm["op"] == 0xff and fm["reg"] & 7 in (2, 3, 4, 5))]
        if calls:
            fail(f"handler {f:#x} has calls or jumps out at {calls}")
        d = ps_derive(op, decoded[f])
        ps_check_derived(op, d)
        funcs[f"{f:#x}"] = {"opcode": f"{op:#x}", "name_inferred": ps_name(op), "fde_end": f"{hi:#x}",
                            "fde_bytes": hi - lo,
                            "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None),
                            "returns": sum(1 for _, fm in decoded[f] if fm is not None and fm["op"] == 0xc3),
                            "derived": d}
    checks = {}
    for va, hx, what in PS_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "opcode_table_slots": ps_opcode_slots(image),
           "excluded": {f"{op:#x}": {"body": f"{b:#x}", "owner": w} for op, (b, w) in PS_EXCLUDED.items()},
           "checked_bytes": checks,
           "interpreter_offsets": {"stack_ptr": f"{PS_I_STACK_PTR:#x}", "stack_len": f"{PS_I_STACK_LEN:#x}",
                                   "code_ptr": f"{PS_I_CODE_PTR:#x}", "spec_byte": f"{PS_I_SPEC:#x}"},
           "results": {"ok": PS_R_OK, "not_activated": PS_R_NOT_ACTIVATED, "underflow": PS_R_UNDERFLOW,
                       "overflow": PS_R_OVERFLOW}}
    return out, decoded


# ---------------------------------------------------------------- evaluation
PS_MODEL_MUTANTS = ["push0_no_gate", "push0_gate_b", "push0_bound_ge", "push_bound_1024", "push_little_endian",
                 "push_drop_last_byte", "push_no_advance", "push_reads_padded_qword", "dup_underflow_2c", "dup_upper_1022",
                 "dup_off_by_one", "swap_need_n2", "swap_upper_bound", "swap_off_by_one"]
PS_BYTE_MUTANTS = [
    (0x2997066, 0x0b, "PUSH0: spec gate 0xa -> 0xb"),
    (0x2997073, 0x73, "PUSH0: je (length == 0x400) -> jae"),
    (0x2997097, 0x2c, "PUSH0: not-activated result 0x2b -> 0x2c"),
    (0x29967e6, 0xfe, "PUSH1: length bound 0x3ff -> 0x3fe"),
    (0x2996829, 0x2c, "PUSH1: overflow result 0x2d -> 0x2c"),
    (0x29960c8, 0x20, "PUSH3: shr 0x28 -> 0x20 after bswap"),
    (0x29960e1, 0x02, "PUSH3: code pointer advance 3 -> 2"),
    (0x29965e9, 0xc8, "PUSH32: bswap rdx -> bswap rax (limb 0 left in memory order)"),
    (0x2996614, 0x1f, "PUSH32: code pointer advance 0x20 -> 0x1f"),
    (0x2995bfb, 0xff, "DUP1: range bound 0x3fe -> 0x3ff (accepts length 1024)"),
    (0x2995bf7, 0xfe, "DUP1: range bias -1 -> -2 (length 1 rejected, length 1024 accepted)"),
    (0x2995d7b, 0xf0, "DUP16: range bound 0x3ef -> 0x3f0"),
    (0x2995d91, 0x40, "DUP16: source offset -0x200 -> -0x1c0"),
    (0x2996e17, 0x03, "SWAP1: minimum length 2 -> 3"),
    (0x2996e4e, 0x2d, "SWAP1: underflow result 0x2c -> 0x2d"),
    (0x2996dc7, 0x10, "SWAP16: minimum length 0x11 -> 0x10"),
    (0x2996dd6, 0x00, "SWAP16: deep offset -0x220 -> -0x300"),
]


def ps_outcome(c, got):
    if "error" in got:
        return "error"
    fam, n = ps_kind(c["op"])
    nm = ps_name(c["op"])
    r = got["ret"]
    if r == PS_R_NOT_ACTIVATED:
        return nm + "/not-activated"
    if r == PS_R_OVERFLOW:
        return nm + ("/underflow-reported-as-overflow" if fam == "DUP" and c["len"] < n else "/overflow")
    if r == PS_R_UNDERFLOW:
        return nm + "/underflow"
    if r != PS_R_OK:
        return nm + f"/r{r:#x}"
    return nm + ("/ok-beyond-1024" if c["len"] >= PS_LIMIT else "/ok")


# ================================================================ family 2: control flow and EIP-8024 immediates
CF_BODIES = {  # opcode -> body named by both tables; EVM names are inferred from the opcode number and the code
    0x00: (0x2999600, "STOP"), 0x56: (0x2999580, "JUMP"), 0x57: (0x2999610, "JUMPI"), 0x58: (0x29994f0, "PC"),
    0x59: (0x2997550, "MSIZE"), 0x5b: (0x2999710, "JUMPDEST"), 0xe6: (0x2995e10, "DUPN"),
    0xe7: (0x29970a0, "SWAPN"), 0xe8: (0x2997120, "EXCHANGE"), 0xfe: (0x29996f0, "INVALID"),
    0x0c: (0x2999700, "UNDEFINED"),
}
CF_UNDEFINED_BODY = 0x2999700  # one body shared by every unassigned opcode; 0x0c is the representative case opcode
CF_CLAIMED = tuple(sorted(v[0] for v in CF_BODIES.values()))
CF_PANIC_SLOT = 0x64df848  # RELATIVE .got slot called by the impossible-underflow arms of PC, MSIZE and EXCHANGE
CF_PANIC_ARMS = {0x29994f0: 0x2999546, 0x2997550: 0x2997598, 0x2997120: 0x29971d0}
CF_SPEC_GATE = 0x0e  # interpreter +0x1a9 minimum of DUPN / SWAPN / EXCHANGE
CF_IMMEDIATE_OPS = (0xe6, 0xe7, 0xe8)
CF_I_MEM, CF_I_MEM_OFF, CF_I_STACK_PTR, CF_I_STACK_LEN, CF_I_IP, CF_I_CODE, CF_I_SPEC = 0x10, 0x18, 0x28, 0x30, 0x118, 0x120, 0x1a9
CF_C_BITMAP, CF_C_BITLEN, CF_C_BASE = 0x18, 0x28, 0x38
CF_M_LEN = 0x28
CF_STACK_LIMIT = 0x400
CF_R_OK, CF_R_STOP, CF_R_UNDEFINED, CF_R_INVALID, CF_R_BAD_JUMP = 0x00, 0x01, 0x26, 0x29, 0x2a
CF_R_NOT_ACTIVATED, CF_R_UNDERFLOW, CF_R_OVERFLOW, CF_R_BAD_IMMEDIATE = 0x2b, 0x2c, 0x2d, 0x37
CF_SAVED_REGS = (3, 5, 12, 13, 14, 15)

CF_INTERP_AT, CF_INTERP_SIZE = 0x7d00_0000_0000, 0x1b0
CF_CTX_AT, CF_CTX_SIZE = 0x7d00_0100_0000, 0x260
CF_STK_AT = 0x7d00_0300_0000
CF_CODE_AT, CF_CODE_SIZE = 0x7d00_0400_0000, 0x60
CF_MEM_AT, CF_MEM_SIZE = 0x7d00_0500_0000, 0x40
CF_MAP_AT, CF_MAP_SIZE = 0x7d00_0600_0000, 0x90
CF_BYTES_AT, CF_BYTES_SIZE = 0x7d00_0700_0000, 0x240
CF_STACK_FILL, CF_SLACK_FILL = 0x5a, 0x7c
CF_SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]


# ---------------------------------------------------------------- reconstruction
def cf_le(b, off, n):
    return int.from_bytes(b[off:off + n], "little")


def cf_sat64(w, mut=frozenset()):
    """A 256-bit word as a u64 destination: values with any high limb set become 2^64 - 1."""
    if "dest_truncates" in mut:
        return w & M64
    return w if w <= M64 else M64


def cf_is_jumpdest(c, dest, mut=frozenset()):
    """Bitmap test of the code object: dest < bit length and bit (dest & 7) of byte dest >> 3 is set."""
    if dest >= cf_le(c["code"], CF_C_BITLEN, 8) - (1 if "bound_inclusive" in mut else 0):
        return False
    bit = 7 - (dest & 7) if "bitmap_msb_first" in mut else dest & 7
    return bool(c["bitmap"][dest >> 3] >> bit & 1)


def cf_decode_single(x, mut=frozenset()):
    """DUPN / SWAPN immediate: None when rejected (signed byte >= 0x5b), else the depth (x + 0x91) mod 256."""
    signed = x - 256 if x >= 0x80 and "imm_unsigned" not in mut else x
    if signed >= 0x5b:
        return None
    return (x + (0x90 if "imm_bias_0x90" in mut else 0x91)) & 0xff


def cf_decode_pair(x, mut=frozenset()):
    """EXCHANGE immediate: None when rejected (signed byte >= 0x52), else depths (a + 1, b) below the top."""
    signed = x - 256 if x >= 0x80 else x
    if signed >= 0x52:
        return None
    t = x ^ 0x8f
    q, r = t >> 4, t & 0xf
    if "pair_swapped" in mut:
        q, r = r, q
    if q < r:
        a, b = q, r + 1
    else:
        a, b = r, (0x1c if "pair_bound_28" in mut else 0x1d) - q
    return a, b


def cf_model(c, mut=frozenset()):
    """Result code, new stack length, written stack slots, new instruction pointer, or a panic."""
    op, n, it, w = c["op"], c["n"], c["interp"], c["words"]
    ip = cf_le(it, CF_I_IP, 8)
    out = {"ret": CF_R_OK, "n": n, "writes": {}, "ip": ip, "panic": False}
    if op == 0x00:
        out["ret"] = 0 if "stop_zero" in mut else CF_R_STOP
    elif op == 0x5b:
        pass
    elif op == 0xfe:
        out["ret"] = CF_R_INVALID
    elif op == 0x0c:
        out["ret"] = CF_R_UNDEFINED
    elif op in (0x56, 0x57):
        need = 1 if op == 0x56 else 2
        if n < need:
            out["ret"] = CF_R_UNDERFLOW
            return out
        if "jump_pops_late" not in mut:
            out["n"] = n - need
        dest = w[n - 1]
        if op == 0x57:
            cond = w[n - 2] & M64 if "cond_low_limb" in mut else w[n - 2]
            if cond == 0:
                out["n"] = n - need
                return out
        d = cf_sat64(dest, mut)
        if not cf_is_jumpdest(c, d, mut):
            out["ret"] = CF_R_BAD_JUMP
            return out
        out["n"] = n - need
        out["ip"] = (cf_le(c["code"], CF_C_BASE, 8) + d) & M64
    elif op in (0x58, 0x59):
        if op == 0x58:
            base = cf_le(c["code"], CF_C_BASE, 8)
            if ip == base:
                out["panic"] = True
                return out
            v = (ip - base - (0 if "pc_no_minus1" in mut else 1)) & M64
        else:
            ln, off = cf_le(c["mem"], CF_M_LEN, 8), cf_le(it, CF_I_MEM_OFF, 8)
            if "msize_no_offset" in mut:
                off = 0
            if ln < off:
                out["panic"] = True
                return out
            v = ln - off
        if n >= CF_STACK_LIMIT:
            out["ret"] = CF_R_OVERFLOW
            return out
        out["n"], out["writes"] = n + 1, {n: v}
    else:
        if it[CF_I_SPEC] < CF_SPEC_GATE:
            out["ret"] = CF_R_NOT_ACTIVATED
            return out
        x = c["imm"]
        if op in (0xe6, 0xe7):
            k = cf_decode_single(x, mut)
            if k is None:
                out["ret"] = CF_R_BAD_IMMEDIATE
                return out
            if op == 0xe6:
                if n < k or n > CF_STACK_LIMIT - 1:
                    out["ret"] = CF_R_UNDERFLOW if "dupn_underflow_2c" in mut and n < k else CF_R_OVERFLOW
                    return out
                out["n"], out["writes"] = n + 1, {n: w[n - k]}
            else:
                if n <= k - (1 if "swapn_off_by_one" in mut else 0):
                    out["ret"] = CF_R_UNDERFLOW
                    return out
                i, j = n - 1, n - 1 - k
                out["writes"] = {i: w[j], j: w[i]}
        else:
            pair = cf_decode_pair(x, mut)
            if pair is None:
                out["ret"] = CF_R_BAD_IMMEDIATE
                return out
            a, b = pair
            if b <= a:
                out["panic"] = True
                return out
            if b >= n:
                out["ret"] = CF_R_UNDERFLOW
                return out
            i, j = n - 2 - a, n - 1 - b
            out["writes"] = {i: w[j], j: w[i]}
        out["ip"] = ip + 1
    return out


# ---------------------------------------------------------------- harness
def cf_regs_ok(m):
    return [m.regs[k] for k in CF_SAVED_REGS] == CF_SAVED and m.regs[4] == STACK_TOP - 0x100


def cf_depth(op):
    return 0xf0 if op in CF_IMMEDIATE_OPS else 2


def cf_window(c):
    """Mapped stack slots: every slot an opcode can reach below the top and two free slots above it."""
    lo = max(c["n"] - cf_depth(c["op"]), 0)
    return lo, c["n"] + 2 - lo


def cf_stack_image(c):
    lo, slots = cf_window(c)
    raw = bytearray([CF_SLACK_FILL]) * (32 * slots)
    for i, w in c["words"].items():
        raw[32 * (i - lo):32 * (i - lo) + 32] = w.to_bytes(32, "little")
    return bytes(raw)


def cf_run_case(m, c):
    m.reset()
    m.stubs[m.image.relative[CF_PANIC_SLOT]] = "panic"
    m.regions[0][2][:] = bytes([CF_STACK_FILL]) * len(m.regions[0][2])
    it = m.add_region(CF_INTERP_AT, CF_INTERP_SIZE, c["interp"])
    x = m.add_region(CF_CTX_AT, CF_CTX_SIZE, c["ctx"])
    code = m.add_region(CF_CODE_AT, CF_CODE_SIZE, c["code"])
    mem = m.add_region(CF_MEM_AT, CF_MEM_SIZE, c["mem"])
    bm = m.add_region(CF_MAP_AT, CF_MAP_SIZE, c["bitmap"])
    bc = m.add_region(CF_BYTES_AT, CF_BYTES_SIZE, c["bytes"])
    lo, slots = cf_window(c)
    stk = m.add_region(CF_STK_AT + 32 * lo, 32 * slots, cf_stack_image(c))
    side = bytes(x) + bytes(code) + bytes(mem) + bytes(bm) + bytes(bc)
    for k, v in zip(CF_SAVED_REGS, CF_SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = CF_INTERP_AT, CF_CTX_AT
    try:
        m.run(c["body"], limit=2000)
    except Boundary as exc:
        if exc.kind != "panic":
            raise
        return {"panic": True, "at": CF_PANIC_ARMS.get(c["body"]), "ret": None, "n": u(it, CF_I_STACK_LEN, 8),
                "ip": u(it, CF_I_IP, 8), "stack_raw": bytes(stk), "regs_ok": True, "interp_ok": bytes(it) == c["interp"],
                "side_ok": True}
    rest = bytearray(it)
    for off in (CF_I_STACK_LEN, CF_I_IP):
        rest[off:off + 8] = c["interp"][off:off + 8]
    return {"panic": False, "ret": m.regs[0] & 0xff, "n": u(it, CF_I_STACK_LEN, 8), "ip": u(it, CF_I_IP, 8),
            "stack_raw": bytes(stk), "regs_ok": cf_regs_ok(m), "interp_ok": bytes(rest) == c["interp"],
            "side_ok": bytes(x) + bytes(code) + bytes(mem) + bytes(bm) + bytes(bc) == side}


def cf_expected_raw(c, want):
    lo, _ = cf_window(c)
    raw = bytearray(cf_stack_image(c))
    for k, w in want["writes"].items():
        raw[32 * (k - lo):32 * (k - lo) + 32] = w.to_bytes(32, "little")
    return bytes(raw)


def cf_compare(c, want, got):
    if want["panic"] or got["panic"]:
        return want["panic"] == got["panic"] and got["interp_ok"] and got["stack_raw"] == cf_stack_image(c)
    return (want["ret"] == got["ret"] and want["n"] == got["n"] and want["ip"] == got["ip"] and got["regs_ok"]
            and got["interp_ok"] and got["side_ok"] and got["stack_raw"] == cf_expected_raw(c, want))


# ---------------------------------------------------------------- cases
CF_CASES = 6000
CF_OPS = sorted(CF_BODIES)
CF_WEIGHT = {0x00: 1, 0x5b: 1, 0xfe: 1, 0x0c: 1, 0x56: 4, 0x57: 4, 0x58: 2, 0x59: 2, 0xe6: 4, 0xe7: 4, 0xe8: 4}
CF_ROTA = [op for op in CF_OPS for _ in range(CF_WEIGHT[op])]
CF_EDGE = (0, 1, 2, 7, 8, 0xff, M64 - 1, M64, 1 << 64, (1 << 64) + 1, 1 << 128, 1 << 192, M256)
CF_SPECS = (0, 5, 0xb, 0xd, 0xe, 0xf, 0x11, 0xff)
CF_MODES = ("random", "edge", "full-stack", "empty-stack", "valid-dest", "threshold", "gate-edge", "random",
         "high-limb", "near-full", "valid-dest", "threshold", "underflow-arm")


def cf_rand_word(s):
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def cf_depths(op, x):
    """Stack length thresholds of an immediate opcode: the lengths at which its arms change."""
    if op in (0xe6, 0xe7):
        k = cf_decode_single(x)
        return () if k is None else (k - 1, k, k + 1)
    pair = cf_decode_pair(x)
    return () if pair is None else (pair[1] - 1, pair[1], pair[1] + 1)


def cf_make_case(s, k):
    op = CF_ROTA[k % len(CF_ROTA)]
    mode = CF_MODES[(k // len(CF_ROTA)) % len(CF_MODES)]
    it = bytearray(s.take(CF_INTERP_SIZE))
    x = bytes(s.take(CF_CTX_SIZE))
    code = bytearray(s.take(CF_CODE_SIZE))
    mem = bytearray(s.take(CF_MEM_SIZE))
    bitmap = bytearray(s.take(CF_MAP_SIZE))
    raw = bytearray(s.take(CF_BYTES_SIZE))
    bitlen = s.pick((0, 1, 7, 8, 9, 63, 64, 0x200, 0x3ff, 0x400, 8 * CF_MAP_SIZE))
    put(code, CF_C_BITMAP, 8, CF_MAP_AT)
    put(code, CF_C_BITLEN, 8, bitlen)
    put(code, CF_C_BASE, 8, CF_BYTES_AT)
    imm_at = s.below(CF_BYTES_SIZE - 1) + 1
    imm = s.below(256)
    if mode in ("threshold", "underflow-arm") and op in CF_IMMEDIATE_OPS:
        imm = s.pick(tuple(b for b in range(256) if (cf_decode_single(b) if op != 0xe8 else cf_decode_pair(b)) is not None))
    elif mode == "edge" and op in CF_IMMEDIATE_OPS:
        imm = s.pick((0, 0x50, 0x51, 0x52, 0x5a, 0x5b, 0x5c, 0x7f, 0x80, 0x81, 0x8f, 0xfe, 0xff))
    raw[imm_at] = imm
    ip = CF_BYTES_AT + imm_at
    if op == 0x58 and mode == "underflow-arm":
        ip = CF_BYTES_AT
    elif op == 0x58 and mode == "edge":
        ip = s.pick((CF_BYTES_AT + 1, M64, CF_BYTES_AT - 1, 0))
    n = s.pick((1, 2, 3, 17, 0x3fe, 0x3ff))
    if mode == "full-stack":
        n = CF_STACK_LIMIT
    elif mode == "empty-stack":
        n = 0
    elif mode == "near-full":
        n = s.pick((0x3fe, 0x3ff, CF_STACK_LIMIT))
    elif mode in ("threshold", "underflow-arm") and op in CF_IMMEDIATE_OPS:
        n = min(max(s.pick(cf_depths(op, imm) + (0xf0, 0x3ff, CF_STACK_LIMIT)), 0), CF_STACK_LIMIT)
    elif mode == "random" and op in CF_IMMEDIATE_OPS:
        n = s.below(CF_STACK_LIMIT + 1)
    it[CF_I_SPEC] = s.pick(CF_SPECS)
    if mode == "gate-edge":
        it[CF_I_SPEC] = CF_SPEC_GATE - s.pick((0, 1))
    elif op in CF_IMMEDIATE_OPS and s.below(5):
        it[CF_I_SPEC] = s.pick((0xe, 0xf, 0x11, 0xff))
    lo = max(n - cf_depth(op), 0)
    stem = s.take(30)
    words = {i: int.from_bytes(stem + i.to_bytes(2, "little"), "little") for i in range(lo, n)}
    if n and op in (0x56, 0x57):
        valid = [d for d in range(min(bitlen, 8 * CF_MAP_SIZE)) if bitmap[d >> 3] >> (d & 7) & 1]
        if mode in ("valid-dest", "threshold") and valid:
            words[n - 1] = s.pick(valid)
        elif mode in ("edge", "high-limb"):
            words[n - 1] = s.pick(CF_EDGE + (bitlen, bitlen - 1 & M256, bitlen + 1))
        elif mode == "underflow-arm":
            words[n - 1] = s.below(bitlen + 1) if bitlen else 0
        else:
            words[n - 1] = s.pick((s.below(8 * CF_MAP_SIZE + 8), cf_rand_word(s)))
        if mode == "high-limb" and valid:
            words[n - 1] = s.pick(valid) | (1 << s.pick((64, 128, 192, 255)))
    if op == 0x57 and n >= 2:
        words[n - 2] = s.pick((0, 0, 1, 1 << 64, 1 << 128, 1 << 192, 1 << 255, cf_rand_word(s), M256))
    put(it, CF_I_STACK_PTR, 8, CF_STK_AT)
    put(it, CF_I_STACK_LEN, 8, n)
    put(it, CF_I_CODE, 8, CF_CODE_AT)
    put(it, CF_I_IP, 8, ip)
    put(it, CF_I_MEM, 8, CF_MEM_AT)
    ln = s.pick((0, 0x20, 0x40, 0x1000, int.from_bytes(s.take(4), "little"), M64))
    put(mem, CF_M_LEN, 8, ln)
    off = s.pick((0, 0, 0x20, ln, ln - 1 if ln else 0, s.below(ln + 1)))
    if op == 0x59 and mode == "underflow-arm":
        off = ln + s.pick((1, 0x20, 0x1000))
    put(it, CF_I_MEM_OFF, 8, off)
    return {"op": op, "body": CF_BODIES[op][0], "mode": mode, "n": n, "words": words, "imm": imm,
            "interp": bytes(it), "ctx": x, "code": bytes(code), "mem": bytes(mem), "bitmap": bytes(bitmap),
            "bytes": bytes(raw)}


def cf_all_cases():
    s = Stream("re11-control-flow-115")
    return [cf_make_case(s, k) for k in range(CF_CASES)]


# ---------------------------------------------------------------- static evidence
CF_CHECKED = (
    (0x2999600, "b0 01 c3", "STOP: result 0x01"),
    (0x2999584, "48 85 c0", "JUMP: empty stack test (result 0x2c at 0x29995f1)"),
    (0x29995ba, "48 89 47 30", "JUMP: the pop is stored before the destination check"),
    (0x29995ad, "48 c7 c2 ff ff ff ff", "JUMP: destination with a high limb saturates to 2^64 - 1"),
    (0x29995be, "b0 2a", "JUMP: result 0x2a (not a jump destination)"),
    (0x29995c0, "48 3b 51 28", "JUMP: destination below code object +0x28 (bitmap length in bits)"),
    (0x29995c6, "48 8b 71 18", "JUMP: bitmap bytes at code object +0x18"),
    (0x29995dd, "44 0f a3 c6", "JUMP: bt byte, dest & 7 (LSB-first bitmap)"),
    (0x29995e3, "48 03 51 38", "JUMP: new ip = code object +0x38 base + destination"),
    (0x29995e7, "48 89 97 18 01 00 00", "JUMP: ip at interpreter +0x118"),
    (0x2999616, "49 83 f8 02", "JUMPI: two words needed (result 0x2c below)"),
    (0x2999661, "4c 89 47 30", "JUMPI: both words popped before the condition test"),
    (0x2999675, "66 0f 76 c8", "JUMPI: 256-bit condition zero test (pcmpeqd / movmskps)"),
    (0x29994fe, "48 8b 48 38", "PC: code base at code object +0x38"),
    (0x2999513, "48 f7 d1", "PC: not base; add ip = ip - base - 1"),
    (0x299950b, "48 3d 00 04 00 00", "PC: stack length 0x400 = full (push arms share this bound)"),
    (0x2997554, "48 8b 40 28", "MSIZE: memory object (interpreter +0x10) length at +0x28"),
    (0x2997558, "48 2b 47 18", "MSIZE: minus interpreter +0x18 (context memory offset), panic on borrow"),
    (0x2999710, "31 c0 c3", "JUMPDEST: result 0, no state change"),
    (0x29996f0, "b0 29 c3", "INVALID: result 0x29"),
    (0x2999700, "b0 26 c3", "UNDEFINED: result 0x26"),
    (0x2995e10, "80 bf a9 01 00 00 0e", "DUPN: spec byte interpreter +0x1a9 >= 0xe"),
    (0x2995e25, "80 fa 5b", "DUPN: immediate rejected with 0x37 when the SIGNED byte is >= 0x5b"),
    (0x2995e2a, "80 c2 91", "DUPN: depth = immediate + 0x91 (mod 256)"),
    (0x2995e34, "b0 2d", "DUPN: a short stack and a full stack both return 0x2d"),
    (0x2995e3b, "48 81 fa ff 03 00 00", "DUPN: stack length above 0x3ff = full"),
    (0x29970b5, "80 fa 5b", "SWAPN: signed immediate bound 0x5b"),
    (0x29970c4, "48 39 d0", "SWAPN: stack length must exceed the depth (result 0x2c at 0x2997115)"),
    (0x2997139, "80 fa 52", "EXCHANGE: signed immediate bound 0x52"),
    (0x2997142, "48 81 f2 8f 00 00 00", "EXCHANGE: immediate xor 0x8f splits into high / low nibbles"),
    (0x2997151, "41 b8 1d 00 00 00", "EXCHANGE: second depth 29 - high nibble when high >= low"),
    (0x2997172, "48 39 f0", "EXCHANGE: stack length must exceed the deeper depth (result 0x2c at 0x29971cd)"),
)


def cf_opcode_slots(image):
    rows, undefined = {}, {}
    for table in OP_TABLES:
        if image.relative.get(table + 8 * SLOAD_OP) not in SLOAD_BODIES:
            fail(f"opcode table {table:#x} is not anchored by the SLOAD slot")
        for op, (body, _) in sorted(CF_BODIES.items()):
            got = image.relative.get(table + 8 * op)
            if got != body:
                fail(f"opcode table {table:#x} slot {op:#x} is {got}")
            rows[f"{table:#x}+{8 * op:#x}"] = {"opcode": f"{op:#x}", "target": f"{got:#x}"}
        undefined[f"{table:#x}"] = [f"{op:#x}" for op in range(256)
                                    if image.relative.get(table + 8 * op) == CF_UNDEFINED_BODY]
    if len(set(tuple(v) for v in undefined.values())) != 1:
        fail("the two opcode tables disagree on the undefined opcodes")
    return rows, undefined[f"{OP_TABLES[0]:#x}"]


def cf_call_sites(decoded, lo, hi):
    """Every call, indirect jump or out-of-body jmp of a decoded body: (address, kind, target)."""
    out = []
    for va, fm in decoded:
        if fm is None:
            continue
        if fm["op"] == 0xe8 or fm["op"] == 0xe9 and not lo <= fm["target"] < hi:
            out.append((va, "direct", fm["target"]))
        elif fm["op"] == 0xff and fm["reg"] & 7 in (2, 3, 4, 5):
            rm = fm["rm"]
            if rm[0] == "m" and rm[1] == "rip":
                out.append((va, "got", (va + fm["len"] + rm[4]) & M64))
            else:
                out.append((va, "register", None))
    return out


def cf_expected_calls(f):
    return [(CF_PANIC_ARMS[f] + 8, "got", CF_PANIC_SLOT)] if f in CF_PANIC_ARMS else []


def cf_static_evidence(image):
    if CF_PANIC_SLOT in image.imports or CF_PANIC_SLOT not in image.relative:
        fail("panic .got slot is not a RELATIVE slot")
    rows = fde_rows(image, list(CF_CLAIMED))
    decoded, funcs = {}, {}
    names = {b: (op, name) for op, (b, name) in CF_BODIES.items()}
    for f in CF_CLAIMED:
        lo, hi = rows[f]
        decoded[f] = sweep_padded(image, lo, hi)
        calls = cf_call_sites(decoded[f], lo, hi)
        if calls != cf_expected_calls(f):
            fail(f"body {f:#x} has unexpected calls {[(hex(a), k) for a, k, _ in calls]}")
        op, name = names[f]
        funcs[f"{f:#x}"] = {"opcode": f"{op:#x}", "inferred_name": name, "fde_end": f"{hi:#x}",
                            "fde_bytes": hi - lo, "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None),
                            "returns": sum(1 for _, fm in decoded[f] if fm is not None and fm["op"] == 0xc3),
                            "calls": len(calls), "spec_gate": f"{CF_SPEC_GATE:#x}" if op in CF_IMMEDIATE_OPS else None}
    checks = {}
    for va, hx, what in CF_CHECKED:
        want_b = bytes.fromhex(hx)
        if image.code(va, len(want_b)) != want_b:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want_b.hex(), "meaning": what}
    slots, undefined = cf_opcode_slots(image)
    single = {f"{x:#04x}": cf_decode_single(x) for x in range(256) if cf_decode_single(x) is not None}
    pair = {f"{x:#04x}": list(cf_decode_pair(x)) for x in range(256) if cf_decode_pair(x) is not None}
    out = {"binary_sha256": SHA256, "functions": funcs, "opcode_table_slots": slots,
           "undefined_opcodes": undefined, "undefined_opcode_count": len(undefined),
           "checked_bytes": checks, "panic_got_slot": f"{CF_PANIC_SLOT:#x}",
           "panic_got_target": f"{image.relative[CF_PANIC_SLOT]:#x}",
           "panic_arms": {f"{k:#x}": f"{v:#x}" for k, v in sorted(CF_PANIC_ARMS.items())},
           "interpreter_offsets": {"memory_object": f"{CF_I_MEM:#x}", "memory_offset": f"{CF_I_MEM_OFF:#x}",
                                   "stack_ptr": f"{CF_I_STACK_PTR:#x}", "stack_len": f"{CF_I_STACK_LEN:#x}",
                                   "ip": f"{CF_I_IP:#x}", "code_object": f"{CF_I_CODE:#x}", "spec_byte": f"{CF_I_SPEC:#x}"},
           "code_object_offsets": {"bitmap_ptr": f"{CF_C_BITMAP:#x}", "bitmap_bits": f"{CF_C_BITLEN:#x}",
                                   "code_base": f"{CF_C_BASE:#x}"},
           "memory_object_offsets": {"length": f"{CF_M_LEN:#x}"},
           "decode_single": single, "decode_pair_a_b": pair,
           "decode_single_accepted": len(single), "decode_pair_accepted": len(pair),
           "decode_pair_panic_immediates": [k for k, (a, b) in pair.items() if b <= a],
           "stack_limit": CF_STACK_LIMIT,
           "results": {"ok": CF_R_OK, "stop": CF_R_STOP, "undefined": CF_R_UNDEFINED, "invalid": CF_R_INVALID,
                       "bad_jump": CF_R_BAD_JUMP, "not_activated": CF_R_NOT_ACTIVATED, "underflow": CF_R_UNDERFLOW,
                       "overflow": CF_R_OVERFLOW, "bad_immediate": CF_R_BAD_IMMEDIATE}}
    return out, decoded


# ---------------------------------------------------------------- evaluation
CF_MODEL_MUTANTS = ["stop_zero", "dest_truncates", "bound_inclusive", "bitmap_msb_first", "jump_pops_late",
                 "cond_low_limb", "pc_no_minus1", "msize_no_offset", "imm_unsigned", "imm_bias_0x90",
                 "dupn_underflow_2c", "swapn_off_by_one", "pair_swapped", "pair_bound_28"]
CF_BYTE_MUTANTS = [
    (0x2999601, 0x02, "STOP: result 0x01 -> 0x02"),
    (0x29995bf, 0x2b, "JUMP: bad-destination result 0x2a -> 0x2b"),
    (0x29995c9, 0x10, "JUMP: bitmap pointer +0x18 -> +0x10"),
    (0x29995e6, 0x30, "JUMP: code base +0x38 -> +0x30"),
    (0x2999619, 0x03, "JUMPI: two-word bound 2 -> 3"),
    (0x29996c3, 0x30, "JUMPI: code base +0x38 -> +0x30"),
    (0x299950e, 0x05, "PC: stack bound 0x400 -> 0x500"),
    (0x2997557, 0x20, "MSIZE: memory length +0x28 -> +0x20"),
    (0x29996f1, 0x28, "INVALID: result 0x29 -> 0x28"),
    (0x2999701, 0x27, "UNDEFINED: result 0x26 -> 0x27"),
    (0x2995e16, 0x0f, "DUPN: spec gate 0xe -> 0xf"),
    (0x2995e27, 0x5a, "DUPN: immediate bound 0x5b -> 0x5a"),
    (0x2995e2c, 0x90, "DUPN: depth bias 0x91 -> 0x90"),
    (0x2995e35, 0x2c, "DUPN: short-stack result 0x2d -> 0x2c"),
    (0x2997116, 0x2d, "SWAPN: underflow result 0x2c -> 0x2d"),
    (0x29970bc, 0x90, "SWAPN: depth bias 0x91 -> 0x90"),
    (0x299713b, 0x51, "EXCHANGE: immediate bound 0x52 -> 0x51"),
    (0x2997145, 0x8e, "EXCHANGE: immediate xor 0x8f -> 0x8e"),
    (0x2997153, 0x1c, "EXCHANGE: second depth 29 -> 28"),
]


CF_TAGS = {CF_R_OK: "ok", CF_R_STOP: "stop", CF_R_UNDEFINED: "undefined", CF_R_INVALID: "invalid", CF_R_BAD_JUMP: "bad-jump",
        CF_R_NOT_ACTIVATED: "not-activated", CF_R_UNDERFLOW: "underflow", CF_R_OVERFLOW: "overflow",
        CF_R_BAD_IMMEDIATE: "bad-immediate"}


def cf_outcome(c, want, got):
    name = CF_BODIES[c["op"]][1]
    if "error" in got:
        return name + "/error"
    if got["panic"]:
        return name + "/panic"
    out = name + "/" + CF_TAGS.get(got["ret"], f"r{got['ret']:#x}")
    op, n, w = c["op"], c["n"], c["words"]
    if op == 0x57 and got["ret"] == CF_R_OK and n >= 2:
        out += "-not-taken" if w[n - 2] == 0 else "-taken"
    if op in (0x56, 0x57) and got["ret"] in (CF_R_OK, CF_R_BAD_JUMP) and n >= 1 and not (op == 0x57 and w[n - 2] == 0):
        d = w[n - 1]
        out += "-saturated" if d > M64 else ("-past-bitmap" if d >= cf_le(c["code"], CF_C_BITLEN, 8) else "")
    if op == 0xe6 and got["ret"] == CF_R_OVERFLOW:
        out += "-full" if n >= CF_STACK_LIMIT else "-short"
    if op in CF_IMMEDIATE_OPS and got["ret"] == CF_R_OK:
        out += "-negative-imm" if c["imm"] >= 0x80 else "-positive-imm"
    return out


# ================================================================ shared evaluation, controls and output
class Family:
    def __init__(self, key, cases, model, run_case, compare, machine, model_mutants, byte_mutants, static,
                 outcome, row, header):
        self.key, self.cases, self.model, self.run_case, self.compare = key, cases, model, run_case, compare
        self.machine, self.model_mutants, self.byte_mutants, self.static = machine, model_mutants, byte_mutants, static
        self.outcome, self.row, self.header = outcome, row, header


def wtag(x):
    if x is None:
        return "-"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes(64, "little")).hexdigest()[:12]


def ps_row(i, c, want, got, ok, oc):
    fam, n = ps_kind(c["op"])
    if "error" in got:
        res = got["error"]
    else:
        res = f"ret={got['ret']:#x},len={got['len']},adv={got['ptr'] - c['ptr']}"
        if got["ret"] == PS_R_OK and want is not None and fam != "SWAP":
            res += f",word={wtag(want['words'][c['len']])}"
        if fam == "PUSH" and n:
            res += f",read={len(got['code_reads'])}"
    imm = c["code"][c["ptr"]:c["ptr"] + n].hex() if fam == "PUSH" and n else "-"
    top = wtag(c["words"].get(c["len"] - 1))
    return (f"{i}\t{c['op']:#x}\t{ps_name(c['op'])}\t{c['mode']}\t{c['spec']:#x}\t{c['len']}\t{c['ptr']}\t"
            f"{imm}\t{top}\t{oc}\t{res}\t{'yes' if ok else 'NO'}")


def cf_row(i, c, want, got, ok, oc):
    if "error" in got:
        res = got["error"]
    elif got["panic"]:
        res = f"panic@{got['at']:#x}"
    else:
        res = f"ret={got['ret']:#x},n={got['n']},ip+{(got['ip'] - CF_BYTES_AT) & M64:#x}"
        if want is not None and want["writes"]:
            res += ",words=" + "/".join(f"{k}:{wtag(v)}" for k, v in sorted(want["writes"].items()))
    top = c["words"].get(c["n"] - 1) if c["n"] else None
    return (f"{i}\t{c['op']:#x}\t{CF_BODIES[c['op']][1]}\t{c['mode']}\t{c['interp'][CF_I_SPEC]:#x}\t"
            f"{c['imm']:#04x}\t{c['n']}\t{wtag(top)}\t{oc}\t{res}\t{'yes' if ok else 'NO'}")


PS = Family("push-dup-swap", ps_all_cases, ps_model, ps_run_case, ps_compare, ps_CodeMachine, PS_MODEL_MUTANTS,
            PS_BYTE_MUTANTS, ps_static_evidence, lambda c, want, got: ps_outcome(c, got), ps_row,
            "case\topcode\tname\tmode\tspec\tlength\tcode_off\timmediate\ttop\toutcome\tresult\tmatch")
CF = Family("control-flow", cf_all_cases, cf_model, cf_run_case, cf_compare, TraceMachine, CF_MODEL_MUTANTS,
            CF_BYTE_MUTANTS, cf_static_evidence, cf_outcome, cf_row,
            "case\topcode\tname\tmode\tspec\timm\tn\ttop\toutcome\tresult\tmatch")
FAMILIES = (PS, CF)
SHARED_LAYOUT = {"stack_ptr": (PS_I_STACK_PTR, CF_I_STACK_PTR), "stack_len": (PS_I_STACK_LEN, CF_I_STACK_LEN),
                 "code_cursor": (PS_I_CODE_PTR, CF_I_IP), "spec_byte": (PS_I_SPEC, CF_I_SPEC),
                 "result_not_activated": (PS_R_NOT_ACTIVATED, CF_R_NOT_ACTIVATED),
                 "result_underflow": (PS_R_UNDERFLOW, CF_R_UNDERFLOW), "result_overflow": (PS_R_OVERFLOW, CF_R_OVERFLOW),
                 "stack_limit": (PS_LIMIT, CF_STACK_LIMIT)}
SAMPLE_EVERY = 8
# control-flow instructions that no accepted EXCHANGE immediate reaches: push / lea / call of the panic arm
EXPECTED_NOT_EXECUTED = (0x29971d0, 0x29971d1, 0x29971d8)


def shared_layout():
    for k, (a, b) in SHARED_LAYOUT.items():
        if a != b:
            fail(f"the two families disagree on {k}: {a:#x} != {b:#x}")
    return {k: f"{a:#x}" for k, (a, _) in sorted(SHARED_LAYOUT.items())}


def evaluate(fam, image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None):
    m = machine or fam.machine(image, override)
    rows, bad = [], 0
    for i, c in enumerate(cases if cases is not None else fam.cases()):
        try:
            want = fam.model(c, mut)
            got = fam.run_case(m, c)
            ok = fam.compare(c, want, got)
        except (ToolError, KeyError) as exc:  # KeyError: a wrong model reads a slot outside the stack
            want, got, ok = None, {"error": f"{type(exc).__name__}: {exc}"}, False
        except Boundary as exc:
            want, got, ok = None, {"error": f"reached {exc.kind} arm"}, False
        bad += not ok
        rows.append((i, c, want, got, ok))
        if stop_on_first and not ok:
            return rows, bad, m
    return rows, bad, m


def input_controls(image):
    rows = []
    corrupt = bytearray(image.data)
    corrupt[image.text["offset"] + 7] ^= 1
    probes = (("one flipped .text byte", lambda: Image(bytes(corrupt))),
              ("address past .text", lambda: image.code(image.text["address"] + image.text["size"] + 0x100, 4)),
              ("opcode 0x5e outside the PUSH/DUP/SWAP family", lambda: ps_kind(0x5e)),
              ("opcode 0xa0 outside the PUSH/DUP/SWAP family", lambda: ps_kind(0xa0)))
    for what, probe in probes:
        try:
            probe()
            rows.append(("shared", "input", what, 0))
        except ToolError:
            rows.append(("shared", "input", what, 1))
    return rows


def controls(image, cases):
    rows = []
    for fam in FAMILIES:
        for nm in fam.model_mutants:
            _, bad, _ = evaluate(fam, image, mut=frozenset([nm]), stop_on_first=True, cases=cases[fam.key])
            rows.append((fam.key, "model", nm, int(bad > 0)))
        for va, byte, what in fam.byte_mutants:
            if image.code(va, 1)[0] == byte:
                fail(f"byte mutant at {va:#x} does not change the byte")
            _, bad, _ = evaluate(fam, image, override={va: byte}, stop_on_first=True, cases=cases[fam.key])
            rows.append((fam.key, "code", f"{va:#x}={byte:#04x} {what}", int(bad > 0)))
    return rows + input_controls(image)


def compact_constants(consts):
    """One line per decoded immediate instead of one per list item (the values are unchanged)."""
    consts["decode_pair_a_b"] = {k: f"{a},{b}" for k, (a, b) in consts["decode_pair_a_b"].items()}
    return consts


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    layout = shared_layout()
    cases = {fam.key: fam.cases() for fam in FAMILIES}
    classes, summary_fams, executed, not_executed, consts_all = {}, {}, [], [], {}
    for fam in FAMILIES:
        rows, bad, m = evaluate(fam, image, cases=cases[fam.key])
        consts, decoded = fam.static(image)
        full = [fam.header]
        fam_classes = {}
        for i, c, want, got, ok in rows:
            oc = fam.outcome(c, want, got)
            fam_classes[oc] = fam_classes.get(oc, 0) + 1
            full.append(fam.row(i, c, want, got, ok, oc))
        text = "\n".join(full) + "\n"
        (out / f"{fam.key}-cases-sample.tsv").write_text(
            "\n".join([full[0]] + full[1::SAMPLE_EVERY]) + "\n")
        for k, v in fam_classes.items():
            classes[(fam.key, k)] = v
        hit = total = 0
        for start, insns in sorted(decoded.items()):
            for va, f in insns:
                if f is None:
                    continue
                total += 1
                if va in m.seen:
                    hit += 1
                    executed.append(f"{fam.key}\t{start:#x}\t{va:#x}\t{f['bytes'].hex()}")
                else:
                    not_executed.append(f"{fam.key}\t{start:#x}\t{va:#x}\t{f['bytes'].hex()}")
        if fam is PS:
            funcs = consts.pop("functions")
            cols = ("spec_gate", "length_compare", "dup_bias", "code_advance", "failure_results",
                    "reads_code_pointer", "stack_offsets")
            lines = ["opcode\tname\tbody\tfde_end\tfde_bytes\tinstructions\treturns\t" + "\t".join(cols) + "\tsha256"]
            for op in PS_OPS:
                f = funcs[f"{PS_BODIES[op]:#x}"]
                d = f["derived"]
                vals = ["-" if d[k] is None else ",".join(str(x) for x in d[k]) if isinstance(d[k], list)
                        else str(d[k]) for k in cols]
                lines.append(f"{op:#x}\t{ps_name(op)}\t{PS_BODIES[op]:#x}\t{f['fde_end']}\t{f['fde_bytes']}\t"
                             f"{f['instructions']}\t{f['returns']}\t" + "\t".join(vals) + f"\t{f['sha256']}")
            (out / "push-dup-swap-functions.tsv").write_text("\n".join(lines) + "\n")
        else:
            consts = compact_constants(consts)
        consts.pop("binary_sha256")
        consts_all[fam.key] = consts
        summary_fams[fam.key] = {
            "cases": len(rows), "mismatches": bad, "bodies": len(decoded),
            "cases_sha256": hashlib.sha256(text.encode()).hexdigest(), "cases_rows_committed": len(full[1::SAMPLE_EVERY]),
            "instructions": {"executed": hit, "total": total}, "outcome_classes": len(fam_classes),
            "model_mutants": len(fam.model_mutants), "byte_mutants": len(fam.byte_mutants)}
    (out / "outcome-classes.tsv").write_text(
        "family\toutcome\tcases\n" + "".join(f"{f}\t{k}\t{classes[(f, k)]}\n" for f, k in sorted(classes)))
    (out / "not-executed.tsv").write_text("family\tfunction\taddress\tbytes\n" + "".join(r + "\n" for r in not_executed))
    ctl = controls(image, cases)
    (out / "negative-controls.tsv").write_text(
        "family\tkind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    consts_all["binary_sha256"] = SHA256
    consts_all["shared_interpreter_layout"] = layout
    (out / "constants.json").write_text(json.dumps(consts_all, indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "families": summary_fams,
               "cases": sum(v["cases"] for v in summary_fams.values()),
               "mismatches": sum(v["mismatches"] for v in summary_fams.values()),
               "instructions": {"executed": len(executed), "total": len(executed) + len(not_executed),
                                "executed_sha256": hashlib.sha256("".join(r + "\n" for r in executed).encode())
                                .hexdigest()},
               "not_executed_expected": [f"{va:#x}" for va in EXPECTED_NOT_EXECUTED],
               "sample_every": SAMPLE_EVERY,
               "negative_controls": {"total": len(ctl), "detected": sum(r[3] for r in ctl),
                                     "by_kind": {k: sum(1 for r in ctl if r[1] == k) for k in ("model", "code", "input")}}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    summary["not_executed"] = [int(r.split("\t")[2], 16) for r in not_executed]
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: summary[k] for k in ("cases", "mismatches", "instructions", "negative_controls")},
                     sort_keys=True))
    bad = (summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
           or tuple(summary["not_executed"]) != EXPECTED_NOT_EXECUTED)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
