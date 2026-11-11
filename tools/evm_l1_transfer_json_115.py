"""Reconstruct and verify node #115's pretty-JSON serializer of the L1ToEvmNativeTokenTransfer record.

The 0xc0-byte record is written by `l1_transfer_json` 0x22ea830 as one JSON object through serde_json's
PrettyFormatter. Six entries, in this order, each through its own entry path:

  token             u64 at +0x20   entry 0x259bc50: key, ": ", itoa 0x25fba40 (decimal, 20-byte stack buffer),
                                   reserve(len) when len > spare, memcpy; cannot fail
  system_address    b160 at +0x80  inline in the body: key, ": ", address JSON serializer (stubbed)
  contract          b160 at +0x94  inline in the body: key, ": ", address JSON serializer (stubbed)
  wei               U256 at +0x00  inline in the body: key, ": ", U256 JSON serializer (stubbed)
  user              b160 at +0xa8  entry 0x259fdc0: key, ": ", address JSON serializer (stubbed)
  send_to_evm_data  Option at +0x28 guard 0x2339440 (compound state byte != 0 -> serde_json error, else tail jump)
                                   -> entry 0x2598140: key, ": ", "null" when word +0x28 == 0 (reserve 4 when the
                                   spare capacity is <= 3), else the bytes JSON serializer (stubbed)

The body raises current_indent first (u64::MAX panics before any write), writes '{', and closes with end_object
only when every entry succeeded. Any value serializer error returns at once: no '}', current_indent stays raised.

The serde_json helpers the path calls run REAL: serialize_key 0x26077c0, format_escaped_str_contents 0x25bf330
(direct cases drive every escape arm), end_object 0x232b070 and the u64 itoa 0x25fba40. The reconstruction is
`model` (class `JsonFlow`, pure Python). A concrete x86-64 evaluator runs the real bytes of all nine functions with
RawVec::reserve, memcpy and the three value serializers as recording contract stubs, and compares the ordered calls,
every byte appended to the Vec, the final capacity and length, the serializer and compound bytes, the result and
the callee-saved registers. The binary is never executed.
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
RECORD = 0xc0                     # L1ToEvmNativeTokenTransfer record size (one case record slot)
NREC = 2
BODY = 0x22ea830                  # l1_transfer_json: the record's Serialize impl, serde_json PrettyFormatter
ENTRY = {"u64f": 0x259bc50, "addrf": 0x259fdc0, "guard": 0x2339440, "optf": 0x2598140}
HELPERS = {"key": 0x26077c0, "escape": 0x25bf330, "end": 0x232b070}
ITOA = 0x25fba40                  # itoa-style u64 -> decimal into a 20-byte buffer, returns (ptr, len)
CODE = (BODY,) + tuple(ENTRY.values()) + tuple(HELPERS.values()) + (ITOA,)
NAME = {BODY: "l1_transfer_json", ENTRY["u64f"]: "entry_u64", ENTRY["addrf"]: "entry_address",
        ENTRY["guard"]: "entry_option_guard", ENTRY["optf"]: "entry_option_bytes", HELPERS["key"]: "serialize_key",
        HELPERS["escape"]: "format_escaped_str_contents", HELPERS["end"]: "end_object", ITOA: "u64_itoa"}
GROUP_OF = {"body": BODY, "u64f": ENTRY["u64f"], "addrf": ENTRY["addrf"], "guard": ENTRY["guard"],
            "optf": ENTRY["optf"], "itoa": ITOA}
MEMCPY_GOT = 0x64df508
ESCAPE_GOT = 0x64e13d8            # relocated pointer to serde_json's 256-byte ESCAPE table
HEX_GOT = 0x64e13e0               # relocated pointer to the 16 lowercase hex digits used by \u00XX
DIGITS_AT = 0x5f1383              # "000102...99" pair table of the itoa
ERROR_GOT = 0x64e0b08             # serde_json error constructor (code word by pointer, 0, 0) -> boxed error in rax
PANICS = {0x64df520: "add_overflow_panic", 0x64df730: "unreachable_panic", 0x64df848: "sub_overflow_panic"}
INDENT_PANIC_LOC = 0x642dc18      # Location of the current_indent + 1 check in the body
UNREACHABLE_MSG = 0x5f2167        # "internal error: entered unreachable code"
UNREACHABLE_LEN = 0x28
ERROR_CODE = 0x0a                 # code word handed to the error constructor by the guard and the body

# Callees that stay outside the reconstruction; each becomes a recording contract stub.
#   reserve     - RawVec::reserve(vec, len, additional, 1, 1): grows capacity, never returns an error
#   json_value  - (&value, json ser) -> rax: serde_json value serializer, Ok when rax == 0 (else a boxed error)
#   error_ctor  - (&code word, 0, 0) -> rax: boxed serde_json error
STUBS = (
    ("vec_reserve", "reserve", 0x231e050),
    ("b160_json", "json_value", 0x298b150),
    ("u256_json", "json_value", 0x29fed00),
    ("bytes_json", "json_value", 0x22f2810),
)
ROLE_KIND = {r: k for r, k, _ in STUBS}
ROLE_KIND["error_ctor"] = "error_ctor"
ROLE_VA = {r: va for r, _, va in STUBS}

# The record, in serialization order: (key, value kind, record offset, how the entry is written)
FIELDS = (
    ("token", "u64", 0x20, "u64f"),
    ("system_address", "b160", 0x80, "inline"),
    ("contract", "b160", 0x94, "inline"),
    ("wei", "u256", 0x00, "inline"),
    ("user", "b160", 0xa8, "addrf"),
    ("send_to_evm_data", "option_bytes", 0x28, "guard"),
)
FIELD_AT = {"u64f": 0x20, "addrf": 0xa8, "guard": 0x28, "optf": 0x28}


def escape_table():
    """serde_json's ESCAPE table: 'u' for 0x00..0x1f except b/t/n/f/r, '"' and '\\' for themselves, 0 elsewhere."""
    t = [0] * 256
    for b in range(0x20):
        t[b] = ord("u")
    for b, ch in ((0x08, "b"), (0x09, "t"), (0x0a, "n"), (0x0c, "f"), (0x0d, "r"), (0x22, '"'), (0x5c, "\\")):
        t[b] = ord(ch)
    return bytes(t)


ESCAPE = escape_table()
HEXDIG = b"0123456789abcdef"

# Regions of the evaluation
SVEC_AT = 0x7190_0000_0000         # the Vec behind the serde_json Serializer (cap, ptr, len)
SER_AT = 0x71a0_0000_0000          # serde_json pretty Serializer (&Vec, indent ptr, indent len, current_indent,
#                                    has_value byte +0x20)
CMP_AT = 0x71b0_0000_0000          # Compound::Map {state byte +0, First/Rest byte +1, &Serializer +8}
INDENT_AT = 0x71c0_0000_0000
KEY_AT = 0x71d0_0000_0000
ITB_AT = 0x71e0_0000_0000          # 20-byte itoa buffer of the direct itoa cases
JSER_SIZE = 0x28
BUF_AT = 0x7200_0000_0000
BUF_SIZE = 0x2000
ST_AT = 0x7300_0000_0000
ST_SIZE = NREC * RECORD
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)
STACK_LO = STACK_TOP - 0x10000


# ---------------------------------------------------------------- reconstruction
class Panic(Exception):
    def __init__(self, kind, arg):
        super().__init__(kind)
        self.kind, self.arg = kind, arg


def itoa_text(v, mut=frozenset()):
    """Decimal digits of a u64, as the itoa writes them (no sign, no padding)."""
    if "token-u32" in mut:
        v &= 0xffffffff
    if "itoa-hex" in mut:
        return b"%x" % v
    s = b"%d" % v
    if "itoa-leading-zero" in mut and len(s) % 2 and len(s) > 1:
        s = b"0" + s
    return s


class JsonFlow:
    """Python reconstruction of one run: Vec bytes, capacity, ordered calls, Serializer and Compound state, result.
    Every call that a stub answers draws its words from the case plan."""

    def __init__(self, c, mut):
        self.c, self.mut = c, mut
        self.cap, self.ln = c["cap"], len(c["prefix"])
        self.out = bytearray()
        self.calls = []
        self.cur, self.has = c["cur"], c["has_in"]
        self.state, self.first = c["state"], c["first"]

    # -- Vec writes
    def reserve(self, add):
        self.calls.append(("vec_reserve", self.ln, add))
        self.cap = self.ln + add + self.c["extra"]

    def push(self, data):
        self.out.extend(data)
        self.ln += len(data)

    def byte(self, b):
        if self.cap == self.ln and "byte-no-reserve" not in self.mut:
            self.reserve(1)
        self.push(bytes([b]))

    def two(self, data):
        if self.cap - self.ln <= (0 if "two-reserve-lt" in self.mut else 1):
            self.reserve(2)
        self.push(data)

    def run(self, data):
        """Append a byte run: reserve(len) only when len > spare capacity."""
        if len(data) > self.cap - self.ln or ("escape-always-reserve" in self.mut and self.c.get("in_escape")):
            self.reserve(len(data))
        self.push(data)

    def answer(self, role, args):
        k = len(self.calls)
        self.calls.append((role,) + tuple(args))
        c = self.c
        if k < len(c["plan"]):
            return c["plan"][k] if c["fault"] == k else c["okplan"][k]
        return (0x0dead, 0x0dead, 0x0dead)

    # -- serde_json helpers (run real in the machine)
    def indent(self, n):
        text = self.c["indent"]
        if n == 0 or not text:
            return
        for _ in range(n + 1 if "indent-one-more" in self.mut else n):
            if len(text) > self.cap - self.ln:
                self.reserve(len(text))
            self.push(text)

    def escape(self, raw):
        """format_escaped_str_contents: flush the run before each escapable byte, then \\X or \\u00XX."""
        self.c["in_escape"] = True
        start = 0
        for i, b in enumerate(raw):
            e = ESCAPE[b]
            if "escape-del" in self.mut and b == 0x7f:
                e = ord("u")
            if "escape-short-tab" in self.mut and b == 0x09:
                e = ord("u")
            if not e:
                continue
            if i > start:
                self.run(raw[start:i])
            if e == ord("u"):
                if self.cap - self.ln <= (6 if "escape-reserve-lt6" in self.mut else 5):
                    self.reserve(6)
                digits = HEXDIG.upper() if "escape-upper-hex" in self.mut else HEXDIG
                self.push(b"\\u00" + bytes([digits[b >> 4], digits[b & 15]]))
            else:
                if self.cap - self.ln <= 1:
                    self.reserve(2)
                self.push(bytes([0x5c, e]))
            start = i + 1
        if len(raw) > start:
            self.run(raw[start:])
        self.c["in_escape"] = False

    def key(self, name):
        """SerializeMap::serialize_key on Compound::Map: state 1 is unreachable!(); First (byte == 1) writes "\\n",
        anything else ",\\n"; then the byte becomes Rest (2), indent x current_indent, '"' escaped key '"'."""
        if self.state == 1 or ("key-panic-any-nonzero" in self.mut and self.state):
            raise Panic("unreachable_panic", (UNREACHABLE_MSG, UNREACHABLE_LEN))
        first = self.first != 0 if "first-any-nonzero" in self.mut else self.first == 1
        if first or "first-newline-always" in self.mut:
            self.byte(0x0a)
        else:
            self.two(b",\n")
        self.first = 2
        self.indent(self.cur)
        self.byte(0x22)
        self.escape(name)
        self.byte(0x22)

    def colon(self):
        self.two(b":" if "colon-no-space" in self.mut else b": ")

    def end(self):
        """PrettyFormatter::end_object: current_indent - 1; "\\n" + indent only when has_value; '}'."""
        if self.cur == 0:
            raise Panic("sub_overflow_panic", None)
        cur = (self.cur - 1) & M64
        if "end-keeps-indent" not in self.mut:
            self.cur = cur
        if self.has and "end-no-newline" not in self.mut:
            self.byte(0x0a)
            self.indent(cur)
        self.byte(0x7d)

    # -- values
    def value_stub(self, role, at):
        w = self.answer(role, (("S", at), "ser"))
        if w[0] != 0:
            if "has-on-error" in self.mut:
                self.has = 1
            return w[0]
        self.has = 1
        return None

    def entry_u64(self, name, at):
        """0x259bc50: key, ": ", decimal digits of the u64 (reserve(len) when len > spare), has_value = 1."""
        self.key(name)
        self.colon()
        v = u(self.c["st"], at, 8)
        text = itoa_text(v, self.mut)
        if len(text) >= self.cap - self.ln if "itoa-reserve-ge" in self.mut else len(text) > self.cap - self.ln:
            self.reserve(len(text))
        self.push(text)
        if "has-value-unset" not in self.mut:
            self.has = 1
        return None

    def entry_value(self, name, role, at):
        """Inline entries of the body and 0x259fdc0: key, ": ", value serializer, has_value = 1 on success."""
        self.key(name)
        self.colon()
        return self.value_stub(role, at)

    def guard(self, name, at):
        """0x2339440: Compound state byte != 0 -> serde_json error (code 10); else tail jump to 0x2598140."""
        if self.state != 0 and "guard-state-ignored" not in self.mut:
            w = self.answer("error_ctor", (9 if "error-code-9" in self.mut else ERROR_CODE, 0, 0))
            return w[0]
        return self.entry_option(name, at)

    def entry_option(self, name, at):
        """0x2598140: key, ": ", then "null" for a zero tag word (reserve 4 when spare <= 3) or the bytes value."""
        self.key(name)
        self.colon()
        tag = u(self.c["st"], at, 1 if "opt-tag-byte" in self.mut else 8)
        if tag == 0:
            if self.cap - self.ln <= (4 if "null-reserve-lt" in self.mut else 3):
                self.reserve(4)
            self.push(b"null")
            if "opt-has-unset" not in self.mut:
                self.has = 1
            return None
        return self.value_stub("bytes_json", at)

    def fields(self):
        rows = list(FIELDS)
        if "order-wei-first" in self.mut:
            rows.insert(0, rows.pop(3))
        return rows

    def record(self, base):
        """0x22ea830."""
        if self.cur == M64 and "indent-wraps" not in self.mut:
            raise Panic("add_overflow_panic", INDENT_PANIC_LOC)
        self.cur = (self.cur + 1) & M64
        self.has = 0
        self.byte(0x7b)
        self.state, self.first = 0, 1
        for name, kind, off, how in self.fields():
            at = base + off
            if "contract-offset-0x80" in self.mut and name == "contract":
                at = base + 0x80
            if "user-offset-0x94" in self.mut and name == "user":
                at = base + 0x94
            if how == "u64f":
                err = self.entry_u64(name.encode(), at)
            elif how == "guard":
                err = self.guard(name.encode(), at)
            else:
                role = "b160_json" if kind == "b160" else "u256_json"
                if "kinds-swapped" in self.mut and kind == "u256":
                    role = "b160_json"
                err = self.entry_value(name.encode(), role, at)
            if err is not None:
                if "end-on-error" in self.mut:
                    self.end()
                return err
        self.end()
        return 0


def model(c, mut=frozenset()):
    """Predict (calls, appended bytes, capacity, length, rax, current_indent, has_value, compound state/first,
    panic) for one case; itoa cases predict (digits, rax offset, rdx)."""
    if c["group"] == "itoa":
        text = itoa_text(c["value"], mut)
        return {"text": text, "rax": ITB_AT + 20 - len(text), "rdx": len(text)}
    f = JsonFlow(c, mut)
    panic = None
    res = None
    try:
        g = c["group"]
        at = c["base"] + FIELD_AT.get(g, 0)
        if g == "body":
            res = f.record(c["base"])
        elif g == "u64f":
            res = f.entry_u64(c["key"], at) or 0
        elif g == "addrf":
            res = f.entry_value(c["key"], "b160_json", at) or 0
        elif g == "guard":
            res = f.guard(b"send_to_evm_data", at) or 0
        else:
            res = f.entry_option(c["key"], at) or 0
    except Panic as p:
        panic = (p.kind, p.arg)
    return {"calls": f.calls, "data": bytes(f.out), "cap": f.cap, "len": f.ln, "rax": res, "cur": f.cur,
            "has": f.has, "state": f.state, "first": f.first, "panic": panic}


# ---------------------------------------------------------------- evaluation
def arg_ptr(m, v):
    if ST_AT <= v < ST_AT + ST_SIZE:
        return ("S", v - ST_AT)
    if STACK_LO <= v < STACK_TOP:
        return ("stack", bytes(m.load(v + i, 1) for i in range(16)))
    return ("ptr", v)


def who(v):
    return {SER_AT: "ser"}.get(v, ("ptr", v))


def plan_for(c, k):
    if k < len(c["plan"]):
        return c["plan"][k] if c["fault"] == k else c["okplan"][k]
    return (0x0dead, 0x0dead, 0x0dead)


def install(m, c):
    m.calls = []

    def reserve(m):
        r = m.regs
        if r[7] != SVEC_AT or r[1] != 1 or r[8] != 1 or r[6] != m.load(SVEC_AT + 0x10, 8):
            fail("reserve called outside its contract")
        ln, add = r[6], r[2]
        if ln + add + c["extra"] > BUF_SIZE:
            fail("case output larger than the buffer region")
        m.calls.append(("vec_reserve", ln, add))
        m.store(SVEC_AT, 8, ln + add + c["extra"])
        for x in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            r[x] = 0x0dead_0000 | x

    def make(role):
        def stub(m):
            r = m.regs
            k = len(m.calls)
            if role == "error_ctor":
                m.calls.append((role, m.load(r[7], 8), r[6], r[2]))
            else:
                m.calls.append((role, arg_ptr(m, r[7]), who(r[6])))
            r[0] = plan_for(c, k)[0]
            for x in (1, 2, 6, 7, 8, 9, 10, 11):
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

    for role, va in ROLE_VA.items():
        m.stubs[va] = reserve if role == "vec_reserve" else make(role)
    m.stubs[m.image.word(ERROR_GOT)] = make("error_ctor")
    m.stubs[m.image.word(MEMCPY_GOT)] = memcpy
    for got, name in PANICS.items():
        m.stubs[m.image.word(got)] = name


def run_itoa(m, c):
    m.reset()
    install(m, c)
    buf = m.add_region(ITB_AT, 20, c["fill"])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = c["value"], ITB_AT
    m.run(ITOA, limit=20000)
    return {"calls": list(m.calls), "buf": bytes(buf), "rax": m.regs[0], "rdx": m.regs[2],
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100}


def run_case(m, c):
    if c["group"] == "itoa":
        return run_itoa(m, c)
    m.reset()
    install(m, c)
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
    cmp_ = bytearray(c["cmp"])
    cmp_[0], cmp_[1] = c["state"], c["first"]
    put(cmp_, 8, 8, SER_AT)
    inputs = (bytes(ser), bytes(cmp_))
    sreg = m.add_region(SVEC_AT, 0x18, bytes(svec[:0x18]))
    serreg = m.add_region(SER_AT, JSER_SIZE, bytes(ser))
    creg = m.add_region(CMP_AT, 0x10, bytes(cmp_))
    ireg = m.add_region(INDENT_AT, 0x40, c["indent"])
    kreg = m.add_region(KEY_AT, 0x40, c.get("key", b""))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"])
    st = m.add_region(ST_AT, ST_SIZE, bytes(c["st"]))
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    g = c["group"]
    at = ST_AT + c["base"] + FIELD_AT.get(g, 0)
    if g == "body":
        m.regs[7], m.regs[6] = ST_AT + c["base"], SER_AT
    elif g == "guard":
        m.regs[7], m.regs[6] = CMP_AT, at
    else:
        m.regs[7], m.regs[6], m.regs[2], m.regs[1] = CMP_AT, KEY_AT, len(c["key"]), at
    panic = None
    try:
        m.run(GROUP_OF[g], limit=400000)
    except Boundary as b:
        if b.kind not in PANICS.values():
            raise
        arg = {"sub_overflow_panic": None, "unreachable_panic": (b.regs[7], b.regs[6])}.get(b.kind, b.regs[7])
        panic = (b.kind, arg)
    ln = m.load(SVEC_AT + 0x10, 8)
    return {"calls": list(m.calls), "vec": bytes(sreg), "st": bytes(st), "rax": m.regs[0],
            "buf": bytes(buf[:min(ln, BUF_SIZE)]), "tail": bytes(buf[min(ln, BUF_SIZE):]), "len": ln,
            "ser": bytes(serreg), "cmp": bytes(creg), "inputs": inputs, "indent": bytes(ireg), "key": bytes(kreg),
            "panic": panic,
            "regs_ok": panic is not None or ([m.regs[k] for k in SAVED_REGS] == list(SAVED)
                                             and m.regs[4] == STACK_TOP - 0x100)}


def compare(c, want, got):
    """First difference between the model and the machine, or None."""
    if got is None:
        return "tool-error"
    if not got["regs_ok"]:
        return "machine"
    if c["group"] == "itoa":
        n = len(want["text"])
        if got["calls"]:
            return "calls"
        if got["buf"][20 - n:] != want["text"] or got["buf"][:20 - n] != c["fill"][:20 - n]:
            return "bytes"
        if got["rax"] != want["rax"] or got["rdx"] != want["rdx"]:
            return "result"
        return None
    if got["st"] != bytes(c["st"]) or got["indent"][:len(c["indent"])] != c["indent"]:
        return "inputs"
    if got["key"][:len(c.get("key", b""))] != c.get("key", b""):
        return "inputs"
    if got["panic"] != want["panic"]:
        return "panic"
    calls = want["calls"]
    if len(calls) != len(got["calls"]) or any(w != g for w, g in zip(calls, got["calls"])):
        return "calls"
    if got["len"] != want["len"] or got["buf"] != c["prefix"] + want["data"] or any(got["tail"]):
        return "bytes"
    if u(got["vec"], 0, 8) != want["cap"] or u(got["vec"], 8, 8) != BUF_AT:
        return "capacity"
    ser0, cmp0 = got["inputs"]
    if got["panic"] is not None:
        return None if got["ser"][0x21:] == ser0[0x21:] else "serializer"
    if u(got["ser"], 0x18, 8) != want["cur"] or got["ser"][0x20] != want["has"]:
        return "serializer"
    if got["ser"][:0x18] != ser0[:0x18] or got["ser"][0x21:] != ser0[0x21:]:
        return "serializer"
    if c["group"] != "body":
        if got["cmp"][0] != want["state"] or got["cmp"][1] != want["first"] or got["cmp"][2:] != cmp0[2:]:
            return "compound"
    if got["rax"] != want["rax"]:
        return "result"
    return None


# ---------------------------------------------------------------- cases
CASES = {"body": 6000, "u64f": 2500, "addrf": 1500, "guard": 1500, "optf": 2000, "itoa": 3000}
GROUPS = tuple(CASES)
INDENTS = (b"  ", b"  ", b"\t", b"", b"    ", b" ", b"\t\t", b"--", b" " * 9)
CURS = (0, 0, 1, 2, 3, 1, 5, M64, M64 - 1)
DCURS = (0, 1, 1, 2, 3, 4)
SLACK = tuple(range(0, 16)) + (40, 120, 400)
STATES = (0, 0, 0, 0, 0, 1, 2, 0x80, 0xff)
FIRSTS = (1, 1, 2, 2, 0, 3, 0xff)
U64_EDGES = (0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000, 99999, 100000, 99999999, 100000000, 999999999999,
             10 ** 16 - 1, 10 ** 16, 10 ** 19 - 1, 10 ** 19, M64, M64 - 1, 1 << 63, (1 << 32) - 1, 1 << 32)
NAME_POOL = (b"token", b"user", b"send_to_evm_data", b"a", b"", b"system_address")


def plan_words(stream, kind):
    """(ok words, failing words) for one stubbed call."""
    junk = (int.from_bytes(stream.take(8), "little"), int.from_bytes(stream.take(8), "little"))
    if kind == "error_ctor":
        w = 0x7f00_0000_0000 | stream.below(1 << 32) << 4
        return (w,) + junk, (w,) + junk
    return (0,) + junk, (stream.pick((1, ERR_TAG_WORD, 0x7f00_0000_0010, int.from_bytes(stream.take(8), "little")
                                      | 1 << 63)),) + junk


ERR_TAG_WORD = 0x8000000000000000


def fill_plan(stream, c):
    """Grow the per-call word plan along the fault-free path until the call list is stable, then pick the failing
    call: k % (n + 2), so every call position fails in turn and two of every n + 2 cases run fault-free."""
    for _ in range(64):
        calls = model(c)["calls"]
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
    if c["fault"] >= 0 and ROLE_KIND[calls[c["fault"]][0]] != "json_value":
        c["fault"] = -1  # reserve cannot fail; the error constructor always returns its box
    return c


def u64_value(stream, k):
    if k % 4 == 0:
        return stream.pick(U64_EDGES)
    d = 1 + stream.below(20)
    return stream.below(10 ** d) & M64 if d < 20 else (10 ** 19 + stream.below(M64 - 10 ** 19 + 1))


def key_bytes(stream, k):
    """Keys for the direct entry cases: plain names, and every fourth one built to hit the escape arms
    (control bytes, '"', '\\', DEL, high bytes)."""
    if k % 4:
        return stream.pick(NAME_POOL) if k % 3 else bytes(0x61 + stream.below(26) for _ in range(stream.below(30)))
    out = bytearray()
    for _ in range(stream.below(24)):
        r = stream.below(8)
        if r < 3:
            out.append(stream.below(0x20))
        elif r == 3:
            out.append(stream.pick((0x22, 0x5c, 0x7f, 0x2f, 0x27)))
        elif r == 4:
            out.append(0x80 + stream.below(0x80))
        else:
            out.append(0x20 + stream.below(0x5f))
    return bytes(out)


def make_case(stream, group, k):
    if group == "itoa":
        return {"group": group, "k": k, "value": u64_value(stream, k), "fill": stream.take(20)}
    st = bytearray(stream.take(ST_SIZE))
    base = RECORD * stream.below(NREC)
    if k % 2:
        put(st, base + 0x28, 8, 0)          # Option None (tag word 0)
    elif k % 6 == 2:
        put(st, base + 0x28, 8, 1 << stream.below(64))   # Some with a single set bit (high bits test the tag width)
    put(st, base + 0x20, 8, u64_value(stream, k // 2))
    if k % 23 == 5:
        prefix = stream.take(stream.below(3000))
    else:
        prefix = stream.take(stream.below(24))
    ln = len(prefix)
    cap = ln + stream.pick(SLACK)
    if k % 3 == 0:
        cap = ln + stream.below(9)
    c = {"group": group, "k": k, "st": st, "base": base, "svec": bytearray(stream.take(0x18)),
         "jser": bytearray(stream.take(JSER_SIZE)), "cmp": bytearray(stream.take(0x10)), "prefix": prefix,
         "cap": cap, "extra": stream.pick((0, 0, 1, 3, 17)), "fault": -1, "plan": [], "okplan": [],
         "has_in": stream.pick((0, 1, 0x5a))}
    c["indent"] = stream.pick(INDENTS) if k % 11 else stream.take(1 + stream.below(12))
    if group == "body":
        c["cur"] = stream.pick(CURS)
        if c["cur"] == M64 - 1:
            c["indent"] = b""  # a non-empty indent would repeat 2^64 - 1 times
        c["state"], c["first"] = c["cmp"][0], c["cmp"][1]
    else:
        c["cur"] = stream.pick(DCURS)
        c["state"], c["first"] = stream.pick(STATES), stream.pick(FIRSTS)
        if group != "guard":
            c["key"] = key_bytes(stream, k)
    return fill_plan(stream, c)


def all_cases(scale=1.0):
    out = []
    for g in GROUPS:
        s = Stream(f"evm-l1-transfer-json-115/{g}")
        for k in range(int(CASES[g] * scale)):
            out.append(make_case(s, g, k))
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
        elif f["op"] == 0xff and f["rm"][0] == "m" and f["rm"][1] == "rip":
            out.append((v, "got", (v + f["len"] + f["rm"][4]) & M64))
    return out


def key_texts(image, insns):
    """(lea site, text) for every `lea rsi, [rip+d]` followed within three instructions by `mov edx, imm32`: the
    key pointer and length handed to the key writer or an entry helper, read as bytes from the file."""
    out = []
    for i, (v, f) in enumerate(insns):
        if not (f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == "rip" and f["reg"] & 15 == 6):
            continue
        for _, g in insns[i + 1:i + 4]:
            if g["op"] == 0xba and g.get("imm") is not None:
                at = (v + f["len"] + f["rm"][4]) & M64
                out.append((v, image.read(at, g["imm"]).decode("ascii", "replace")))
                break
    return out


def rbx_offsets(insns):
    """Record offsets the body takes from rbx (lea r, [rbx+d] and add rbx, imm)."""
    out = []
    for v, f in insns:
        if f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] == 3 and f["rm"][4]:
            out.append(f["rm"][4])
        elif f["op"] in (0x83, 0x81) and f["reg"] & 7 == 0 and f["rm"] == ("r", 3) and f.get("imm"):
            out.append(f["imm"])
    return out


def body_row(image, ext, va):
    insns = sweep(image, va, ext[va])
    calls = direct_calls(image, va, ext[va])
    role_of = {v: r for r, v in ROLE_VA.items()}
    role_of.update({v: NAME[v] for v in CODE})
    names = dict(PANICS)
    names.update({MEMCPY_GOT: "memcpy", ERROR_GOT: "error_ctor", ESCAPE_GOT: "escape_table",
                  HEX_GOT: "hex_digits"})
    return {"end": ext[va], "size": ext[va] - va, "insns": len(insns),
            "calls": [(v, how, t, names.get(t, "?") if how == "got" else role_of.get(t, "?")) for v, how, t in calls],
            "keys": key_texts(image, insns), "offsets": rbx_offsets(insns)}


def tables(image):
    """The three byte tables the path reads, from the file: ESCAPE (through its GOT slot), hex digits, digit pairs."""
    esc = image.read(image.word(ESCAPE_GOT), 256)
    hexd = image.read(image.word(HEX_GOT), 16)
    pairs = image.read(DIGITS_AT, 200)
    return esc, hexd, pairs


def check_static(image, rows):
    """The facts the model takes from the bytes, re-derived and asserted."""
    b = rows[BODY]
    seq = [(x[3]) for x in b["calls"] if x[1] in ("call", "tail") and x[3] != "vec_reserve"]
    want = ["entry_u64", "serialize_key", "b160_json", "serialize_key", "b160_json", "serialize_key", "u256_json",
            "entry_address", "entry_option_guard", "end_object"]
    if seq != want:
        fail(f"l1_transfer_json call order changed: {seq}")
    if [t for _, t in b["keys"]] != ["token", "system_address", "contract", "wei", "user"]:
        fail(f"l1_transfer_json key texts changed: {b['keys']}")
    if b["offsets"] != [0x20, 0x80, 0x94, 0xa8, 0x28]:
        fail(f"l1_transfer_json record offsets changed: {[hex(x) for x in b['offsets']]}")
    if [t for _, t in rows[ENTRY["guard"]]["keys"]] != ["send_to_evm_data"]:
        fail("option guard key text changed")
    if [x[3] for x in rows[ENTRY["guard"]]["calls"]] != ["entry_option_bytes", "error_ctor"]:
        fail(f"option guard callees changed: {rows[ENTRY['guard']]['calls']}")
    for e, value in (("u64f", "u64_itoa"), ("addrf", "b160_json"), ("optf", "bytes_json")):
        got = [x[3] for x in rows[ENTRY[e]]["calls"] if x[3] not in ("vec_reserve", "unreachable_panic", "memcpy")]
        if got != ["serialize_key", value]:
            fail(f"{NAME[ENTRY[e]]} callees changed: {got}")
    esc, hexd, pairs = tables(image)
    if esc != ESCAPE:
        fail("serde_json ESCAPE table differs from the model")
    if hexd != HEXDIG:
        fail("hex digit table differs from the model")
    if pairs != b"".join(b"%02d" % i for i in range(100)):
        fail("itoa digit-pair table differs from the model")


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
    "indent-wraps", "order-wei-first", "itoa-hex", "itoa-leading-zero", "token-u32", "itoa-reserve-ge",
    "null-reserve-lt", "opt-tag-byte", "has-on-error", "end-on-error", "first-newline-always", "first-any-nonzero",
    "colon-no-space", "two-reserve-lt", "byte-no-reserve", "indent-one-more", "escape-upper-hex", "escape-short-tab",
    "escape-del", "escape-reserve-lt6", "escape-always-reserve", "guard-state-ignored", "key-panic-any-nonzero",
    "contract-offset-0x80", "user-offset-0x94", "kinds-swapped", "end-keeps-indent", "end-no-newline",
    "has-value-unset", "opt-has-unset", "error-code-9",
)

IMM8_OPS = (0x80, 0x83, 0xc6, 0xc0, 0xc1)
# Flip patterns other than bit 0 where bit 0 gives the same machine for every reachable state:
#   0x22eaa1b `cmpb $0, first` -> $1 still calls end_object for Rest (2); $2 skips it.
#   0x25fbb52 `cmp $0x14, rax` (itoa start index bound) -> 0x15 is never exceeded either; 0x0b panics for short numbers.
SITE_XOR = {0x22eaa1b: 0x02, 0x25fbb52: 0x1f}
# has_value is cleared at the start of the body, but the token entry (which cannot fail) always sets it to 1 before
# anything reads it, so no value of this immediate is observable: an equivalent mutant by construction.
EQUIVALENT_SITES = {
    0x22ea856: "has_value = 0 at object start: overwritten by the infallible token entry before any read",
}
# Which case groups reach each function (byte flips run these groups, own group first).
REACHED_BY = {BODY: ("body",), ENTRY["u64f"]: ("u64f", "body"), ENTRY["addrf"]: ("addrf", "body"),
              ENTRY["guard"]: ("guard", "body"), ENTRY["optf"]: ("optf", "guard", "body"),
              HELPERS["key"]: ("u64f", "addrf", "optf", "body"), HELPERS["escape"]: ("u64f", "addrf", "optf"),
              HELPERS["end"]: ("body",), ITOA: ("itoa", "u64f")}


def byte_sites(image, ext, reached):
    """One byte of every immediate operand the cases reach (key lengths, record offsets, reserve sizes, spare
    capacity tests, punctuation bytes, state tests, itoa divisors and bounds), except stack-frame arithmetic."""
    sites = []
    for va in CODE:
        for v, f in sweep(image, va, ext[va]):
            if f.get("imm") is None or f["op"] in (0xe8, 0xe9) or 0x70 <= f["op"] <= 0x7f or v not in reached:
                continue
            if f["op"] & 0xfff0 == 0x0f80:
                continue
            raw = image.read(v, f["len"])
            if f["op"] in (0x83, 0x81) and f["rm"][0] == "r" and f["rm"][1] == 4:
                continue  # rsp adjust
            if f["op"] in IMM8_OPS:
                at = v + f["len"] - 1
            elif f["op"] in (0x81, 0xc7, 0x69) or 0xb8 <= f["op"] <= 0xbf and f["len"] in (5, 6):
                at = v + f["len"] - 4
            elif 0xb8 <= f["op"] <= 0xbf and f["len"] == 10:
                at = v + f["len"] - 8
            elif f["op"] == 0x66c7:
                at = v + f["len"] - 2
            else:
                continue
            if v in EQUIVALENT_SITES:
                continue
            sites.append({"body": va, "insn": v, "at": at, "old": raw[at - v], "xor": SITE_XOR.get(v, 0x01)})
    return sites


def controls(image, cases, sites):
    rows = []
    by_group = {}
    for c in cases:
        by_group.setdefault(c["group"], []).append(c)
    for mut in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, cases, frozenset([mut]), stop_on_first=True)
        rows.append({"control": f"model:{mut}", "detected": bool(bad),
                     "witness": f"{bad[0][0]['group']}/{bad[0][0]['k']}/{bad[0][1]}" if bad else "-"})
    for s in sites:
        override = {s["at"]: s["old"] ^ s["xor"]}
        pool = [c for g in REACHED_BY[s["body"]] for c in by_group[g]]
        _, bad, _ = evaluate(image, pool, override=override, stop_on_first=True)
        rows.append({"control": f"byte:{s['body']:#x}:{s['insn']:#x}:{s['at']:#x}:{s['old']:02x}^{s['xor']:02x}",
                     "detected": bool(bad),
                     "witness": f"{bad[0][0]['group']}/{bad[0][0]['k']}/{bad[0][1]}" if bad else "-"})
    return rows


# ---------------------------------------------------------------- output
SAMPLE_STEP = 5   # every 5th case of each group; all cases are hashed into summary.json


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


def case_line(c, got):
    if c["group"] == "itoa":
        return f"itoa\t{c['k']}\t{c['value']}\t-\t-\t-\t-\t-\t{got['rdx']}\t-\t{got['rax'] - ITB_AT:#x}\t" \
               f"{got['buf'][20 - got['rdx']:].decode()}\t-"
    res = f"panic:{got['panic'][0]}" if got["panic"] else f"{got['rax']:#x}"
    return (f"{c['group']}\t{c['k']}\t{c['base'] // RECORD}\t{c['fault']}\t{c['state']:#x}/{c['first']:#x}\t"
            f"{c['cur'] if c['cur'] < 1 << 32 else hex(c['cur'])}\t{len(c['prefix'])}\t{c['cap']}\t{got['len']}\t"
            f"{u(got['vec'], 0, 8)}\t{res}\t{hexs(got['buf'][len(c['prefix']):])}\t"
            + (" | ".join(call_text(r) for r in got["calls"]) or "-"))


def generate(out, scale=1.0):
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        fail("node #115 digest mismatch")
    image = Image(data)
    ext = extents(image)
    rows = {va: body_row(image, ext, va) for va in CODE}
    check_static(image, rows)
    cases = all_cases(scale)
    results, bad, m = evaluate(image, cases)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first {c['group']}/{c['k']}: {why}")
    reached = m.seen
    sites = byte_sites(image, ext, reached)
    ctl = controls(image, cases, sites)
    missed = [r["control"] for r in ctl if not r["detected"]]
    if missed:
        fail(f"undetected controls: {missed}")
    out.mkdir(parents=True, exist_ok=True)

    lines = ["function\tname\tend\tbytes\tinstructions\treached\tkey_texts\trecord_offsets"]
    cov = ["function\tinstruction\tlength\treason"]
    for va in CODE:
        insns = sweep(image, va, ext[va])
        hit = sum(1 for v, _ in insns if v in reached)
        r = rows[va]
        keys = ",".join(t for _, t in r["keys"]) or "-"
        offs = ",".join(f"{x:#x}" for x in r["offsets"]) if va == BODY else "-"
        lines.append(f"{va:#x}\t{NAME[va]}\t{r['end']:#x}\t{r['size']}\t{r['insns']}\t{hit}\t{keys}\t{offs}")
        for v, f in insns:
            if v not in reached:
                cov.append(f"{va:#x}\t{v:#x}\t{f['len']}\t{unreached_why(va, v)}")
    (out / "functions.tsv").write_text("\n".join(lines) + "\n")
    (out / "unreached.tsv").write_text("\n".join(cov) + "\n")

    crow = ["function\tsite\tkind\ttarget\trole"]
    for va in CODE:
        for v, how, t, role in rows[va]["calls"]:
            crow.append(f"{va:#x}\t{v:#x}\t{how}\t{t:#x}\t{role}")
    (out / "callees.tsv").write_text("\n".join(crow) + "\n")

    frow = ["index\tkey\tvalue_kind\trecord_offset\twritten_by"]
    for i, (name, kind, off, how) in enumerate(FIELDS):
        frow.append(f"{i}\t{name}\t{kind}\t{off:#x}\t{NAME[ENTRY[how]] if how in ENTRY else 'l1_transfer_json'}")
    (out / "fields.tsv").write_text("\n".join(frow) + "\n")

    rows_out = ["group\tcase\trecord_or_value\tfault\tstate/first\tcurrent_indent\tprefix_len\tcap\tfinal_len"
                "\tfinal_cap\tresult\tappended\tcall_list"]
    for c, got, _ in results:
        if c["k"] % SAMPLE_STEP == 0:
            rows_out.append(case_line(c, got))
    (out / "cases-sample.tsv").write_text("\n".join(rows_out) + "\n")

    crows = ["control\tdetected\twitness"]
    for r in ctl:
        crows.append(f"{r['control']}\t{'yes' if r['detected'] else 'no'}\t{r['witness']}")
    (out / "controls.tsv").write_text("\n".join(crows) + "\n")

    by = {}
    digest = hashlib.sha256()
    for c, got, _ in results:
        d = by.setdefault(c["group"], {"cases": 0, "ok": 0, "error": 0, "panic": 0, "reserve_calls": 0})
        d["cases"] += 1
        if c["group"] == "itoa":
            d["ok"] += 1
        else:
            d["ok" if got["panic"] is None and got["rax"] == 0 else "panic" if got["panic"] else "error"] += 1
            d["reserve_calls"] += sum(1 for r in got["calls"] if r[0] == "vec_reserve")
        digest.update((case_line(c, got) + "\n").encode())
    summary = {
        "binary_sha256": SHA256,
        "functions": len(CODE),
        "instructions": sum(len(sweep(image, va, ext[va])) for va in CODE),
        "instructions_reached": sum(1 for va in CODE for v, _ in sweep(image, va, ext[va]) if v in reached),
        "cases": len(results),
        "mismatches": 0,
        "controls": len(ctl),
        "controls_detected": sum(1 for r in ctl if r["detected"]),
        "model_mutants": len(MODEL_MUTANTS),
        "byte_flips": len(sites),
        "equivalent_sites_excluded": len(EQUIVALENT_SITES),
        "all_cases_sha256": digest.hexdigest(),
        "per_group": dict(sorted(by.items())),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return summary


def unreached_why(va, v):
    """Why an instruction of the evaluated code is never reached by the cases (checked by the unit tests)."""
    if va == HELPERS["escape"]:
        return "alignment padding (multi-byte nop) between two blocks of the escape loop, never executed"
    if va == ITOA:
        return "overflow panic arm: the write index never leaves 0..20 for a u64"
    if va == HELPERS["end"]:
        return "current_indent == 0 panic: the body incremented it before the call"
    if va == BODY:
        return "state byte != 0 error arm / end skipped: the body builds Compound::Map {state 0, First} itself"
    if va in (ENTRY["u64f"], ENTRY["addrf"], ENTRY["optf"]):
        return "state byte == 1 panic arm: serialize_key already panicked for state 1"
    return "unexplained"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--scale", type=float, default=1.0, help="case count multiplier (default 1.0 = 16,500 cases)")
    a = ap.parse_args(argv)
    try:
        s = generate(a.out, a.scale)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{s['cases']} cases, {s['mismatches']} mismatches, {s['controls_detected']}/{s['controls']} controls, "
          f"{s['instructions_reached']}/{s['instructions']} instructions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
