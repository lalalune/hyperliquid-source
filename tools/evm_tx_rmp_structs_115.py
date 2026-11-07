"""Reconstruct and verify the rmp-serde struct serializers of node #115's EVM transaction bodies.

Thirteen bodies serialize seven structs - the Legacy, EIP-2930, EIP-1559, EIP-4844 and EIP-7702 transaction bodies
and a destination-call record (destination_recipient, destination_chain_id, gas_limit, nonce, data), each in two copy
families, plus the block header (family a only, header count computed from the raw optional-field tags) - through
rmp-serde's `Serializer<&mut Vec<u8>, C>`: a map or array length header chosen by serializer byte +0xb, the field names when that byte is 1, then one nested serializer call per field, with early return of the
first error. Legacy's chainId is an Option that is skipped (and the header count lowered) when its word is 0; the
block header skips eight optional fields and adds their raw tags (not their presence) to the header count. Two more
copies of the destination-call serializer take the Vec<u8> itself as serializer and write the header byte and four
names inline (header byte 0x85 | (flag ^ 1) << 4, fixstr markers, RawVec reserve when spare capacity is short).

The reconstruction is `model`: a declarative field table per struct plus the presence, header, name and error rules.
A concrete x86-64 evaluator runs the real bytes of each body on generated cases with every callee replaced by a
recording contract stub (the callee's role is fixed by a role table for each copy family) and compares the ordered
call list with normalized arguments (struct offsets, stack copies, name texts, header counts), the 24-byte result
record, the callee-saved registers and the untouched inputs. The binary is never executed.
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
ERR_TAG = 0x8000000000000000      # result word 0 for "rmp encode error carried in words 1..2"
OK_TAG = ERR_TAG | 4              # result word 0 for Ok(()) of a nested serializer
WRITER_OK = 2                     # low-level rmp writers report success as word 0 == 2
FLAG_AT = 0xb                     # serializer byte: 1 = struct-as-map (write field names)

# Two copy families of the same monomorphs. Every callee is named by its role; the role table says where each
# family's copy lives. "hdr_map"/"hdr_seq" are the two length-header writers selected by the serializer flag.
ROLES = (
    ("hdr_map", "slot_writer", 0x25e7670, 0x3d4f6d0),
    ("hdr_seq", "slot_writer", 0x25e7940, 0x3d50270),
    ("str", "rax_writer", 0x25e8750, 0x41c6110),
    ("uint", "slot_writer", 0x25e9c70, 0x3d517e0),
    ("b256", "nested", 0x298c640, 0x3d3fa20),
    ("opt_chain", "nested", 0x2967a00, 0x3d3ee70),
    ("u64", "nested", 0x29fe9c0, 0x43c4270),
    ("u128", "nested", 0x2968180, 0x43c3e10),
    ("tx_kind", "nested", 0x26e5610, 0x3f47010),
    ("kf_value", "keyed", 0x233b370, 0x44fa5c0),
    ("kf_bytes", "keyed", 0x233a820, 0x44f76c0),
    ("if_to_1559", "inner", 0x233af30, 0x44fbeb0),
    ("if_access_list", "inner", 0x233a0e0, 0x44f7bb0),
    ("if_to_addr", "inner", 0x2339dc0, 0x44fa6c0),
    ("if_blob_hashes", "inner", 0x233a080, 0x44f8380),
    ("if_blob_fee", "inner", 0x233b8a0, 0x44fc1b0),
    ("if_auth_list", "inner", 0x233bc40, 0x44f8fa0),
    # block header only (no family b copy of the header body was found)
    ("b160", "nested", 0x298ac30, None),
    ("kf_b256", "keyed", 0x233b840, None),
    ("if_bloom", "inner", 0x233b900, None),
    ("if_number", "inner", 0x233a480, None),
    ("if_gas_limit", "inner", 0x233a010, None),
    ("if_gas_used", "inner", 0x233a7b0, None),
    ("if_timestamp", "inner", 0x233ad20, None),
    ("if_nonce", "inner", 0x233af90, None),
    ("if_opt_base_fee", "inner", 0x233a610, None),
    ("kf_opt_b256", "keyed", 0x233b3d0, None),
    ("if_opt_blob_gas_used", "inner", 0x233a5b0, None),
    ("if_opt_excess_blob_gas", "inner", 0x233acc0, None),
    ("if_opt_tail", "inner", 0x2339fb0, None),
)
ROLE_KIND = {r: k for r, k, _, _ in ROLES}
FAMILY_ROLE = {"a": {r: a for r, _, a, _ in ROLES}, "b": {r: b for r, _, _, b in ROLES if b is not None}}
ROLE_OF = {}
for _fam, _tab in FAMILY_ROLE.items():
    for _r, _va in _tab.items():
        ROLE_OF[_va] = (_fam, _r)

# Field rows: (name, how, role, offset). how:
#   key   - the body writes the name with "str" when the flag is 1, then calls role(out, &S[off], ser)
#   u64   - like key, but the u64 at S[off] is first copied to the stack and passed by reference
#   u128  - like key; family a passes &S[off], family b a stack copy of the 16 bytes
#   uint  - like key, but the body calls "uint"(out, ser, S[off]) (u64, or u32 for "uint32")
#   keyed - the body calls role(out, ser, name, len(name), &S[off]); the callee writes the name itself
#   inner - the body calls role(out, ser, &S[off]); name handling is inside the callee
#   optkey    - key, present only when the u64 at S[off] is not 0 (Legacy chainId)
#   inner_opt - inner, present only when the u64 at S[off] is not 0
#   keyed_opt - keyed, present only when the byte at S[off] is exactly 1
# A count of None means the header count is computed (block header, see header_count).
STRUCTS = {
    "destination_call": (5, [
        ("destination_recipient", "key", "b256", 0x20),
        ("destination_chain_id", "uint32", "uint", 0x50),
        ("gas_limit", "uint", "uint", 0x40),
        ("nonce", "uint", "uint", 0x48),
        ("data", "keyed", "kf_bytes", 0x0),
    ]),
    "legacy": (7, [
        ("chainId", "optkey", "opt_chain", 0x0),
        ("nonce", "u64", "u64", 0x60),
        ("gasPrice", "u128", "u128", 0x30),
        ("gas", "u64", "u64", 0x68),
        ("to", "key", "tx_kind", 0x70),
        ("value", "keyed", "kf_value", 0x40),
        ("input", "keyed", "kf_bytes", 0x10),
    ]),
    "eip2930": (8, [
        ("chainId", "u64", "u64", 0x50),
        ("nonce", "u64", "u64", 0x58),
        ("gasPrice", "u128", "u128", 0x40),
        ("gas", "u64", "u64", 0x60),
        ("to", "key", "tx_kind", 0x80),
        ("value", "keyed", "kf_value", 0x0),
        ("", "inner", "if_access_list", 0x68),
        ("input", "keyed", "kf_bytes", 0x20),
    ]),
    "eip1559": (9, [
        ("chainId", "u64", "u64", 0x60),
        ("nonce", "u64", "u64", 0x68),
        ("gas", "u64", "u64", 0x70),
        ("maxFeePerGas", "u128", "u128", 0x40),
        ("maxPriorityFeePerGas", "u128", "u128", 0x50),
        ("", "inner", "if_to_1559", 0x90),
        ("value", "keyed", "kf_value", 0x0),
        ("", "inner", "if_access_list", 0x78),
        ("input", "keyed", "kf_bytes", 0x20),
    ]),
    "eip4844": (11, [
        ("chainId", "u64", "u64", 0x70),
        ("nonce", "u64", "u64", 0x78),
        ("gas", "u64", "u64", 0x80),
        ("maxFeePerGas", "u128", "u128", 0x40),
        ("maxPriorityFeePerGas", "u128", "u128", 0x50),
        ("", "inner", "if_to_addr", 0xb8),
        ("value", "keyed", "kf_value", 0x0),
        ("", "inner", "if_access_list", 0x88),
        ("", "inner", "if_blob_hashes", 0xa0),
        ("", "inner", "if_blob_fee", 0x60),
        ("input", "keyed", "kf_bytes", 0x20),
    ]),
    "eip7702": (10, [
        ("chainId", "u64", "u64", 0x60),
        ("nonce", "u64", "u64", 0x68),
        ("gas", "u64", "u64", 0x70),
        ("maxFeePerGas", "u128", "u128", 0x40),
        ("maxPriorityFeePerGas", "u128", "u128", 0x50),
        ("", "inner", "if_to_addr", 0xa8),
        ("value", "keyed", "kf_value", 0x0),
        ("", "inner", "if_access_list", 0x78),
        ("", "inner", "if_auth_list", 0x90),
        ("input", "keyed", "kf_bytes", 0x20),
    ]),
}
STRUCTS["block_header"] = (None, [
    ("parentHash", "key", "b256", 0x60),
    ("sha3Uncles", "key", "b256", 0x80),
    ("miner", "key", "b160", 0x268),
    ("stateRoot", "key", "b256", 0xa0),
    ("transactionsRoot", "key", "b256", 0xc0),
    ("receiptsRoot", "keyed", "kf_b256", 0xe0),
    ("", "inner", "if_bloom", 0x100),
    ("difficulty", "keyed", "kf_value", 0x200),
    ("", "inner", "if_number", 0x220),
    ("", "inner", "if_gas_limit", 0x228),
    ("", "inner", "if_gas_used", 0x230),
    ("", "inner", "if_timestamp", 0x238),
    ("extraData", "keyed", "kf_bytes", 0x40),
    ("mixHash", "keyed", "kf_b256", 0x240),
    ("", "inner", "if_nonce", 0x260),
    ("", "inner_opt", "if_opt_base_fee", 0x0),
    ("withdrawalsRoot", "keyed_opt", "kf_opt_b256", 0x27c),
    ("", "inner_opt", "if_opt_blob_gas_used", 0x10),
    ("", "inner_opt", "if_opt_excess_blob_gas", 0x20),
    ("parentBeaconBlockRoot", "keyed_opt", "kf_opt_b256", 0x29d),
    ("requestsHash", "keyed_opt", "kf_opt_b256", 0x2be),
    ("blockAccessListHash", "keyed_opt", "kf_opt_b256", 0x2df),
    ("", "inner_opt", "if_opt_tail", 0x30),
])
HEADER_TERMS = (("w0", 0x0), ("u8", 0x27c), ("lo32", 0x10), ("lo32", 0x20), ("u8", 0x29d), ("u8", 0x2be),
                ("u8", 0x2df), ("lo32", 0x30))


def header_count(st, mut=frozenset()):
    """Block header map/array length: 16 - (word 0 == 0) + every optional field's RAW tag (byte or low 32 bits),
    wrapping at 2^32. Presence itself is tested with `!= 0` / `== 1`, so non-canonical tags disagree with it."""
    n = 0x10
    for kind, off in HEADER_TERMS:
        if kind == "w0":
            n -= u(st, off, 8) == 0
        elif "count-presence-only" in mut:
            n += (u(st, off, 1) == 1) if kind == "u8" else (u(st, off, 8) != 0)
        else:
            n += u(st, off, 1) if kind == "u8" else u(st, off, 4)
    return n & 0xffffffff


BODIES = {
    0x22daf00: ("a", "block_header"),
    0x22f2a20: ("a", "destination_call"), 0x44dad80: ("b", "destination_call"),
    0x2331bf0: ("a", "legacy"), 0x44ec9f0: ("b", "legacy"),
    0x2332eb0: ("a", "eip2930"), 0x44ed9b0: ("b", "eip2930"),
    0x2332430: ("a", "eip1559"), 0x44ed300: ("b", "eip1559"),
    0x2333150: ("a", "eip4844"), 0x44ee450: ("b", "eip4844"),
    0x2333c30: ("a", "eip7702"), 0x44eeb50: ("b", "eip7702"),
}
UNWIND_RESUME = 0x63f0a50

SER_AT = 0x7100_0000_0000
ST_AT = 0x7300_0000_0000
ST_SIZE = 0x300
OUT_AT = 0x7500_0000_0000
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)


# ---------------------------------------------------------------- reconstruction
def fields_of(c, mut=frozenset()):
    """The struct's field list as the body serializes it, after the presence rule."""
    count, rows = STRUCTS[c["struct"]]
    rows = list(rows)
    if "swap-first-two" in mut:
        rows[0], rows[1] = rows[1], rows[0]
    st = c["st"]
    if count is None:
        count = header_count(st, mut)
    out = []
    for row in rows:
        if row[1] == "inner_opt" and u(st, row[3], 8) == 0:
            continue
        if row[1] == "keyed_opt":
            b = u(st, row[3], 1)
            if not ((b != 0) if "opt-byte-nonzero" in mut else (b == 1)):
                continue
        if row[1] == "optkey":
            w0 = u(st, row[3], 8)
            present = (w0 == 1) if "opt-when-one" in mut else (w0 != 0 or "opt-always" in mut)
            if not present:
                count -= 1
                continue
        out.append(row)
    if "count-plus-one" in mut:
        count += 1
    return count, out


def model(c, mut=frozenset()):
    """Predict the ordered callee list and the 24-byte result record of one body run."""
    fam = c["family"]
    st, flag = c["st"], c["flag"]
    keys = (flag != 0) if "keys-when-nonzero" in mut else (flag == 1)
    as_map = (flag == 1) if "map-when-one" in mut else (flag != 0)
    count, rows = fields_of(c, mut)
    calls = []
    plan = c["plan"]

    def call(role, args):
        k = len(calls)
        calls.append((role,) + tuple(args))
        kind = ROLE_KIND[role]
        if c["fault"] != k:
            return None
        w = plan[k]
        if kind == "rax_writer":
            if "str-error-three-words" in mut:
                return (w[0], w[1], w[2])
            return (ERR_TAG, w[0], w[1])
        if kind == "slot_writer":
            if "slot-error-raw" in mut:
                return (w[0], w[1], w[2])
            return (ERR_TAG, w[0], w[1])
        if "nested-error-wrapped" in mut:
            return (ERR_TAG, w[0], w[1])
        return (w[0], w[1], w[2])

    def finish(res):
        if res is not None and "continue-after-error" not in mut:
            return res
        return None

    res = call("hdr_map" if as_map else "hdr_seq", ("stk", "ser", count & 0xffffffff))
    if finish(res):
        return calls, res
    for name, how, role, off in rows:
        if "value-off-plus-8" in mut and name == "value":
            off += 8
        if how in ("key", "optkey", "u64", "u128", "uint", "uint32") or ("keyed-key-in-body" in mut and how == "keyed"):
            if keys and name:
                res = call("str", ("ser", name.encode()))
                if finish(res):
                    return calls, res
        if how in ("key", "optkey"):
            res = call(role, ("stk", ("S", off), "ser"))
        elif how == "u64":
            n = 16 if "u64-copy-16" in mut else 8
            res = call(role, ("stk", ("copy", bytes(st[off:off + n])), "ser"))
        elif how == "u128":
            if fam == "a" or "u128-pointer" in mut:
                res = call(role, ("stk", ("S", off), "ser"))
            else:
                res = call(role, ("stk", ("copy", bytes(st[off:off + 16])), "ser"))
        elif how == "uint":
            res = call(role, ("stk", "ser", u(st, off, 8)))
        elif how == "uint32":
            res = call(role, ("stk", "ser", u(st, off, 8 if "chain-id-u64" in mut else 4)))
        elif how in ("keyed", "keyed_opt"):
            res = call(role, ("stk", "ser", name.encode(), ("S", off)))
        elif how in ("inner", "inner_opt"):
            res = call(role, ("stk", "ser", ("S", off)))
        if finish(res):
            return calls, res
    if "ok-writes-all-words" in mut:
        return calls, (OK_TAG, 0, 0)
    return calls, (OK_TAG,)


# ---------------------------------------------------------------- evaluation
class CaseMachine(TraceMachine):
    def step(self, va):
        if self.lo <= va < self.hi:
            self.seen.add(va)
        return Machine.step(self, va)


def arg_ptr(m, v):
    if ST_AT <= v < ST_AT + ST_SIZE:
        return ("S", v - ST_AT)
    if STACK_TOP - 0x10000 <= v < STACK_TOP:
        return ("stack", bytes(m.load(v + i, 1) for i in range(16)))
    return ("ptr", v)


def text_at(m, ptr, n):
    if n > 64:
        return ("long", ptr, n)
    try:
        return bytes(m.load(ptr + i, 1) for i in range(n))
    except Exception:
        return ("bad", ptr, n)


def install(m, c):
    fam = c["family"]
    m.calls = []

    def make(role):
        kind = ROLE_KIND[role]

        def stub(m):
            r = m.regs
            k = len(m.calls)
            if kind == "rax_writer":
                rec = (role, "ser" if r[7] == SER_AT else ("ptr", r[7]), text_at(m, r[6], r[2]))
            elif kind == "slot_writer":
                rec = (role, "stk" if STACK_TOP - 0x10000 <= r[7] < STACK_TOP else ("ptr", r[7]),
                       "ser" if r[6] == SER_AT else ("ptr", r[6]),
                       r[2] & 0xffffffff if role.startswith("hdr") else r[2])
            elif kind == "nested":
                rec = (role, "stk" if STACK_TOP - 0x10000 <= r[7] < STACK_TOP else ("ptr", r[7]),
                       arg_ptr(m, r[6]), "ser" if r[2] == SER_AT else ("ptr", r[2]))
            elif kind == "keyed":
                rec = (role, "stk" if STACK_TOP - 0x10000 <= r[7] < STACK_TOP else ("ptr", r[7]),
                       "ser" if r[6] == SER_AT else ("ptr", r[6]), text_at(m, r[2], r[1]), arg_ptr(m, r[8]))
            else:
                rec = (role, "stk" if STACK_TOP - 0x10000 <= r[7] < STACK_TOP else ("ptr", r[7]),
                       "ser" if r[6] == SER_AT else ("ptr", r[6]), arg_ptr(m, r[2]))
            m.calls.append(rec)
            if k < len(c["plan"]):
                w = c["plan"][k] if c["fault"] == k else c["okplan"][k]
            else:
                w = (0x0dead, 0x0dead, 0x0dead)
            if kind == "rax_writer":
                r[0], r[2] = w[0], w[1]
            else:
                if not STACK_TOP - 0x10000 <= r[7] < STACK_TOP:
                    fail("result slot is not on the stack")
                m.store(r[7], 8, w[0])
                m.store(r[7] + 8, 8, w[1])
                m.store(r[7] + 16, 8, w[2])
                r[0] = r[7]
            for x in (1, 6, 7, 8, 9, 10, 11):
                r[x] = 0x0dead_0000 | x
        return stub

    for role, va in FAMILY_ROLE[fam].items():
        m.stubs[va] = make(role)


def run_case(m, c):
    m.reset()
    install(m, c)
    va = c["body"]
    m.lo, m.hi = va, m.extents[va]
    ser = bytearray(c["ser"])
    sreg = m.add_region(SER_AT, 0x10, bytes(ser))
    st = m.add_region(ST_AT, ST_SIZE, bytes(c["st"]))
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2] = OUT_AT, ST_AT, SER_AT
    m.run(va, limit=20000)
    return {"calls": list(m.calls), "result": bytes(out), "ser": bytes(sreg), "st": bytes(st),
            "rax": m.regs[0],
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100}


def match_call(want, got):
    if len(want) != len(got) or want[0] != got[0]:
        return False
    for w, g in zip(want[1:], got[1:]):
        if isinstance(w, tuple) and w[0] == "copy":
            if not (isinstance(g, tuple) and g[0] == "stack" and g[1][:len(w[1])] == w[1]):
                return False
        elif w != g:
            return False
    return True


def compare(c, want, got):
    if got is None:
        return "tool-error"
    if not got["regs_ok"] or got["rax"] != OUT_AT:
        return "machine"
    if got["ser"] != bytes(c["ser"]) or got["st"] != bytes(c["st"]):
        return "inputs"
    wcalls, res = want
    if len(wcalls) != len(got["calls"]) or not all(match_call(w, g) for w, g in zip(wcalls, got["calls"])):
        return "calls"
    if len(res) == 1:
        expect = res[0].to_bytes(8, "little") + b"\x5a" * 0x10
    else:
        expect = b"".join(x.to_bytes(8, "little") for x in res)
    if got["result"] != expect:
        return "result"
    return None


# ---------------------------------------------------------------- cases
PER_BODY = 1000
FLAGS = (0, 1, 1, 1, 0, 2, 0x80, 0xff, 1, 0)


def plan_words(stream, kind, fault):
    """Return words for one call: ok words, or (when it is the faulting call) an error triple."""
    junk = (int.from_bytes(stream.take(8), "little"), int.from_bytes(stream.take(8), "little"))
    if kind in ("rax_writer", "slot_writer"):
        okw = WRITER_OK
        bad = stream.pick((0, 1, 3, OK_TAG, ERR_TAG, int.from_bytes(stream.take(8), "little") | 1 << 40))
    else:
        okw = OK_TAG
        bad = stream.pick((WRITER_OK, ERR_TAG, ERR_TAG | 3, ERR_TAG | 5, 0, int.from_bytes(stream.take(8), "little") | 1 << 40))
    return (okw,) + junk, (bad,) + junk


def make_case(stream, va, k):
    fam, struct_ = BODIES[va]
    st = bytearray(stream.take(ST_SIZE))
    if struct_ == "legacy":
        put(st, 0, 8, stream.pick((0, 0, 1, 1, 2, 0xff, 1 << 63, int.from_bytes(stream.take(8), "little"))))
    if struct_ == "block_header":
        for kind, off in HEADER_TERMS:
            if kind == "u8":
                st[off] = stream.pick((0, 0, 1, 1, 1, 2, 0xff, stream.below(256)))
            else:
                put(st, off, 8, stream.pick((0, 0, 1, 1, 2, 1 << 32, (1 << 32) + 1, 0xffffffff,
                                             int.from_bytes(stream.take(8), "little"))))
    if k % 7 == 3 and struct_ != "block_header":  # zero/one edges of the copied integers
        for off in range(0x30, 0xc0, 8):
            put(st, off, 8, stream.pick((0, 1, 0xffffffff, 1 << 32, (1 << 64) - 1)))
    ser = bytearray(stream.take(0x10))
    ser[FLAG_AT] = FLAGS[k % len(FLAGS)] if k % 13 else stream.below(256)
    c = {"body": va, "family": fam, "struct": struct_, "k": k, "st": st, "ser": ser, "flag": ser[FLAG_AT]}
    c["fault"] = -1
    c["plan"], c["okplan"] = [], []
    calls, _ = model(c)
    n = len(calls)
    c["fault"] = -1 if k % (n + 2) == n + 1 else k % (n + 2) if k % (n + 2) < n else -1
    for j, rec in enumerate(calls):
        ok, bad = plan_words(stream, ROLE_KIND[rec[0]], j == c["fault"])
        c["okplan"].append(ok)
        c["plan"].append(bad)
    return c


def all_cases(per_body=PER_BODY):
    out = []
    for va in sorted(BODIES):
        s = Stream(f"evm-tx-rmp-structs-115/{va:#x}")
        for k in range(per_body):
            out.append(make_case(s, va, k))
    return out


# ---------------------------------------------------------------- static checks (from ELF bytes)
def extents(image):
    _, ordered, _ = fde_extents.fde_extents(image.data)
    ext = {f["start"]: f["end"] for f in ordered}
    for va in BODIES:
        if va not in ext:
            fail(f"no FDE starts at {va:#x}")
    return ext


def direct_calls(image, va, end):
    out = []
    for v, f in sweep(image, va, end):
        if f["op"] in (0xe8, 0xe9) and "target" in f:
            if f["op"] == 0xe9 and va <= f["target"] < end:
                continue
            out.append((v, "call" if f["op"] == 0xe8 else "jmp", f["target"]))
        elif f["op"] == 0xff and f["reg"] & 7 in (2, 4) and f["rm"][0] == "m" and f["rm"][1] == "rip":
            out.append((v, "got", v + f["len"] + f["rm"][4]))
    return out


def rip_texts(image, insns):
    """Every `lea rel(%rip)` followed (within three instructions) by `mov $n, %edx/%ecx`: (va, text)."""
    out = []
    for i, (v, f) in enumerate(insns):
        if f["op"] != 0x8d or f["rm"][0] != "m" or f["rm"][1] != "rip":
            continue
        at = (v + f["len"] + f["rm"][4]) & M64
        for _, g in insns[i + 1:i + 4]:
            if g["op"] in (0xba, 0xb9) and g.get("imm") is not None and 0 < g["imm"] < 64:
                out.append((v, image.read(at, g["imm"])))
                break
    return out


def body_row(image, ext, va):
    fam, struct_ = BODIES[va]
    insns = sweep(image, va, ext[va])
    roles = []
    for v, kind, t in direct_calls(image, va, ext[va]):
        if t == UNWIND_RESUME:
            continue
        if kind != "call":
            fail(f"body {va:#x}: unexpected {kind} at {v:#x}")
        fr = ROLE_OF.get(t)
        if fr is None or fr[0] != fam:
            fail(f"body {va:#x} calls {t:#x} outside its family role table")
        roles.append(fr[1])
    count, rows = STRUCTS[struct_]
    want = ["hdr_map", "hdr_seq"]
    for name, how, role, off in rows:
        if how in ("key", "optkey", "u64", "u128", "uint", "uint32"):
            want.append("str")
        want.append(role)
    if roles != want:
        fail(f"body {va:#x}: call sequence {roles} differs from the field table")
    texts = [t for _, t in rip_texts(image, insns)]
    names = [n.encode() for n, how, _, _ in rows if n]
    if texts != names:
        fail(f"body {va:#x}: name texts {texts} differ from the field table")
    flag_tests = sorted({(f["rm"][4], f.get("imm")) for _, f in insns if f["op"] == 0x80 and f["reg"] & 7 == 7
                         and f["rm"][0] == "m" and f["rm"][1] not in (None, "rip") and f["rm"][4] == FLAG_AT})
    if flag_tests != [(FLAG_AT, 0), (FLAG_AT, 1)]:
        fail(f"body {va:#x}: serializer tests {flag_tests}")
    imms = [f.get("imm") for _, f in insns]
    tags = sorted({i & M64 for i in imms if i is not None} & {OK_TAG, ERR_TAG})
    if not tags:
        fail(f"body {va:#x}: result tag constant missing")
    hdr_imm = [f["imm"] for _, f in insns if f["op"] == 0xba and f.get("imm") == count]
    if count is None:
        # computed count: the `add $0x10, %edx` base and one `movzbl d32(%rsi)` per optional tag byte
        hdr_imm = [f.get("imm") for _, f in insns if f["op"] == 0x83 and f.get("imm") == 0x10]
        tag_bytes = sorted(f["rm"][4] for _, f in insns if f["op"] == 0x0fb6 and f["rm"][0] == "m")
        if tag_bytes != sorted(off for kind, off in HEADER_TERMS if kind == "u8"):
            fail(f"body {va:#x}: header tag bytes {tag_bytes}")
    if not hdr_imm:
        fail(f"body {va:#x}: header count {count} not found as `mov $imm, %edx`")
    return {"va": va, "end": ext[va], "size": ext[va] - va, "insns": len(insns), "family": fam, "struct": struct_,
            "count": count, "calls": len(roles), "names": len(names), "tag_imm": tags[0]}


def statics_of(image, ext):
    return {va: body_row(image, ext, va) for va in sorted(BODIES)}


# ---------------------------------------------------------------- evaluation and controls
def machine(image, ext, override=None):
    m = CaseMachine(image, override)
    m.extents = ext
    return m


def evaluate(image, ext, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = machine(image, ext, override)
    results, bad = [], []
    for c in cases:
        try:
            got = run_case(m, c)
        except ToolError:
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


MODEL_MUTANTS = ("count-presence-only", "opt-byte-nonzero", "keys-when-nonzero", "map-when-one", "opt-always", "opt-when-one", "count-plus-one",
                 "swap-first-two", "str-error-three-words", "slot-error-raw", "nested-error-wrapped",
                 "continue-after-error", "u64-copy-16", "u128-pointer", "chain-id-u64", "ok-writes-all-words",
                 "keyed-key-in-body", "value-off-plus-8")


def byte_sites(image, ext):
    """Bytes whose change must be visible: header count and name-length immediates, the flag-test immediates and
    offset, and the 8-bit displacement of every `lea d8(%r14)` field address. One flip each, low bit (or 0x08 for a
    displacement, keeping alignment)."""
    sites = []
    for va in sorted(BODIES):
        insns = sweep(image, va, ext[va])
        picked = {"count": None, "name_len": None, "flag_imm": None, "flag_off": None, "field_disp": None}
        count = STRUCTS[BODIES[va][1]][0] or 0x10
        for i, (v, f) in enumerate(insns):
            raw = image.read(v, f["len"])
            if picked["count"] is None and f["op"] == 0xba and f.get("imm") == count and raw[0] == 0xba:
                picked["count"] = (v + 1, 0x01)
            elif picked["name_len"] is None and f["op"] == 0xba and raw[0] == 0xba and i and insns[i - 1][1]["op"] == 0x8d:
                picked["name_len"] = (v + 1, 0x01)
            elif f["op"] == 0x80 and f["reg"] & 7 == 7 and f["rm"][0] == "m" and f["rm"][1] not in (None, "rip"):
                if f.get("imm") == 1 and picked["flag_imm"] is None:
                    picked["flag_imm"] = (v + f["len"] - 1, 0x01)
                if f.get("imm") == 0 and picked["flag_off"] is None and raw[-2] == FLAG_AT:
                    picked["flag_off"] = (v + f["len"] - 2, 0x01)
            elif (picked["field_disp"] is None and f["op"] == 0x8d and f["rm"][0] == "m" and f["rm"][1] not in (None, "rip")
                  and f["len"] == 4 and raw[-1] == f["rm"][4] and f["rm"][4] >= 0x10):
                prev = [g for _, g in insns[max(0, i - 1):i]]
                picked["field_disp"] = (v + 3, 0x08)
        for kind in sorted(picked):
            if picked[kind] is None:
                continue
            at, x = picked[kind]
            sites.append({"body": va, "kind": kind, "at": at, "old": image.read(at, 1)[0], "xor": x})
    return sites


def controls(image, ext, cases, sites):
    rows = []
    by_body = {}
    for c in cases:
        by_body.setdefault(c["body"], []).append(c)
    for mut in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, ext, cases, frozenset([mut]), stop_on_first=True)
        rows.append({"control": f"model:{mut}", "detected": bool(bad),
                     "witness": f"{bad[0][0]['body']:#x}/{bad[0][0]['k']}/{bad[0][1]}" if bad else "-"})
    for s in sites:
        override = {s["at"]: s["old"] ^ s["xor"]}
        _, bad, _ = evaluate(image, ext, by_body[s["body"]], override=override, stop_on_first=True)
        rows.append({"control": f"byte:{s['body']:#x}:{s['kind']}:{s['at']:#x}:{s['old']:02x}^{s['xor']:02x}",
                     "detected": bool(bad),
                     "witness": f"{bad[0][0]['body']:#x}/{bad[0][0]['k']}/{bad[0][1]}" if bad else "-"})
    return rows


# ---------------------------------------------------------------- inline-Vec layer (destination call, &mut Vec<u8> serializer)
# The same destination-call struct is also serialized through a serializer that IS the Vec<u8> (cap, ptr, len at
# +0, +8, +0x10; struct-as-map flag at +0x1b). These copies write the map header byte and four of the five names
# straight into the Vec, calling the RawVec reserve helper when the spare capacity is too small.
INLINE_BODIES = {0x22f2c20: "a", 0x44da780: "b"}
INLINE_ROLES = (
    ("vec_reserve", "reserve", 0x231e050, 0x43bd910),
    ("vec_b256", "nested", 0x298bad0, 0x3d40650),
    ("vec_uint", "slot_writer", 0x25e9f10, 0x3d51450),
    ("vec_str", "rax_writer", 0x25e8bf0, 0x41c6610),
    ("vec_kf_bytes", "keyed", 0x233b960, 0x44fbb50),
)
for _r, _k, _a, _b in INLINE_ROLES:
    ROLE_KIND[_r] = _k
INLINE_ROLE = {"a": {r: a for r, _, a, _ in INLINE_ROLES}, "b": {r: b for r, _, _, b in INLINE_ROLES}}
INLINE_ROLE_OF = {va: (f, r) for f, t in INLINE_ROLE.items() for r, va in t.items()}
VFLAG_AT = 0x1b
VEC_AT = 0x7180_0000_0000
BUF_AT = 0x7200_0000_0000
BUF_SIZE = 0x400
# (name, how, offset): "inline" names are pushed as fixstr marker + bytes by the body; "str" goes through vec_str
INLINE_FIELDS = (
    ("destination_recipient", "inline", "vec_b256", 0x20),
    ("destination_chain_id", "inline", "vec_uint32", 0x50),
    ("gas_limit", "inline", "vec_uint", 0x40),
    ("nonce", "str", "vec_uint", 0x48),
    ("data", "keyed", "vec_kf_bytes", 0x0),
)


def inline_header_byte(flag, mut=frozenset()):
    """`movzbl 0x1b; xor $1; shl $4; or $0x85` on an 8-bit register: 0x85 (fixmap 5) for flag 1, 0x95 (fixarray 5)
    for flag 0, and other marker bytes for non-boolean flags (2 -> 0xb5, a fixstr marker)."""
    if "inline-header-bool" in mut:
        return 0x85 if flag else 0x95
    return ((((flag ^ 1) << 4) & 0xff) | 0x85) & 0xff


def inline_model(c, mut=frozenset()):
    """Predict reserve/callee calls, the bytes appended to the Vec, the final cap/len and the result record."""
    flag, st = c["flag"], c["st"]
    cap, ln = c["cap"], len(c["prefix"])
    out = bytearray()
    calls = []
    plan = c["plan"]

    def reserve(add):
        nonlocal cap
        calls.append(("vec_reserve", ln, add))
        cap = ln + add + c["extra"]

    def push(data):
        nonlocal ln
        out.extend(data)
        ln += len(data)

    def callee(role, args):
        k = len(calls)
        calls.append((role,) + tuple(args))
        if c["fault"] != k:
            return None
        w = plan[k]
        kind = ROLE_KIND[role]
        if kind in ("rax_writer", "slot_writer") and "inline-error-raw" not in mut:
            return (ERR_TAG, w[0], w[1])
        return (w[0], w[1], w[2])

    if cap == ln:
        reserve(1)
    push(bytes([inline_header_byte(flag, mut)]))
    keys = (flag != 0) if "keys-when-nonzero" in mut else flag == 1
    for name, how, role, off in INLINE_FIELDS:
        if keys and how == "inline":
            n = len(name)
            if cap == ln:
                reserve(1)
            push(bytes([0xa0 | n]))
            limit = n if "inline-reserve-lt" in mut else n - 1
            if cap - ln <= limit:
                reserve(n)
            push(name.encode())
        elif keys and how == "str":
            res = callee("vec_str", ("vec", name.encode()))
            if res:
                return calls, bytes(out), cap, ln, res
        if role == "vec_b256":
            res = callee(role, ("stk", ("S", off), "vec"))
        elif role == "vec_uint32":
            res = callee("vec_uint", ("stk", "vec", u(st, off, 8 if "chain-id-u64" in mut else 4)))
        elif role == "vec_uint":
            res = callee(role, ("stk", "vec", u(st, off, 8)))
        else:
            res = callee(role, ("stk", "vec", name.encode(), ("S", off)))
        if res:
            return calls, bytes(out), cap, ln, res
    return calls, bytes(out), cap, ln, (OK_TAG,)


def inline_install(m, c):
    fam = c["family"]
    m.calls = []

    def reserve(m):
        r = m.regs
        if r[7] != VEC_AT or r[1] != 1 or r[8] != 1 or r[6] != m.load(VEC_AT + 0x10, 8):
            fail("reserve called outside its contract")
        ln, add = r[6], r[2]
        if ln + add + c["extra"] > BUF_SIZE:
            fail("case output larger than the buffer region")
        m.calls.append(("vec_reserve", ln, add))
        m.store(VEC_AT, 8, ln + add + c["extra"])
        for x in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            r[x] = 0x0dead_0000 | x

    def make(role):
        kind = ROLE_KIND[role]

        def stub(m):
            r = m.regs
            k = len(m.calls)
            if kind == "rax_writer":
                rec = (role, "vec" if r[7] == VEC_AT else ("ptr", r[7]), text_at(m, r[6], r[2]))
            elif kind == "slot_writer":
                rec = (role, "stk" if STACK_TOP - 0x10000 <= r[7] < STACK_TOP else ("ptr", r[7]),
                       "vec" if r[6] == VEC_AT else ("ptr", r[6]), r[2])
            elif kind == "nested":
                rec = (role, "stk" if STACK_TOP - 0x10000 <= r[7] < STACK_TOP else ("ptr", r[7]),
                       arg_ptr(m, r[6]), "vec" if r[2] == VEC_AT else ("ptr", r[2]))
            else:
                rec = (role, "stk" if STACK_TOP - 0x10000 <= r[7] < STACK_TOP else ("ptr", r[7]),
                       "vec" if r[6] == VEC_AT else ("ptr", r[6]), text_at(m, r[2], r[1]), arg_ptr(m, r[8]))
            m.calls.append(rec)
            w = c["plan"][k] if c["fault"] == k else c["okplan"][k] if k < len(c["okplan"]) else (0xdead, 0, 0)
            if kind == "rax_writer":
                r[0], r[2] = w[0], w[1]
            else:
                if not STACK_TOP - 0x10000 <= r[7] < STACK_TOP:
                    fail("result slot is not on the stack")
                for i in range(3):
                    m.store(r[7] + 8 * i, 8, w[i])
                r[0] = r[7]
            for x in (1, 6, 7, 8, 9, 10, 11):
                r[x] = 0x0dead_0000 | x
        return stub

    for role, va in INLINE_ROLE[fam].items():
        m.stubs[va] = reserve if role == "vec_reserve" else make(role)


def inline_run(m, c):
    m.reset()
    inline_install(m, c)
    va = c["body"]
    m.lo, m.hi = va, m.extents[va]
    vec = bytearray(c["ser"])
    put(vec, 0, 8, c["cap"])
    put(vec, 8, 8, BUF_AT)
    put(vec, 0x10, 8, len(c["prefix"]))
    vreg = m.add_region(VEC_AT, 0x20, bytes(vec))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"])
    st = m.add_region(ST_AT, ST_SIZE, bytes(c["st"]))
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2] = OUT_AT, ST_AT, VEC_AT
    m.run(va, limit=20000)
    ln = m.load(VEC_AT + 0x10, 8)
    return {"calls": list(m.calls), "result": bytes(out), "vec": bytes(vreg), "st": bytes(st), "rax": m.regs[0],
            "buf": bytes(buf[:min(ln, BUF_SIZE)]), "tail": bytes(buf[min(ln, BUF_SIZE):]), "len": ln,
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100}


def inline_compare(c, want, got):
    if got is None:
        return "tool-error"
    calls, data, cap, ln, res = want
    if not got["regs_ok"] or got["rax"] != OUT_AT:
        return "machine"
    if got["st"] != bytes(c["st"]) or got["vec"][0x18:] != bytes(c["ser"][0x18:0x20]):
        return "inputs"
    if len(calls) != len(got["calls"]) or not all(match_call(w, g) for w, g in zip(calls, got["calls"])):
        return "calls"
    if got["len"] != ln or got["buf"] != c["prefix"] + data or any(got["tail"]):
        return "bytes"
    if u(got["vec"], 0, 8) != cap or u(got["vec"], 8, 8) != BUF_AT:
        return "capacity"
    expect = res[0].to_bytes(8, "little") + b"\x5a" * 0x10 if len(res) == 1 else b"".join(
        x.to_bytes(8, "little") for x in res)
    if got["result"] != expect:
        return "result"
    return None


INLINE_SLACK = tuple(range(0, 49)) + (120,)   # every spare count around the 1/9/20/21-byte reserve tests


def inline_case(stream, va, k):
    fam = INLINE_BODIES[va]
    st = bytearray(stream.take(ST_SIZE))
    ser = bytearray(stream.take(0x20))
    flag = FLAGS[k % len(FLAGS)] if k % 13 else stream.below(256)
    ser[VFLAG_AT] = flag
    prefix = stream.take(stream.below(24))
    c = {"body": va, "family": fam, "struct": "destination_call_vec", "k": k, "st": st, "ser": ser, "flag": flag,
         "prefix": prefix, "cap": len(prefix) + stream.pick(INLINE_SLACK), "extra": stream.pick((0, 0, 3, 17)),
         "fault": -1, "plan": [], "okplan": []}
    calls = inline_model(c)[0]
    n = len(calls)
    c["fault"] = k % (n + 2) if k % (n + 2) < n else -1
    for rec in calls:
        kind = ROLE_KIND[rec[0]]
        ok, bad = plan_words(stream, kind if kind != "reserve" else "slot_writer", False)
        c["okplan"].append(ok)
        c["plan"].append(bad)
    if c["fault"] >= 0 and calls[c["fault"]][0] == "vec_reserve":
        c["fault"] = -1  # reserve cannot fail (it panics / aborts instead of returning an error)
    return c


def inline_cases(per_body=PER_BODY):
    out = []
    for va in sorted(INLINE_BODIES):
        s = Stream(f"evm-tx-rmp-structs-115/inline/{va:#x}")
        for k in range(per_body):
            out.append(inline_case(s, va, k))
    return out


def inline_evaluate(image, ext, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = machine(image, ext, override)
    results, bad = [], []
    for c in cases:
        try:
            got = inline_run(m, c)
        except ToolError:
            if override is None and not mut:
                raise
            got = None
        why = inline_compare(c, inline_model(c, mut), got)
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad, m


def inline_row(image, ext, va):
    """Static check from bytes: call sequence, the header-byte recipe, every inline name (marker, length test and
    the name bytes stored by immediates/`movups` from .rodata) is visible in the body."""
    fam = INLINE_BODIES[va]
    insns = sweep(image, va, ext[va])
    roles = []
    for v, kind, t in direct_calls(image, va, ext[va]):
        if t == UNWIND_RESUME:
            continue
        fr = INLINE_ROLE_OF.get(t)
        if kind != "call" or fr is None or fr[0] != fam:
            fail(f"inline body {va:#x} calls {t:#x} outside its family")
        roles.append(fr[1])
    want = ["vec_b256", "vec_uint", "vec_uint", "vec_str", "vec_uint", "vec_kf_bytes"]
    if [r for r in roles if r != "vec_reserve"] != want or roles.count("vec_reserve") != 7:
        fail(f"inline body {va:#x}: call sequence {roles}")
    raw = image.read(va, ext[va] - va)
    for needle in (b"\x40\x80\xf5\x01", b"\x40\xc0\xe5\x04", b"\x40\x80\xcd\x85"):
        if needle not in raw:
            fail(f"inline body {va:#x}: header recipe bytes {needle.hex()} missing")
    markers = [f.get("imm") for _, f in insns if f["op"] == 0xc6 and f["rm"][0] == "m"]
    if [x for x in markers if x in (0xb5, 0xb4, 0xa9)] != [0xb5, 0xb4, 0xa9]:
        fail(f"inline body {va:#x}: fixstr markers {markers}")
    limits = [f.get("imm") for _, f in insns if f["op"] == 0x83 and f["reg"] & 7 == 7 and f["rm"][0] == "r"]
    if [x for x in limits if x in (0x14, 0x13, 0x8)] != [0x14, 0x13, 0x8]:
        fail(f"inline body {va:#x}: spare-capacity tests {limits}")
    adds = [f.get("imm") for _, f in insns if f["op"] == 0xba]
    if sorted(x for x in adds if x in (1, 0x15, 0x14, 9)) != [1, 1, 1, 1, 9, 0x14, 0x15]:
        fail(f"inline body {va:#x}: reserve sizes {adds}")
    flags = sorted({(f["rm"][4], f.get("imm")) for _, f in insns if f["op"] == 0x80 and f["rm"][0] == "m"
                    and f["rm"][1] not in (None, "rip")})
    if flags != [(VFLAG_AT, 1)]:
        fail(f"inline body {va:#x}: flag tests {flags}")
    return {"va": va, "end": ext[va], "size": ext[va] - va, "insns": len(insns), "family": fam,
            "calls": len(roles)}


INLINE_MUTANTS = ("inline-header-bool", "inline-reserve-lt", "inline-error-raw", "keys-when-nonzero",
                  "chain-id-u64")


def inline_sites(image, ext):
    sites = []
    for va in sorted(INLINE_BODIES):
        raw = image.read(va, ext[va] - va)
        for kind, needle, pos in (("header_or", b"\x40\x80\xcd\x85", 3), ("header_xor", b"\x40\x80\xf5\x01", 3),
                                  ("marker_b5", b"\xb5", 0)):
            at = raw.find(needle) + pos
            if kind == "marker_b5":
                at = raw.find(b"\xc6\x04\x30\xb5") + 3
            sites.append({"body": va, "kind": kind, "at": va + at, "old": raw[at], "xor": 0x01})
        insns = sweep(image, va, ext[va])
        for v, f in insns:
            if f["op"] == 0x83 and f["reg"] & 7 == 7 and f["rm"][0] == "r" and f.get("imm") == 0x14:
                sites.append({"body": va, "kind": "spare_test", "at": v + f["len"] - 1, "old": 0x14, "xor": 0x02})
                break
    return sites


def inline_controls(image, ext, cases, sites):
    rows = []
    for mut in INLINE_MUTANTS:
        _, bad, _ = inline_evaluate(image, ext, cases, frozenset([mut]), stop_on_first=True)
        rows.append({"control": f"inline-model:{mut}", "detected": bool(bad),
                     "witness": f"{bad[0][0]['body']:#x}/{bad[0][0]['k']}/{bad[0][1]}" if bad else "-"})
    for s in sites:
        mine = [c for c in cases if c["body"] == s["body"]]
        _, bad, _ = inline_evaluate(image, ext, mine, override={s["at"]: s["old"] ^ s["xor"]}, stop_on_first=True)
        rows.append({"control": f"inline-byte:{s['body']:#x}:{s['kind']}:{s['at']:#x}:{s['old']:02x}^{s['xor']:02x}",
                     "detected": bool(bad),
                     "witness": f"{bad[0][0]['body']:#x}/{bad[0][0]['k']}/{bad[0][1]}" if bad else "-"})
    return rows


SAMPLE_STEP = 4   # committed sample: every 4th case of each body; all cases are covered by all_cases_sha256


def hexs(b):
    return b.hex() if b else "-"


def call_text(rec):
    parts = [rec[0]]
    for a in rec[1:]:
        if isinstance(a, bytes):
            parts.append(a.decode("ascii", "replace"))
        elif isinstance(a, tuple) and a[0] in ("S",):
            parts.append(f"S+{a[1]:#x}")
        elif isinstance(a, tuple) and a[0] in ("copy", "stack"):
            parts.append("stack:" + a[1].hex())
        elif isinstance(a, int):
            parts.append(f"{a:#x}")
        else:
            parts.append(str(a))
    return " ".join(parts)


def generate(out, per_body=PER_BODY):
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        fail("node #115 digest mismatch")
    image = Image(data)
    ext = extents(image)
    statics = statics_of(image, ext)
    cases = all_cases(per_body)
    results, bad, m = evaluate(image, ext, cases)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first {c['body']:#x}/{c['k']}: {why}")
    reached = m.seen
    sites = byte_sites(image, ext)
    ctl = controls(image, ext, cases, sites)
    icases = inline_cases(per_body)
    iresults, ibad, im = inline_evaluate(image, ext, icases)
    if ibad:
        c, why = ibad[0]
        fail(f"{len(ibad)} inline mismatches; first {c['body']:#x}/{c['k']}: {why}")
    istatics = {va: inline_row(image, ext, va) for va in sorted(INLINE_BODIES)}
    reached = reached | im.seen
    ctl += inline_controls(image, ext, icases, inline_sites(image, ext))
    missed = [r["control"] for r in ctl if not r["detected"]]
    if missed:
        fail(f"undetected controls: {missed}")
    out.mkdir(parents=True, exist_ok=True)

    lines = ["body\tend\tbytes\tinstructions\treached\tfamily\tstruct\theader_count\tdirect_calls\tname_texts\tresult_tag_imm"]
    cov = ["body\tinstruction\tlength\treached"]
    for va in sorted(BODIES):
        r = statics[va]
        insns = sweep(image, va, ext[va])
        hit = sum(1 for v, _ in insns if v in reached)
        lines.append(f"{va:#x}\t{r['end']:#x}\t{r['size']}\t{r['insns']}\t{hit}\t{r['family']}\t{r['struct']}\t"
                     f"{'computed' if r['count'] is None else r['count']}\t{r['calls']}\t{r['names']}\t{r['tag_imm']:#x}")
        for v, f in insns:
            if v not in reached:
                cov.append(f"{va:#x}\t{v:#x}\t{f['len']}\t0")
    for va in sorted(INLINE_BODIES):
        r = istatics[va]
        insns = sweep(image, va, ext[va])
        hit = sum(1 for v, _ in insns if v in reached)
        lines.append(f"{va:#x}\t{r['end']:#x}\t{r['size']}\t{r['insns']}\t{hit}\t{r['family']}\tdestination_call_vec\t"
                     f"5\t{r['calls']}\t4\t{OK_TAG:#x}")
        for v, f in insns:
            if v not in reached:
                cov.append(f"{va:#x}\t{v:#x}\t{f['len']}\t0")
    (out / "bodies.tsv").write_text("\n".join(lines) + "\n")
    (out / "unreached.tsv").write_text("\n".join(cov) + "\n")

    rows = ["role\tkind\tfamily_a\tfamily_b"]
    for role, kind, a, b in ROLES:
        rows.append(f"{role}\t{kind}\t{a:#x}\t{b:#x}" if b is not None else f"{role}\t{kind}\t{a:#x}\t-")
    for role, kind, a, b in INLINE_ROLES:
        rows.append(f"{role}\t{kind}\t{a:#x}\t{b:#x}")
    (out / "roles.tsv").write_text("\n".join(rows) + "\n")

    rows = ["body\tfamily\tstruct\tindex\tname\tname_lea_site\thow\trole\tcallee\tcall_site\toffset"]
    for va in sorted(BODIES):
        fam, struct_ = BODIES[va]
        insns = sweep(image, va, ext[va])
        texts = rip_texts(image, insns)
        calls = [(v, t) for v, k, t in direct_calls(image, va, ext[va]) if t != UNWIND_RESUME]
        ti = 0
        ci = 2  # the two header calls come first
        for i, (name, how, role, off) in enumerate(STRUCTS[struct_][1]):
            tva = "-"
            if name:
                tva = f"{texts[ti][0]:#x}"
                ti += 1
            if how in ("key", "optkey", "u64", "u128", "uint", "uint32"):
                ci += 1
            site, callee = calls[ci]
            ci += 1
            if ROLE_OF[callee] != (fam, role):
                fail("field table / call order drift")
            rows.append(f"{va:#x}\t{fam}\t{struct_}\t{i}\t{name or '-'}\t{tva}\t{how}\t{role}\t{callee:#x}\t{site:#x}\t{off:#x}")
    (out / "fields.tsv").write_text("\n".join(rows) + "\n")

    rows = ["body\tcase\tflag\tfault\tword0\tcalls\tresult\tcall_list"]
    for c, got, _ in results:
        if c["k"] % SAMPLE_STEP:
            continue
        rows.append(f"{c['body']:#x}\t{c['k']}\t{c['flag']:#x}\t{c['fault']}\t{u(c['st'], 0, 8):#x}\t"
                     f"{len(got['calls'])}\t{got['result'].hex()}\t"
                     + " | ".join(call_text(r) for r in got["calls"]))
    (out / "cases-sample.tsv").write_text("\n".join(rows) + "\n")

    rows = ["body\tcase\tflag\tfault\tprefix_len\tcap\textra\tfinal_len\tfinal_cap\tresult\tappended\tcall_list"]
    for c, got, _ in iresults:
        if c["k"] % SAMPLE_STEP:
            continue
        rows.append(f"{c['body']:#x}\t{c['k']}\t{c['flag']:#x}\t{c['fault']}\t{len(c['prefix'])}\t{c['cap']}\t"
                     f"{c['extra']}\t{got['len']}\t{u(got['vec'], 0, 8)}\t{got['result'].hex()}\t"
                     f"{hexs(got['buf'][len(c['prefix']):])}\t" + " | ".join(call_text(r) for r in got["calls"]))
    (out / "inline-cases-sample.tsv").write_text("\n".join(rows) + "\n")

    rows = ["control\tdetected\twitness"]
    for r in ctl:
        rows.append(f"{r['control']}\t{'yes' if r['detected'] else 'no'}\t{r['witness']}")
    (out / "controls.tsv").write_text("\n".join(rows) + "\n")

    by = {}
    for c, got, _ in results:
        key = f"{c['body']:#x}"
        d = by.setdefault(key, {"cases": 0, "ok": 0, "error": 0, "map": 0, "seq": 0, "keys": 0})
        d["cases"] += 1
        d["ok" if got["result"][:8] == OK_TAG.to_bytes(8, "little") else "error"] += 1
        d["map" if c["flag"] else "seq"] += 1
        d["keys"] += c["flag"] == 1
    digest = hashlib.sha256()
    for c, got, _ in results:
        digest.update(f"{c['body']:#x}/{c['k']}/{got['result'].hex()}/{'|'.join(call_text(r) for r in got['calls'])}\n".encode())
    for c, got, _ in iresults:
        digest.update(f"{c['body']:#x}/{c['k']}/{got['result'].hex()}/{got['buf'].hex()}/"
                      f"{'|'.join(call_text(r) for r in got['calls'])}\n".encode())
    summary = {
        "binary_sha256": SHA256,
        "bodies": len(BODIES) + len(INLINE_BODIES),
        "body_instructions": sum(r["insns"] for r in statics.values()) + sum(r["insns"] for r in istatics.values()),
        "body_instructions_reached": sum(1 for va in list(BODIES) + list(INLINE_BODIES)
                                         for v, _ in sweep(image, va, ext[va]) if v in reached),
        "cases": len(results) + len(iresults),
        "inline_cases": len(iresults),
        "mismatches": 0,
        "controls": len(ctl),
        "controls_detected": sum(1 for r in ctl if r["detected"]),
        "model_mutants": len(MODEL_MUTANTS) + len(INLINE_MUTANTS),
        "byte_flips": len(sites) + len(inline_sites(image, ext)),
        "all_cases_sha256": digest.hexdigest(),
        "per_body": dict(sorted(by.items())),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--per-body", type=int, default=PER_BODY)
    a = ap.parse_args(argv)
    try:
        s = generate(a.out, a.per_body)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{s['cases']} cases, {s['mismatches']} mismatches, {s['controls_detected']}/{s['controls']} controls, "
          f"{s['body_instructions_reached']}/{s['body_instructions']} body instructions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
