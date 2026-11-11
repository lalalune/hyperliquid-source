"""Reconstruct and verify node #115's inline-Vec rmp serializer of the EVM block header and 20 field writers.

The block header serializer 0x22da880 takes the rmp-serde serializer that IS the output `Vec<u8>` (cap, ptr, len at
+0, +8, +0x10; struct-as-map byte at +0x1b). It writes a map header (byte != 0) or an array header (byte == 0)
whose length is 16 - (word 0 == 0) + the RAW option tags, writes five names itself when the byte is exactly 1, and
then serializes 23 fields: five 32/20-byte values directly, eight through field writers that are always present,
extraData through a keyed serializer, and eight optional fields whose presence is tested with `!= 0` on a word or
`== 1` on a byte. The 13 field writers (0x2339730..0x233b700) each write their own name - inline as a fixstr marker
plus name bytes, or through the rmp str writer - but they do NOT agree on when: six test the byte with `== 1`,
seven with `!= 0`. The Option writers then test their own tag with `== 1` (a dword or a byte) and push msgpack nil
0xc0 for anything else, so a header word that is non-zero but not 1 is counted, announced and serialized as nil.
Seven more writers of the same copy family serialize transaction-body fields (authorizationList, to, to-as-Option,
blobVersionedHashes, maxFeePerBlobGas, send_to_evm_data as Option<destination call>, accessList); they run on
direct cases with the same model. accessList hands its callee the newtype name "AccessList", not the key.

The reconstruction is `model` (class `Flow`): the field table, the per-writer table, the presence/count/name rules,
the RawVec reserve rule (reserve 1 when cap == len before a marker byte, reserve n when the spare capacity is <= n-1
before an n-byte name) and the error propagation (first result word != 0x8000000000000004 returns the 3 words).
A concrete x86-64 evaluator runs the real bytes of the head and all 20 writers, with the length-header writers,
the str writer, the value serializers, the keyed extraData serializer and RawVec::reserve replaced by recording
contract stubs, and compares the ordered calls, every byte appended to the Vec, the final capacity and length,
the 24-byte result record, the callee-saved registers and the untouched inputs. The binary is never executed.
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
NIL = 0xc0                        # msgpack nil, pushed by the Option writers for None
VFLAG_AT = 0x1b                   # Vec serializer byte: != 0 map header / own names, see FLAG RULES
HEAD = 0x22da880                  # inline-Vec block header serializer
UNWIND_RESUME = 0x63f0a50

# Callees that stay outside the reconstruction. Each becomes a recording contract stub.
#   reserve     - RawVec::reserve(vec, len, additional, 1, 1): grows capacity, never returns an error
#   slot_writer - (slot, vec, count): rmp length header, Ok when slot word 0 == 2
#   rax_writer  - (vec, ptr, len) -> rax/rdx: rmp str, Ok when rax == 2
#   nested      - (slot, &value, vec): value serializer, Ok when slot word 0 == 0x8000000000000004
#   nested_sv   - (slot, vec, &value): value serializer that takes the serializer first (sequence values)
#   keyed       - (slot, vec, name, len, &value): keyed field serializer owned by another packet
STUBS = (
    ("vec_reserve", "reserve", 0x231e050),
    ("hdr_map", "slot_writer", 0x25e7540),
    ("hdr_seq", "slot_writer", 0x25e7c10),
    ("vec_str", "rax_writer", 0x25e8bf0),
    ("b256", "nested", 0x298bad0),
    ("b160", "nested", 0x298c770),
    ("u64", "nested", 0x29feb10),
    ("b64", "nested", 0x298be50),
    ("bloom", "nested", 0x298b910),
    ("u256", "nested", 0x29fe7f0),
    ("kf_bytes", "keyed", 0x233b960),
    ("auth_list", "nested_sv", 0x2262880),
    ("blob_hashes", "nested_sv", 0x2225910),
    ("u128", "nested", 0x2967e20),
    ("dest_call", "nested", 0x22f2c20),
    ("access_list", "keyed", 0x2275200),
)
ROLE_KIND = {r: k for r, k, _ in STUBS}
ROLE_VA = {r: va for r, _, va in STUBS}
ROLE_OF = {va: r for r, _, va in STUBS}

# The 20 field writers, run REAL. (key, how, flag test, value shape, value role)
#   how  inline - the writer pushes the fixstr marker and the name bytes itself
#        str    - the name and its length are arguments; the writer passes them to vec_str
#   test one    - the name is written only when byte +0x1b == 1
#        nz     - the name is written when byte +0x1b != 0
#   value tail      - tail jump role(slot, p, vec)
#         keyed_tail - tail jump role(slot, vec, NEWTYPE_NAME, len, p) (serialize_newtype_struct)
#         copy      - role(slot, &copy of the u64 at p, vec)
#         opt_dword - dword [p] == 1: role(slot, &copy of the u64 at p+8, vec); else push nil, Ok
#         opt_byte  - byte [p] == 1: tail jump role(slot, p+1, vec); else push nil, Ok
WRITERS = {
    0x2339730: ("slotNumber", "inline", "nz", "opt_dword", "u64"),
    0x23399c0: ("nonce", "inline", "one", "tail", "b64"),
    0x2339a80: ("gasUsed", "inline", "one", "copy", "u64"),
    0x2339ce0: ("number", "inline", "one", "copy", "u64"),
    0x233a150: (None, "str", "nz", "tail", "b256"),
    0x233a670: ("timestamp", "inline", "one", "copy", "u64"),
    0x233a940: ("excessBlobGas", "inline", "nz", "opt_dword", "u64"),
    0x233ad90: ("gasLimit", "inline", "one", "copy", "u64"),
    0x233ae70: ("logsBloom", "inline", "one", "tail", "bloom"),
    0x233aff0: (None, "str", "nz", "tail", "u256"),
    0x233b050: ("blobGasUsed", "inline", "nz", "opt_dword", "u64"),
    0x233b190: (None, "str", "nz", "opt_byte", "b256"),
    0x233b700: ("baseFeePerGas", "inline", "nz", "opt_dword", "u64"),
    # same copy family, transaction-body fields (not called by the block header)
    0x2339e80: ("authorizationList", "inline", "one", "tail", "auth_list"),
    0x233a300: ("to", "inline", "one", "tail", "b160"),
    0x233a3b0: ("blobVersionedHashes", "inline", "one", "tail", "blob_hashes"),
    0x233a4f0: ("maxFeePerBlobGas", "inline", "one", "tail", "u128"),
    0x233aa80: ("send_to_evm_data", "inline", "nz", "opt_qword", "dest_call"),
    0x233b510: ("to", "inline", "nz", "opt_byte", "b160"),
    0x233b630: ("accessList", "inline", "one", "keyed_tail", "access_list"),
}

# keyed_tail writers hand the callee a Rust newtype name (rodata text + length), not the msgpack key
NEWTYPE_NAME = {0x233b630: "AccessList"}

# The head's field list, in byte order. (name, how, presence, target, struct offset)
#   how   inline - head pushes the name itself (byte +0x1b == 1), then calls the nested role
#         str    - head calls vec_str(name) when byte +0x1b == 1, then the nested role
#         writer - head calls the field writer with (slot, vec, &S[off]) - name handling is inside
#         wkey   - head calls the field writer / keyed stub with (slot, vec, name, len, &S[off])
#   presence  always | qword (u64 at S[off] != 0) | byte1 (byte at S[off] == 1)
HEAD_FIELDS = (
    ("parentHash", "inline", "always", "b256", 0x60),
    ("sha3Uncles", "inline", "always", "b256", 0x80),
    ("miner", "inline", "always", "b160", 0x268),
    ("stateRoot", "str", "always", "b256", 0xa0),
    ("transactionsRoot", "str", "always", "b256", 0xc0),
    ("receiptsRoot", "wkey", "always", 0x233a150, 0xe0),
    ("", "writer", "always", 0x233ae70, 0x100),
    ("difficulty", "wkey", "always", 0x233aff0, 0x200),
    ("", "writer", "always", 0x2339ce0, 0x220),
    ("", "writer", "always", 0x233ad90, 0x228),
    ("", "writer", "always", 0x2339a80, 0x230),
    ("", "writer", "always", 0x233a670, 0x238),
    ("extraData", "wkey", "always", "kf_bytes", 0x40),
    ("mixHash", "wkey", "always", 0x233a150, 0x240),
    ("", "writer", "always", 0x23399c0, 0x260),
    ("", "writer", "qword", 0x233b700, 0x0),
    ("withdrawalsRoot", "wkey", "byte1", 0x233b190, 0x27c),
    ("", "writer", "qword", 0x233b050, 0x10),
    ("", "writer", "qword", 0x233a940, 0x20),
    ("parentBeaconBlockRoot", "wkey", "byte1", 0x233b190, 0x29d),
    ("requestsHash", "wkey", "byte1", 0x233b190, 0x2be),
    ("blockAccessListHash", "wkey", "byte1", 0x233b190, 0x2df),
    ("", "writer", "qword", 0x2339730, 0x30),
)
HEADER_TERMS = (("w0", 0x0), ("u8", 0x27c), ("lo32", 0x10), ("lo32", 0x20), ("u8", 0x29d), ("u8", 0x2be),
                ("u8", 0x2df), ("lo32", 0x30))

VEC_AT = 0x7180_0000_0000
BUF_AT = 0x7200_0000_0000
BUF_SIZE = 0x800
ST_AT = 0x7300_0000_0000
ST_SIZE = 0x300
OUT_AT = 0x7500_0000_0000
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)
STACK_LO = STACK_TOP - 0x10000


# ---------------------------------------------------------------- reconstruction
def header_count(st, mut=frozenset()):
    """Map/array length: 16 - (word 0 == 0) + the RAW option tags (bytes +0x27c/+0x29d/+0x2be/+0x2df and the low
    32 bits of words +0x10/+0x20/+0x30), wrapping at 2^32. Presence is tested differently (see HEAD_FIELDS)."""
    n = 0x10
    for kind, off in HEADER_TERMS:
        if kind == "w0":
            n -= u(st, off, 8) == 0
        elif "count-presence-only" in mut:
            n += (u(st, off, 1) == 1) if kind == "u8" else (u(st, off, 8) != 0)
        elif "count-low-byte" in mut and kind == "lo32":
            n += st[off]
        else:
            n += u(st, off, 1) if kind == "u8" else u(st, off, 4)
    if "count-plus-one" in mut:
        n += 1
    return n & 0xffffffff


class Flow:
    """Python reconstruction of one run: the Vec bytes, its capacity, the ordered calls and the result record.
    Every call that a stub answers draws its words from the case plan; `fault` names the call that fails."""

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
        """Record a stubbed call; return the words the stub leaves (slot words or rax/rdx)."""
        k = len(self.calls)
        self.calls.append((role,) + tuple(args))
        c = self.c
        if k < len(c["plan"]):
            return c["plan"][k] if c["fault"] == k else c["okplan"][k]
        return (0x0dead, 0x0dead, 0x0dead)

    def keys_on(self, test):
        flag = self.c["flag"]
        if "keys-when-nonzero" in self.mut:
            return flag != 0
        if "keys-when-one" in self.mut:
            return flag == 1
        if test == "one":
            return flag == 1
        return flag != 0

    def inline_name(self, name):
        n = len(name)
        if self.cap == self.ln and "no-marker-reserve" not in self.mut:
            self.reserve(1)
        self.push(bytes([(0xa0 | n) + (1 if "marker-plus-one" in self.mut else 0)]))
        limit = n if "reserve-lt" in self.mut else n - 1
        if self.cap - self.ln <= limit:
            self.reserve(n)
        self.push(name.encode())

    def nil(self):
        if self.cap == self.ln:
            self.reserve(1)
        self.push(bytes([NIL]))
        return (OK_TAG,)

    def str_key(self, name):
        """vec_str; returns None on Ok or the 3-word error record."""
        w = self.answer("vec_str", ("vec", name.encode()))
        if w[0] == WRITER_OK:
            return None
        if "str-error-raw" in self.mut:
            return (w[0], w[1], w[2])
        return (ERR_TAG, w[0], w[1])

    def nested(self, role, slot, arg):
        if ROLE_KIND[role] == "nested_sv" and "sv-order-swap" not in self.mut:
            w = self.answer(role, (slot, "vec", arg))
        else:
            w = self.answer(role, (slot, arg, "vec"))
        return tuple(w)

    def writer(self, va, slot, off, name=None):
        """One field writer. Returns the words it leaves in the slot: 3 words from a nested stub, (OK_TAG,) for a
        nil push or (ERR_TAG, rax, rdx) for a vec_str error."""
        key, how, test, shape, role = WRITERS[va]
        st = self.c["st"]
        if "writer-test-swap" in self.mut:
            test = "one" if test == "nz" else "nz"
        if self.keys_on(test):
            if how == "inline":
                self.inline_name(key)
            else:
                err = self.str_key(name)
                if err:
                    return err
        if shape == "tail":
            return self.nested(role, slot, ("S", off))
        if shape == "keyed_tail":  # the newtype name goes to the callee whatever the flag
            return self.keyed_stub(role, slot, NEWTYPE_NAME[va].lower() if "newtype-is-key" in self.mut
                                   else NEWTYPE_NAME[va], off)
        if shape == "copy":
            return self.nested(role, slot, ("copy", bytes(st[off:off + 8])))
        if shape == "opt_dword":
            tag = u(st, off, 8) if "opt-dword-as-qword" in self.mut else u(st, off, 4)
            present = (tag != 0) if "opt-nonzero" in self.mut else tag == 1
            if present:
                at = off + (0 if "opt-value-at-0" in self.mut else 8)
                return self.nested(role, slot, ("copy", bytes(st[at:at + 8])))
            if "none-skips-nil" in self.mut:
                return (OK_TAG,)
            return self.nil()
        if shape == "opt_qword":
            tag = u(st, off, 4) if "presence-lo32" in self.mut else u(st, off, 8)
            if (tag == 1) if "opt-qword-one" in self.mut else tag != 0:
                return self.nested(role, slot, ("S", off))
            return self.nil()
        if shape == "opt_byte":
            present = (st[off] != 0) if "opt-nonzero" in self.mut else st[off] == 1
            if present:
                return self.nested(role, slot, ("S", off + (0 if "opt-value-at-0" in self.mut else 1)))
            return self.nil()
        fail(f"unknown writer shape {shape}")

    def keyed_stub(self, role, slot, name, off):
        w = self.answer(role, (slot, "vec", name.encode(), ("S", off)))
        return tuple(w)

    def present(self, how, off):
        st = self.c["st"]
        if how == "always" or "presence-always" in self.mut:
            return True
        if how == "qword":
            return (u(st, off, 4) != 0) if "presence-lo32" in self.mut else u(st, off, 8) != 0
        return (st[off] != 0) if "presence-byte-nonzero" in self.mut else st[off] == 1

    def head(self):
        """The block header serializer 0x22da880. Returns the result record words."""
        c, mut = self.c, self.mut
        flag, st = c["flag"], c["st"]
        as_map = (flag == 1) if "map-when-one" in mut else flag != 0
        w = self.answer("hdr_map" if as_map else "hdr_seq", ("stk", "vec", header_count(st, mut)))
        if w[0] != WRITER_OK:
            return (w[0], w[1], w[2]) if "hdr-error-raw" in mut else (ERR_TAG, w[0], w[1])
        own = (flag != 0) if "keys-when-nonzero" in mut else flag == 1
        rows = list(HEAD_FIELDS)
        if "swap-first-two" in mut:
            rows[0], rows[1] = rows[1], rows[0]
        for name, how, pres, target, off in rows:
            if not self.present(pres, off):
                continue
            if how == "inline":
                if own:
                    self.inline_name(name)
                res = self.nested(target, "stk", ("S", off))
            elif how == "str":
                if own:
                    err = self.str_key(name)
                    if err:
                        return err
                res = self.nested(target, "stk", ("S", off))
            elif how == "writer":
                res = self.writer(target, "stk", off)
            elif isinstance(target, str):
                res = self.keyed_stub(target, "stk", name, off)
            else:
                res = self.writer(target, "stk", off, name)
            if res[0] != OK_TAG or "continue-after-error" in mut:
                if res[0] != OK_TAG and "continue-after-error" not in mut:
                    return res
        return (OK_TAG,)


def model(c, mut=frozenset()):
    """Predict calls, appended Vec bytes, final capacity/length and the result record of one case."""
    f = Flow(c, mut)
    if c["body"] == HEAD:
        res = f.head()
    else:
        key, how, _, _, _ = WRITERS[c["body"]]
        res = f.writer(c["body"], "out", c["off"], c.get("name"))
    if len(res) == 3 and c["body"] == HEAD and res[0] == OK_TAG:
        res = (OK_TAG,)
    return f.calls, bytes(f.out), f.cap, f.ln, res


# ---------------------------------------------------------------- evaluation
def arg_ptr(m, v):
    if ST_AT <= v < ST_AT + ST_SIZE:
        return ("S", v - ST_AT)
    if STACK_LO <= v < STACK_TOP:
        return ("stack", bytes(m.load(v + i, 1) for i in range(16)))
    return ("ptr", v)


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


def install(m, c):
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
                rec = (role, slot_of(r[7]), "vec" if r[6] == VEC_AT else ("ptr", r[6]), r[2])
            elif kind == "nested":
                rec = (role, slot_of(r[7]), arg_ptr(m, r[6]), "vec" if r[2] == VEC_AT else ("ptr", r[2]))
            elif kind == "nested_sv":
                rec = (role, slot_of(r[7]), "vec" if r[6] == VEC_AT else ("ptr", r[6]), arg_ptr(m, r[2]))
            else:
                rec = (role, slot_of(r[7]), "vec" if r[6] == VEC_AT else ("ptr", r[6]), text_at(m, r[2], r[1]),
                       arg_ptr(m, r[8]))
            m.calls.append(rec)
            if k < len(c["plan"]):
                w = c["plan"][k] if c["fault"] == k else c["okplan"][k]
            else:
                w = (0x0dead, 0x0dead, 0x0dead)
            if kind == "rax_writer":
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

    for role, va in ROLE_VA.items():
        m.stubs[va] = reserve if role == "vec_reserve" else make(role)


def run_case(m, c):
    m.reset()
    install(m, c)
    vec = bytearray(c["ser"])
    put(vec, 0, 8, c["cap"])
    put(vec, 8, 8, BUF_AT)
    put(vec, 0x10, 8, len(c["prefix"]))
    vreg = m.add_region(VEC_AT, 0x20, bytes(vec))
    buf = m.add_region(BUF_AT, BUF_SIZE, c["prefix"])
    st = m.add_region(ST_AT, ST_SIZE, bytes(c["st"]))
    out = m.add_region(OUT_AT, 0x18, b"\x5a" * 0x18)
    names = m.add_region(NAME_AT, 0x40, c.get("name", "").encode())
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    if c["body"] == HEAD:
        m.regs[7], m.regs[6], m.regs[2] = OUT_AT, ST_AT, VEC_AT
    else:
        m.regs[7], m.regs[6] = OUT_AT, VEC_AT
        name = c.get("name")
        if WRITERS[c["body"]][1] == "str":
            m.regs[2], m.regs[1], m.regs[8] = NAME_AT, len(name), ST_AT + c["off"]
        else:
            m.regs[2] = ST_AT + c["off"]
    m.run(c["body"], limit=40000)
    ln = m.load(VEC_AT + 0x10, 8)
    return {"calls": list(m.calls), "result": bytes(out), "vec": bytes(vreg), "st": bytes(st), "rax": m.regs[0],
            "buf": bytes(buf[:min(ln, BUF_SIZE)]), "tail": bytes(buf[min(ln, BUF_SIZE):]), "len": ln,
            "names": bytes(names),
            "regs_ok": [m.regs[k] for k in SAVED_REGS] == list(SAVED) and m.regs[4] == STACK_TOP - 0x100}


NAME_AT = 0x7400_0000_0000


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


def result_bytes(res):
    if len(res) == 1:
        return res[0].to_bytes(8, "little") + b"\x5a" * 0x10
    return b"".join((x & M64).to_bytes(8, "little") for x in res)


def compare(c, want, got):
    if got is None:
        return "tool-error"
    calls, data, cap, ln, res = want
    if not got["regs_ok"]:
        return "machine"
    if c["body"] == HEAD and got["rax"] != OUT_AT:
        return "machine"
    if got["st"] != bytes(c["st"]) or got["vec"][0x18:] != bytes(c["ser"][0x18:0x20]):
        return "inputs"
    if len(calls) != len(got["calls"]) or not all(match_call(w, g) for w, g in zip(calls, got["calls"])):
        return "calls"
    if got["len"] != ln or got["buf"] != c["prefix"] + data or any(got["tail"]):
        return "bytes"
    if u(got["vec"], 0, 8) != cap or u(got["vec"], 8, 8) != BUF_AT:
        return "capacity"
    if got["result"] != result_bytes(res):
        return "result"
    return None


# ---------------------------------------------------------------- cases
PER_BODY = 1000
HEAD_CASES = 8000
FLAGS = (0, 1, 1, 1, 0, 2, 0x80, 0xff, 1, 0, 1, 3)
SLACK = tuple(range(0, 40)) + (120, 400)


def plan_words(stream, kind):
    """(ok words, failing words) for one stubbed call."""
    junk = (int.from_bytes(stream.take(8), "little"), int.from_bytes(stream.take(8), "little"))
    if kind in ("rax_writer", "slot_writer", "reserve"):
        okw = WRITER_OK
        bad = stream.pick((0, 1, 3, OK_TAG, ERR_TAG, int.from_bytes(stream.take(8), "little") | 1 << 40))
    else:
        okw = OK_TAG
        bad = stream.pick((WRITER_OK, ERR_TAG, ERR_TAG | 3, ERR_TAG | 5, 0, int.from_bytes(stream.take(8), "little") | 1 << 40))
    return (okw,) + junk, (bad,) + junk


def tag_word(stream):
    return stream.pick((0, 0, 1, 1, 1, 2, 0x100000001, 1 << 32, 0xffffffff, 0x1_0000_0000_0001,
                        int.from_bytes(stream.take(8), "little")))


def tag_byte(stream):
    return stream.pick((0, 0, 1, 1, 1, 2, 0xff, stream.below(256)))


def fill_plan(stream, c):
    """Grow the per-call word plan along the fault-free path until the call list is stable, then pick the failing
    call: head cases fail on every third case (position walks the whole path), writer cases on k % (n + 2)."""
    for _ in range(200):
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
    if c["body"] == HEAD:
        c["fault"] = (k // 3) % n if k % 3 == 0 else -1
    else:
        c["fault"] = k % (n + 2) if k % (n + 2) < n else -1
    if c["fault"] >= 0 and calls[c["fault"]][0] == "vec_reserve":
        c["fault"] = -1  # reserve cannot fail (it panics / aborts instead of returning an error)
    return c


def base_case(stream, body, k):
    st = bytearray(stream.take(ST_SIZE))
    ser = bytearray(stream.take(0x20))
    flag = FLAGS[k % len(FLAGS)] if k % 13 else stream.below(256)
    ser[VFLAG_AT] = flag
    prefix = stream.take(stream.below(24))
    return {"body": body, "k": k, "st": st, "ser": ser, "flag": flag, "prefix": prefix,
            "cap": len(prefix) + stream.pick(SLACK), "extra": stream.pick((0, 0, 3, 17)),
            "fault": -1, "plan": [], "okplan": []}


def head_case(stream, k):
    c = base_case(stream, HEAD, k)
    st = c["st"]
    for kind, off in HEADER_TERMS:
        if kind == "u8":
            st[off] = tag_byte(stream)
        else:
            put(st, off, 8, tag_word(stream))
    # the Option writers read a dword tag at their pointer: for word 0 / +0x10 / +0x20 / +0x30 that is the same word
    return fill_plan(stream, c)


WRITER_OFF = 0x40


def writer_case(stream, va, k):
    c = base_case(stream, va, k)
    key, how, test, shape, role = WRITERS[va]
    c["off"] = WRITER_OFF
    if how == "str":
        c["name"] = stream.pick(("receiptsRoot", "mixHash", "difficulty", "withdrawalsRoot", "requestsHash",
                                 "parentBeaconBlockRoot", "blockAccessListHash", "x", ""))
    if shape in ("opt_dword", "opt_qword"):
        put(c["st"], WRITER_OFF, 8, tag_word(stream))
    elif shape == "opt_byte":
        c["st"][WRITER_OFF] = tag_byte(stream)
    return fill_plan(stream, c)


def all_cases(per_body=PER_BODY, head_cases=HEAD_CASES):
    out = []
    s = Stream(f"evm-block-header-vec-115/{HEAD:#x}")
    for k in range(head_cases):
        out.append(head_case(s, k))
    for va in sorted(WRITERS):
        s = Stream(f"evm-block-header-vec-115/{va:#x}")
        for k in range(per_body):
            out.append(writer_case(s, va, k))
    return out


# ---------------------------------------------------------------- static checks (from ELF bytes)
BODIES = (HEAD,) + tuple(sorted(WRITERS))


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
        elif (0x70 <= f["op"] <= 0x7f or 0x0f80 <= f["op"] <= 0x0f8f) and not va <= f["target"] < end:
            out.append((v, "jcc", f["target"]))
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


def flag_tests(insns):
    """`cmpb $imm, 0x1b(reg)`: the immediates compared against the Vec serializer byte."""
    return sorted({f.get("imm") for _, f in insns if f["op"] == 0x80 and f["reg"] & 7 == 7 and f["rm"][0] == "m"
                   and f["rm"][1] not in (None, "rip") and f["rm"][4] == VFLAG_AT})


def inline_names(image, insns):
    """Names a body stores inline: fixstr marker byte (`movb $0xa0|n`) followed by n name bytes. The bytes come
    from the immediates of the following stores (movabs / movl / movw / movb into the Vec buffer)."""
    out = []
    for i, (v, f) in enumerate(insns):
        if f["op"] == 0xc6 and f["rm"][0] == "m" and f.get("imm") is not None and 0xa1 <= f["imm"] <= 0xbf:
            out.append((v, f["imm"] & 0x1f))
    return out


def writer_row(image, ext, va):
    key, how, test, shape, role = WRITERS[va]
    insns = sweep(image, va, ext[va])
    calls = [(v, k, t) for v, k, t in direct_calls(image, va, ext[va]) if t != UNWIND_RESUME]
    roles = []
    for v, kind, t in calls:
        r = ROLE_OF.get(t)
        if r is None:
            fail(f"writer {va:#x} calls {t:#x} outside the stub table")
        roles.append((kind, r))
    want_value = ("jmp" if shape in ("tail", "keyed_tail", "opt_byte", "opt_qword") else "call", role)
    if want_value not in roles:
        fail(f"writer {va:#x}: value call {want_value} missing from {roles}")
    if ("call", "vec_str") in roles and how != "str":
        fail(f"writer {va:#x}: vec_str call but the table says {how}")
    tests = flag_tests(insns)
    if tests != [1 if test == "one" else 0]:
        fail(f"writer {va:#x}: flag tests {tests} differ from {test}")
    markers = inline_names(image, insns)
    if how == "inline":
        if [n for _, n in markers] != [len(key)]:
            fail(f"writer {va:#x}: fixstr markers {markers}")
    elif markers:
        fail(f"writer {va:#x}: unexpected inline markers {markers}")
    texts = [t for _, t in rip_texts(image, insns)]
    if shape == "keyed_tail" and texts != [NEWTYPE_NAME[va].encode()]:
        fail(f"writer {va:#x}: newtype name texts {texts}")
    nils = sum(1 for _, f in insns if f["op"] == 0xc6 and f["rm"][0] == "m" and f.get("imm") == NIL)
    if nils != (1 if shape.startswith("opt") else 0):
        fail(f"writer {va:#x}: nil pushes {nils}")
    tag_cmp = [f for _, f in insns if f["op"] in (0x83, 0x80) and f["reg"] & 7 == 7 and f["rm"][0] == "m"
               and f["rm"][4] in (0, None) and f.get("imm") == (0 if shape == "opt_qword" else 1)
               and f["rm"][1] not in (None, "rip")]
    if shape.startswith("opt") and not tag_cmp:
        fail(f"writer {va:#x}: option tag test `cmp $1, (p)` missing")
    reserves = sum(1 for _, r in roles if r == "vec_reserve")
    return {"va": va, "end": ext[va], "size": ext[va] - va, "insns": len(insns), "key": key or "(argument)",
            "how": how, "test": "==1" if test == "one" else "!=0", "shape": shape, "role": role,
            "callee": ROLE_VA[role], "reserves": reserves, "calls": len(roles)}


def head_row(image, ext):
    insns = sweep(image, HEAD, ext[HEAD])
    seq = []
    for v, kind, t in direct_calls(image, HEAD, ext[HEAD]):
        if t == UNWIND_RESUME:
            continue
        if kind != "call":
            fail(f"head: unexpected {kind} at {v:#x}")
        if t in WRITERS:
            seq.append(t)
        elif t in ROLE_OF:
            seq.append(ROLE_OF[t])
        else:
            fail(f"head calls {t:#x} outside the tables")
    calls = [s for s in seq if s != "vec_reserve"]
    want = ["hdr_map", "hdr_seq"]
    for name, how, pres, target, off in HEAD_FIELDS:
        if how == "str":
            want.append("vec_str")
        want.append(target)
    if calls != want:
        fail(f"head: call sequence {calls} differs from the field table")
    texts = [t for _, t in rip_texts(image, insns)]
    wnames = [n.encode() for n, how, _, _, _ in HEAD_FIELDS if how in ("str", "wkey")]
    if texts != wnames:
        fail(f"head: name texts {texts} differ from the field table")
    markers = [n for _, n in inline_names(image, insns)]
    if markers != [len(n) for n, how, _, _, _ in HEAD_FIELDS if how == "inline"]:
        fail(f"head: inline markers {markers}")
    if flag_tests(insns) != [0, 1]:
        fail(f"head: flag tests {flag_tests(insns)}")
    tag_bytes = sorted(f["rm"][4] for _, f in insns if f["op"] == 0x0fb6 and f["rm"][0] == "m")
    if tag_bytes != sorted(off for kind, off in HEADER_TERMS if kind == "u8"):
        fail(f"head: header tag bytes {tag_bytes}")
    if not any(f["op"] == 0x83 and f.get("imm") == 0x10 for _, f in insns):
        fail("head: header base `add $0x10` missing")
    return {"va": HEAD, "end": ext[HEAD], "size": ext[HEAD] - HEAD, "insns": len(insns),
            "calls": len(seq), "reserves": seq.count("vec_reserve"), "names": len(wnames) + len(markers)}


# ---------------------------------------------------------------- evaluation and controls
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
    "count-presence-only", "count-low-byte", "count-plus-one", "map-when-one", "keys-when-nonzero", "keys-when-one",
    "writer-test-swap", "swap-first-two", "str-error-raw", "hdr-error-raw", "continue-after-error",
    "opt-dword-as-qword", "opt-nonzero", "opt-value-at-0", "none-skips-nil", "presence-always", "presence-lo32",
    "presence-byte-nonzero", "opt-qword-one", "sv-order-swap", "newtype-is-key", "reserve-lt", "no-marker-reserve", "marker-plus-one",
)


def byte_sites(image, ext):
    """Bytes whose change must be visible. Per writer: the flag-test immediate, the fixstr marker, the spare-capacity
    test immediate, the option tag immediate. Head: the header base, the flag tests, one marker, one name length,
    one presence test immediate."""
    sites = []
    for va in BODIES:
        insns = sweep(image, va, ext[va])
        picked = {}
        for i, (v, f) in enumerate(insns):
            raw = image.read(v, f["len"])
            if f["op"] == 0x80 and f["reg"] & 7 == 7 and f["rm"][0] == "m" and f["rm"][4] == VFLAG_AT:
                picked.setdefault(f"flag_imm_{f['imm']}", (v + f["len"] - 1, 0x01))
                picked.setdefault("flag_off", (v + f["len"] - 2, 0x01))
            elif f["op"] == 0xc6 and f["rm"][0] == "m" and f.get("imm") is not None and 0xa1 <= f["imm"] <= 0xbf:
                picked.setdefault("marker", (v + f["len"] - 1, 0x01))
            elif f["op"] == 0xc6 and f["rm"][0] == "m" and f.get("imm") == NIL:
                picked.setdefault("nil", (v + f["len"] - 1, 0x01))
            elif f["op"] == 0x83 and f["reg"] & 7 == 7 and f["rm"][0] == "r" and f.get("imm", 0) > 1:
                picked.setdefault("spare_test", (v + f["len"] - 1, 0x01))
            elif (f["op"] in (0x83, 0x80) and f["reg"] & 7 == 7 and f["rm"][0] == "m" and f.get("imm") == 1
                  and f["rm"][4] != VFLAG_AT and f["rm"][1] not in (None, "rip")):
                picked.setdefault("tag_one", (v + f["len"] - 1, 0x02))
            elif f["op"] == 0x83 and f.get("imm") == 0x10 and va == HEAD:
                picked.setdefault("count_base", (v + f["len"] - 1, 0x01))
            elif f["op"] in (0xb9, 0xba) and raw[0] in (0xb9, 0xba) and i and insns[i - 1][1]["op"] == 0x8d and va == HEAD:
                picked.setdefault("name_len", (v + 1, 0x01))
        for kind in sorted(picked):
            at, x = picked[kind]
            sites.append({"body": va, "kind": kind, "at": at, "old": image.read(at, 1)[0], "xor": x})
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
        rows.append({"control": f"byte:{s['body']:#x}:{s['kind']}:{s['at']:#x}:{s['old']:02x}^{s['xor']:02x}",
                     "detected": bool(bad),
                     "witness": f"{bad[0][0]['body']:#x}/{bad[0][0]['k']}/{bad[0][1]}" if bad else "-"})
    return rows


HEAD_SAMPLE_STEP = 6     # committed sample: every 6th block header case and
WRITER_SAMPLE_STEP = 10  # every 10th direct writer case; all cases are covered by all_cases_sha256


def hexs(b):
    return b.hex() if b else "-"


def call_text(rec):
    parts = [rec[0]]
    for a in rec[1:]:
        if isinstance(a, bytes):
            parts.append(a.decode("ascii", "replace"))
        elif isinstance(a, tuple) and a[0] == "S":
            parts.append(f"S+{a[1]:#x}")
        elif isinstance(a, tuple) and a[0] in ("copy", "stack"):
            parts.append("stack:" + a[1][:8].hex())
        elif isinstance(a, int):
            parts.append(f"{a:#x}")
        else:
            parts.append(str(a))
    return " ".join(parts)


def generate(out, per_body=PER_BODY, head_cases=HEAD_CASES):
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        fail("node #115 digest mismatch")
    image = Image(data)
    ext = extents(image)
    hrow = head_row(image, ext)
    wrows = {va: writer_row(image, ext, va) for va in sorted(WRITERS)}
    cases = all_cases(per_body, head_cases)
    results, bad, m = evaluate(image, cases)
    if bad:
        c, why = bad[0]
        fail(f"{len(bad)} mismatches; first {c['body']:#x}/{c['k']}: {why}")
    reached = m.seen
    sites = byte_sites(image, ext)
    ctl = controls(image, cases, sites)
    missed = [r["control"] for r in ctl if not r["detected"]]
    if missed:
        fail(f"undetected controls: {missed}")
    out.mkdir(parents=True, exist_ok=True)

    lines = ["body\tend\tbytes\tinstructions\treached\tkey\tkey_how\tflag_test\tvalue_shape\tvalue_callee\treserve_calls"]
    cov = ["body\tinstruction\tlength\treached"]
    for va in BODIES:
        insns = sweep(image, va, ext[va])
        hit = sum(1 for v, _ in insns if v in reached)
        if va == HEAD:
            r = hrow
            lines.append(f"{va:#x}\t{r['end']:#x}\t{r['size']}\t{r['insns']}\t{hit}\t(23 fields)\thead\t==1 names, !=0 map"
                         f"\tfield table\t-\t{r['reserves']}")
        else:
            r = wrows[va]
            lines.append(f"{va:#x}\t{r['end']:#x}\t{r['size']}\t{r['insns']}\t{hit}\t{r['key']}\t{r['how']}\t{r['test']}\t"
                         f"{r['shape']}\t{r['callee']:#x}\t{r['reserves']}")
        for v, f in insns:
            if v not in reached:
                cov.append(f"{va:#x}\t{v:#x}\t{f['len']}\t0")
    (out / "bodies.tsv").write_text("\n".join(lines) + "\n")
    (out / "unreached.tsv").write_text("\n".join(cov) + "\n")

    rows = ["role\tkind\tva"]
    for role, kind, va in STUBS:
        rows.append(f"{role}\t{kind}\t{va:#x}")
    (out / "stubs.tsv").write_text("\n".join(rows) + "\n")

    rows = ["index\tname\thow\tpresence\ttarget\toffset\tname_written_when"]
    for i, (name, how, pres, target, off) in enumerate(HEAD_FIELDS):
        if isinstance(target, int):
            key, whow, test, shape, role = WRITERS[target]
            nm = name or key
            when = "flag==1" if test == "one" else "flag!=0"
            tgt = f"{target:#x}"
        else:
            nm, tgt = name, f"{ROLE_VA[target]:#x}"
            when = "flag==1" if how in ("inline", "str") else "callee"
        rows.append(f"{i}\t{nm}\t{how}\t{pres}\t{tgt}\t{off:#x}\t{when}")
    (out / "fields.tsv").write_text("\n".join(rows) + "\n")

    rows = ["body\tcase\tflag\tfault\tprefix_len\tcap\textra\tfinal_len\tfinal_cap\tresult\tappended\tcall_list"]
    for c, got, _ in results:
        if c["k"] % (HEAD_SAMPLE_STEP if c["body"] == HEAD else WRITER_SAMPLE_STEP):
            continue
        rows.append(f"{c['body']:#x}\t{c['k']}\t{c['flag']:#x}\t{c['fault']}\t{len(c['prefix'])}\t{c['cap']}\t"
                    f"{c['extra']}\t{got['len']}\t{u(got['vec'], 0, 8)}\t{got['result'].hex()}\t"
                    f"{hexs(got['buf'][len(c['prefix']):])}\t" + " | ".join(call_text(r) for r in got["calls"]))
    (out / "cases-sample.tsv").write_text("\n".join(rows) + "\n")

    rows = ["control\tdetected\twitness"]
    for r in ctl:
        rows.append(f"{r['control']}\t{'yes' if r['detected'] else 'no'}\t{r['witness']}")
    (out / "controls.tsv").write_text("\n".join(rows) + "\n")

    by = {}
    for c, got, _ in results:
        d = by.setdefault(f"{c['body']:#x}", {"cases": 0, "ok": 0, "error": 0, "flag_one": 0, "flag_other": 0,
                                              "flag_zero": 0})
        d["cases"] += 1
        d["ok" if got["result"][:8] == OK_TAG.to_bytes(8, "little") else "error"] += 1
        d["flag_one" if c["flag"] == 1 else "flag_zero" if c["flag"] == 0 else "flag_other"] += 1
    digest = hashlib.sha256()
    for c, got, _ in results:
        digest.update(f"{c['body']:#x}/{c['k']}/{got['result'].hex()}/{got['buf'].hex()}/"
                      f"{'|'.join(call_text(r) for r in got['calls'])}\n".encode())
    summary = {
        "binary_sha256": SHA256,
        "bodies": len(BODIES),
        "body_instructions": sum(len(sweep(image, va, ext[va])) for va in BODIES),
        "body_instructions_reached": sum(1 for va in BODIES for v, _ in sweep(image, va, ext[va]) if v in reached),
        "cases": len(results),
        "head_cases": sum(1 for c, _, _ in results if c["body"] == HEAD),
        "mismatches": 0,
        "controls": len(ctl),
        "controls_detected": sum(1 for r in ctl if r["detected"]),
        "model_mutants": len(MODEL_MUTANTS),
        "byte_flips": len(sites),
        "all_cases_sha256": digest.hexdigest(),
        "per_body": dict(sorted(by.items())),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--per-body", type=int, default=PER_BODY)
    ap.add_argument("--head-cases", type=int, default=HEAD_CASES)
    a = ap.parse_args(argv)
    try:
        s = generate(a.out, a.per_body, a.head_cases)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{s['cases']} cases, {s['mismatches']} mismatches, {s['controls_detected']}/{s['controls']} controls, "
          f"{s['body_instructions_reached']}/{s['body_instructions']} body instructions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
