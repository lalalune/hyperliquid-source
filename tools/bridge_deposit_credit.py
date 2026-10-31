#!/usr/bin/env python3
"""Pin the node #94 deposit credit step 0x27123d0 from ELF bytes.

After the two gates and the deposit core, a result with bit 0 set looks the user up in the per-dex tables and
one state table, marks an unseen user, adds the amount to the first dex, pushes one ledger record with the
amount over 1e6 as f64, and adds amount / 10000 to two words of a per-user row. The real bytes run under
recording stubs, a separately written rule list predicts every status, stub event and word, and reached rows
are mutated. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/bridge_deposit_credit.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
import json
import math
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x80000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 120000


class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Image:
    """Section, relocation and FDE views of one ELF byte string, through the shared parsers."""

    def __init__(self, blob):
        self.blob = blob
        self.relative_map = None
        self.sections = sections(blob)
        # SHT_NOBITS sections have no file bytes, so they never resolve an address.
        self.mapped = sorted((s for s in self.sections if s["type"] != 8 and s["address"] and s["size"]),
                             key=lambda s: s["address"])
        self.named = {s["name"]: s for s in self.sections}
        _, fdes = eh_frame_records(blob, self.sections)
        ends = {}
        for row in fdes:
            ends[row["start"]] = max(ends.get(row["start"], 0), row["end"])
        self.fde_ends = ends
        self.starts = sorted(ends)

    def offset(self, va):
        for section in self.mapped:
            if section["address"] <= va < section["address"] + section["size"]:
                return va - section["address"] + section["offset"]
        raise EvidenceError("address outside file-backed sections: %#x" % va)

    def fde(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0 or va >= self.fde_ends[self.starts[index]]:
            raise EvidenceError("address outside every FDE: %#x" % va)
        return self.starts[index], self.fde_ends[self.starts[index]]

    def exact_fde(self, va):
        start, end = self.fde(va)
        if start != va:
            raise EvidenceError("not an FDE start: %#x" % va)
        return start, end

    def text_bytes(self):
        text = self.named[".text"]
        return text["address"], bytes(self.blob[text["offset"]:text["offset"] + text["size"]])

    def relocations(self):
        """Yield (slot, type, addend, symbol index) for .rela.dyn."""
        rela = self.named[".rela.dyn"]
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            yield slot, info & 0xFFFFFFFF, addend, info >> 32

    def relative(self):
        if self.relative_map is None:
            self.relative_map = {slot: addend for slot, kind, addend, _ in self.relocations() if kind == 8}
        return self.relative_map

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/"):
            if marker in path:
                path = path[path.rindex(marker) + 1:]
                break
        return path, line, column


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


def fdiv(left, right):
    return left / right


def to_float(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & MASK[8]))[0]


def to_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {4: "shl", 5: "shr", 7: "sar"}


def decode(read, va):
    """Decode one instruction at va; read(va, n) returns n code bytes."""
    window = read(va, 16)
    pos, rex, opsize, rep, repne = 0, 0, False, False, False
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
        elif byte == 0xF2:
            repne = True
        elif byte != 0x2E:
            break
        pos += 1
    if 0x40 <= window[pos] <= 0x4F:
        rex = window[pos]
        pos += 1
    wide = bool(rex & 8)
    width = 8 if wide else (2 if opsize else 4)
    byte = window[pos]
    pos += 1
    imm = None
    rip_at = None

    def modrm(vector=False):
        nonlocal pos, rip_at
        mod_rm = window[pos]
        pos += 1
        mod, reg, rm = mod_rm >> 6, ((mod_rm >> 3) & 7) | ((rex & 4) << 1), mod_rm & 7
        if mod == 3:
            return reg, ("x" if vector else "r", rm | ((rex & 1) << 3))
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = window[pos]
            pos += 1
            scale = 1 << (sib >> 6)
            index = ((sib >> 3) & 7) | ((rex & 2) << 2)
            if index == 4:
                index = None
            base = (sib & 7) | ((rex & 1) << 3)
            if sib & 7 == 5 and mod == 0:
                base = None
                disp = struct.unpack_from("<i", window, pos)[0]
                pos += 4
                return reg, ("m", base, index, scale, disp, False)
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", window, pos)[0]
            pos += 1
        elif mod == 2 or rip:
            if rip:
                rip_at = pos
            disp = struct.unpack_from("<i", window, pos)[0]
            pos += 4
        return reg, ("m", base, index, scale, disp, rip)

    def immediate(size):
        nonlocal pos, imm
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size], window, pos)[0]
        imm = (pos, size)
        pos += size
        return value

    def finish(op, a=None, b=None, w=None, cc=None, target=None):
        size = pos
        if (width if w is None else w) == 1 and not rex:
            for operand in (a, b):
                if operand and operand[0] == "r" and 4 <= operand[1] <= 7:
                    raise EvidenceError("high byte register at %#x" % va)

        def fix(operand):
            if operand and operand[0] == "m" and operand[5]:
                return ("m", None, None, 1, va + size + operand[4], False)
            return operand
        return Insn(va, size, op, fix(a), fix(b), width if w is None else w, cc, target, imm, rip_at)

    if 0x50 <= byte <= 0x57:
        return finish("push", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if 0x58 <= byte <= 0x5F:
        return finish("pop", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if byte < 0x40 and byte & 7 < 4:
        name = GROUP1[byte >> 3]
        w = 1 if not byte & 1 else width
        reg, rm = modrm()
        if byte & 2:
            return finish(name, ("r", reg), rm, w)
        return finish(name, rm, ("r", reg), w)
    if byte < 0x40 and byte & 7 in (4, 5):
        w = 1 if byte & 7 == 4 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish(GROUP1[byte >> 3], ("r", RAX), ("i", value), w)
    if byte == 0x63 and wide:
        reg, rm = modrm()
        return finish("movsxd", ("r", reg), rm, 8)
    if 0x70 <= byte <= 0x7F:
        rel = immediate(1)
        return finish("jcc", cc=byte & 15, target=va + pos + rel)
    if byte in (0x80, 0x81, 0x83):
        reg, rm = modrm()
        w = 1 if byte == 0x80 else width
        value = immediate(4 if byte == 0x81 and w != 2 else 2 if byte == 0x81 else 1)
        return finish(GROUP1[reg & 7], rm, ("i", value), w)
    if byte in (0x84, 0x85):
        reg, rm = modrm()
        return finish("test", rm, ("r", reg), 1 if byte == 0x84 else width)
    if byte in (0x88, 0x89, 0x8A, 0x8B):
        reg, rm = modrm()
        w = 1 if not byte & 1 else width
        if byte & 2:
            return finish("mov", ("r", reg), rm, w)
        return finish("mov", rm, ("r", reg), w)
    if byte == 0x8D:
        reg, rm = modrm()
        return finish("lea", ("r", reg), rm, width)
    if byte == 0x90:
        return finish("nop")
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x98 and wide:
        return finish("cdqe")
    if byte == 0xA8:
        value = immediate(1)
        return finish("test", ("r", RAX), ("i", value), 1)
    if 0xB0 <= byte <= 0xB7:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(1)
        return finish("mov", ("r", reg), ("i", value & 0xFF), 1)
    if 0xB8 <= byte <= 0xBF:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(8 if wide else 2 if opsize else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
    if byte == 0x69:
        reg, rm = modrm()
        value = immediate(4)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0x6B:
        reg, rm = modrm()
        value = immediate(1)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0xD3:
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("r", RCX), width)
    if byte in (0xD1, 0xD0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("i", 1), 1 if byte == 0xD0 else width)
    if byte in (0xC1, 0xC0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        value = immediate(1) & 0xFF
        return finish(SHIFTS[reg & 7], rm, ("i", value), 1 if byte == 0xC0 else width)
    if byte == 0xC3:
        return finish("ret")
    if byte == 0xCC:
        return finish("int3")
    if byte in (0xC6, 0xC7):
        reg, rm = modrm()
        w = 1 if byte == 0xC6 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish("mov", rm, ("i", value & MASK[w]), w)
    if byte == 0xE8:
        rel = immediate(4)
        return finish("call", target=va + pos + rel)
    if byte == 0xE9:
        rel = immediate(4)
        return finish("jmp", target=va + pos + rel)
    if byte == 0xEB:
        rel = immediate(1)
        return finish("jmp", target=va + pos + rel)
    if byte in (0xF6, 0xF7):
        reg, rm = modrm()
        w = 1 if byte == 0xF6 else width
        kind = reg & 7
        if kind == 0:
            value = immediate(1 if w == 1 else 4)
            return finish("test", rm, ("i", value), w)
        if kind in (2, 3, 4, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 6: "div"}[kind], rm, w=w)
        raise EvidenceError("unsupported group 3 opcode at %#x" % va)
    if byte in (0xFE, 0xFF):
        reg, rm = modrm()
        kind = reg & 7
        w = 1 if byte == 0xFE else width
        if kind in (0, 1):
            return finish("inc" if kind == 0 else "dec", rm, w=w)
        if byte == 0xFF and kind == 2:
            return finish("calli", rm, w=8)
        if byte == 0xFF and kind == 4:
            return finish("jmpi", rm, w=8)
        if byte == 0xFF and kind == 6:
            return finish("pushm", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xC6 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufpd", ("x", reg), rm, 16, target=value)
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmppd", ("x", reg), rm, 16, target=value)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two == 0x13:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x70 and (opsize or repne):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else "pshuflw", ("x", reg), rm, 16, target=value)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
        if two == 0xBC and rep:
            reg, rm = modrm()
            return finish("tzcnt", ("r", reg), rm, width)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x6E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x7E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", rm, ("x", reg), 8)
        if 0x40 <= two <= 0x4F:
            reg, rm = modrm()
            return finish("cmov", ("r", reg), rm, width, cc=two & 15)
        if 0x80 <= two <= 0x8F:
            rel = immediate(4)
            return finish("jcc", cc=two & 15, target=va + pos + rel)
        if 0x90 <= two <= 0x9F:
            _, rm = modrm()
            return finish("set", rm, w=1, cc=two & 15)
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two == 0xBD:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAD:
            reg, rm = modrm()
            return finish("shrd", rm, ("r", reg), width)
        if two in (0xB6, 0xB7):
            reg, rm = modrm()
            return finish("movzx", ("r", reg), rm, width, cc=1 if two == 0xB6 else 2)
    raise EvidenceError("undecodable opcode %#x at %#x" % (byte, va))


def decode_range(image, start, end):
    """Decode [start, end) linearly; the last instruction must end exactly at end."""
    base = image.offset(start)
    code = image.blob[base:base + (end - start) + 16]

    def read(va, count):
        return code[va - start:va - start + count]

    rows = []
    va = start
    while va < end:
        row = decode(read, va)
        row.data = bytes(read(va, row.size))
        rows.append(row)
        va = row.next
    if va != end:
        raise EvidenceError("decoder overran FDE end at %#x" % end)
    return rows


class Memory:
    def __init__(self, image):
        self.image = image
        self.stack = bytearray(STACK_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.stack_base = STACK_TOP - STACK_SIZE
        self.fresh = (bytes([STACK_MARK]) * STACK_SIZE, bytes([STACK_MARK]) * HEAP_SIZE)
        self.statics = {}

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        return None, 0

    def read(self, addr, count):
        return int.from_bytes(self.bytes_at(addr, count), "little")

    def write(self, addr, count, value):
        buffer, at = self.locate(addr, count)
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + count] = (value & MASK.get(count, (1 << (8 * count)) - 1)).to_bytes(count, "little")

    def put_bytes(self, addr, data):
        buffer, at = self.locate(addr, len(data))
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + len(data)] = data

    def bytes_at(self, addr, count):
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return self.statics[addr].to_bytes(count, "little")
        try:
            offset = self.image.offset(addr)
        except EvidenceError:
            raise Halt("read outside every mapping: %#x" % addr)
        return bytes(self.image.blob[offset:offset + count])

    def copy(self, dst, src, count):
        self.put_bytes(dst, self.bytes_at(src, count))

class Machine:
    def __init__(self, image, patches=None):
        self.image = image
        self.patches = patches or {}
        self.memory = Memory(image)
        self.cache = {}
        self.calls = {}
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.steps = 0
        self.keep_rdx = False
        self.step_limit = STEP_LIMIT
        self.xmm_result = None

    def read_code(self, va, count):
        offset = self.image.offset(va)
        data = bytearray(self.image.blob[offset:offset + count])
        for index in range(count):
            if va + index in self.patches:
                data[index] = self.patches[va + index]
        return data

    def address(self, operand):
        _, base, index, scale, disp, _ = operand
        value = disp
        if base is not None:
            value += self.regs[base]
        if index is not None:
            value += self.regs[index] * scale
        return value & MASK[8]

    def get(self, operand, width):
        kind = operand[0]
        if kind == "r":
            return self.regs[operand[1]] & MASK[width]
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "r":
            reg = operand[1]
            if width >= 4:
                self.regs[reg] = value
            else:
                self.regs[reg] = (self.regs[reg] & ~MASK[width]) | value
        else:
            self.memory.write(self.address(operand), width, value)

    def condition(self, code):
        result = {
            0: self.of, 1: self.cf, 2: self.zf, 3: self.cf or self.zf, 4: self.sf,
            5: self.pf, 6: self.sf != self.of, 7: self.zf or self.sf != self.of,
        }[code >> 1]
        return bool(result) != bool(code & 1)

    def set_logic(self, result, width):
        self.cf = self.of = False
        self.zf = result & MASK[width] == 0
        self.sf = bool(result & SIGN[width])

    def add_sub(self, left, right, carry, width, subtract):
        mask = MASK[width]
        if subtract:
            result = (left - right - carry) & mask
            self.cf = left < right + carry
            self.of = bool((left ^ right) & (left ^ result) & SIGN[width])
        else:
            total = left + right + carry
            result = total & mask
            self.cf = total > mask
            self.of = bool(~(left ^ right) & (left ^ result) & SIGN[width])
        self.zf = result == 0
        self.sf = bool(result & SIGN[width])
        return result

    def push(self, value):
        self.regs[RSP] -= 8
        self.memory.write(self.regs[RSP], 8, value)

    def pop(self):
        value = self.memory.read(self.regs[RSP], 8)
        self.regs[RSP] += 8
        return value

    def stub(self, hook):
        self.keep_rdx = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        self.xmm = [POISON | POISON << 64] * 16

    def run(self, entry, args, stack=()):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack):
            self.push(value)
        self.push(RETURN_SENTINEL)
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            self.steps += 1
            pc = self.step(row)
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def step(self, row):
        op = row.op
        width = row.width
        if op == "mov":
            self.put(row.a, width, self.get(row.b, width))
        elif op == "jcc":
            return row.target if self.condition(row.cc) else row.next
        elif op == "lea":
            self.put(row.a, width, self.address(row.b))
        elif op == "push":
            self.push(self.regs[row.a[1]])
        elif op == "pop":
            self.regs[row.a[1]] = self.pop()
        elif op in ("add", "adc", "sub", "sbb", "cmp"):
            carry = int(self.cf) if op in ("adc", "sbb") else 0
            result = self.add_sub(self.get(row.a, width), self.get(row.b, width), carry, width, op not in ("add", "adc"))
            if op != "cmp":
                self.put(row.a, width, result)
        elif op in ("and", "or", "xor", "test"):
            left, right = self.get(row.a, width), self.get(row.b, width)
            result = left & right if op in ("and", "test") else left | right if op == "or" else left ^ right
            self.set_logic(result, width)
            if op != "test":
                self.put(row.a, width, result)
        elif op == "call":
            self.push(row.next)
            if row.target in self.real:
                return row.target
            hook = self.calls.get(row.target)
            if not hook:
                raise Halt("unmodelled call to %#x at %#x" % (row.target, row.va))
            self.stub(hook)
            return self.pop()
        elif op == "jmp":
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "pushm":
            self.push(self.get(row.a, 8))
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (row.b[1] & (8 * width - 1)) & 1)
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.xmm_result = None
            self.stub(hook)
            if self.xmm_result is not None:
                self.xmm[0] = self.xmm_result
        elif op == "ret":
            return self.pop()
        elif op == "movzx":
            self.put(row.a, width, self.get(row.b, row.cc))
        elif op == "set":
            self.put(row.a, 1, int(self.condition(row.cc)))
        elif op == "cmov":
            value = self.get(row.b, width)
            self.put(row.a, width, value if self.condition(row.cc) else self.get(row.a, width))
        elif op in ("inc", "dec"):
            carry = self.cf
            value = self.add_sub(self.get(row.a, width), 1, 0, width, op == "dec")
            self.cf = carry
            self.put(row.a, width, value)
        elif op == "neg":
            value = self.add_sub(0, self.get(row.a, width), 0, width, True)
            self.put(row.a, width, value)
        elif op == "not":
            self.put(row.a, width, ~self.get(row.a, width))
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            self.put(row.a, width, self.get(row.b, width) * row.target)
        elif op in ("shl", "shr", "sar"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "shl":
                result = value << count
            elif op == "shr":
                result = value >> count
            else:
                result = (value - (1 << (8 * width)) if value & SIGN[width] else value) >> count
            if count:
                self.set_logic(result, width)
            self.put(row.a, width, result)
        elif op == "movx":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.vector(row.b)
            elif row.b[0] == "x":
                self.memory.write(self.address(row.a), 16, self.xmm[row.b[1]])
            else:
                raise Halt("unmodelled vector move")
        elif op == "xorps":
            self.xmm[row.a[1]] ^= self.vector(row.b)
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd"):
            count = (row.target if op == "shld" else self.regs[RCX]) & 63
            high, low = self.get(row.a, 8), self.get(row.b, 8)
            if op == "shld":
                value = (high << count | low >> (64 - count)) if count else high
            else:
                value = (high >> count | low << (64 - count)) if count else high
            self.put(row.a, 8, value)
        elif op == "div":
            divisor = self.get(row.a, width)
            if divisor == 0:
                raise Halt("division by zero at %#x" % row.va)
            dividend = (self.regs[RDX] & MASK[width]) << (8 * width) | (self.regs[RAX] & MASK[width])
            quotient, remainder = divmod(dividend, divisor)
            if quotient > MASK[width]:
                raise Halt("division overflow at %#x" % row.va)
            self.regs[RAX], self.regs[RDX] = quotient, remainder
        elif op == "movsxd":
            value = self.get(row.b, 4)
            self.put(row.a, 8, value - (1 << 32) if value & SIGN[4] else value)
        else:
            self.step_vector(row, op)
        return row.next

    def low(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]] & MASK[8]
        return self.memory.read(self.address(operand), 8)

    def set_low(self, register, bits):
        self.xmm[register] = (self.xmm[register] & ~MASK[8]) | bits

    def step_vector(self, row, op):
        if op == "movsd":
            if row.a[0] == "x":
                if row.b[0] == "x":
                    self.set_low(row.a[1], self.low(row.b))
                else:
                    self.xmm[row.a[1]] = self.low(row.b)
            else:
                self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "movq":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "divsd":
                result = fdiv(left, right)
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "minsd":
                result = left if left < right else right
            else:
                result = left if left > right else right
            self.set_low(row.a[1], to_bits(result))
        elif op == "ucomisd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            unordered = left != left or right != right
            self.of = self.sf = False
            self.pf = unordered
            self.zf = unordered or left == right
            self.cf = unordered or left < right
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "cvtsi2sd":
            value = self.get(row.b, 8)
            self.set_low(row.a[1], to_bits(float(value - (1 << 64) if value & SIGN[8] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(byte for pair in zip(left[:8], right[:8]) for byte in pair), "little")
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = [(source >> (16 * index)) & 0xFFFF for index in range(4)]
            low = sum(words[(row.target >> (2 * index)) & 3] << (16 * index) for index in range(4))
            self.xmm[row.a[1]] = source >> 64 << 64 | low
        elif op == "pshufd":
            source = self.vector(row.b)
            words = [(source >> (32 * index)) & MASK[4] for index in range(4)]
            self.xmm[row.a[1]] = sum(words[(row.target >> (2 * index)) & 3] << (32 * index) for index in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" * size if left[at:at + size] == right[at:at + size] else bytes(size) for at in range(0, 16, size))
            self.xmm[row.a[1]] = int.from_bytes(b"".join(lanes), "little")
        elif op == "pmovmskb":
            data = self.xmm[row.b[1]].to_bytes(16, "little")
            self.put(row.a, 4, sum((byte >> 7) << index for index, byte in enumerate(data)))
        elif op == "tzcnt":
            source = self.get(row.b, row.width)
            count = (source & -source).bit_length() - 1 if source else row.width * 8
            self.cf = source == 0
            self.zf = count == 0
            self.put(row.a, row.width, count)
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "psrlq":
            value = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((value & MASK[8]) >> row.b[1]) | (((value >> 64) >> row.b[1]) << 64)
        elif op in ("addpd", "divpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                lanes.append(to_bits(one + two if op == "addpd" else fdiv(one, two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target != 5:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                if not to_float((left >> shift) & MASK[8]) < to_float((right >> shift) & MASK[8]):
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



CREDIT = 0x27123D0
NAMES = {CREDIT: "deposit_credit"}
TARGETS = (CREDIT,)
MUTATED = (CREDIT,)

SLOT_CORE = 0x5774A00
SLOT_RECORDER = 0x5773190
SLOT_LEDGER = 0x5774738
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAIL = 0x576E020
SLOT_MEMCPY = 0x576DFE0
SLOT_EXPECT = 0x576E048
HASH_USER = 0x399C7A0
ROW_OF = 0x1F849B0
FIRST_SEEN = 0x2716BC0
BALANCE_ADD = 0x36FF4F0
STATUS_DROP = 0x3379490
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_LIMIT = 0x13F
TAG_KIND = 0x37
TAG_CORE_ERROR = 0x55
STATUS_TABLE = 0x59A8D0
STATUS_TAGS = (TAG_LIMIT, TAG_KIND)
AMOUNT_LIMIT = 0x0CCCCCCCCCCCCCCC
USD_SCALE_AT = 0x20AE60
LOCATION_TOTAL = 0x56F1C50
LOCATION_ROW = 0x5715EF8
I64_MAX = (1 << 63) - 1

S_NOW = 0x60
S_LISTED = 0x36A0
S_BRIDGE = 0x3398
S_CTX = 0x3840
S_LEDGER = 0x8F3
S_ROWS = 0x740
S_DEXES_PTR = 0x5C0
S_DEXES_LEN = 0x5C8
S_CTRL, S_MASK, S_COUNT, S_HASHER = 0x318, 0x320, 0x330, 0x338
D_CTRL, D_MASK, D_COUNT, D_HASHER = 0xF8, 0x100, 0x110, 0x118
D_TOTAL = 0x238
DEX_SIZE = 0x2F0
DEX_BUCKET = 0x78
STATE_BUCKET = 0x58
R_FIRST, R_A, R_B = 0x3D, 0x10, 0x18

ARENA = HEAP_BASE + 0x1000
USED = 0x80000
ARENA_END = HEAP_BASE + 0x70000
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x300
VOTES = HEAP_BASE + 0x500
NOW = bytes(range(0xA0, 0xAC))
USER = bytes(range(0x31, 0x45))
OTHER = bytes(range(0x51, 0x65))
USD = 12345678
DIGEST = bytes(range(0x70, 0x90))
ERROR_TAIL = bytes((0x30 + index) & 0xFF for index in range(0x5E))
HASH_VALUE = (0x2B << 57) | 3
H2 = 0x2B
CAPACITY = 32


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        table = {SLOT_CORE: self.on_core, SLOT_RECORDER: self.on_recorder, SLOT_LEDGER: self.on_ledger, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_FAIL: self.on_stop, SLOT_MEMCPY: self.on_memcpy, SLOT_EXPECT: self.on_expect}
        for slot, hook in table.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        machine.calls = {HASH_USER: self.on_hash, ROW_OF: self.on_row, FIRST_SEEN: self.on_first_seen, BALANCE_ADD: self.on_balance, STATUS_DROP: self.on_nothing}
        self.events = []
        self.top = ARENA

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def data(self, at, size):
        return self.machine.memory.bytes_at(at, size)

    def write(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def put(self, at, data):
        self.machine.memory.put_bytes(at, data)

    def alloc(self, size):
        at = self.top
        self.top += (size + 15) & ~15
        if self.top > ARENA_END:
            raise Halt("fixture arena full")
        return at

    def on_nothing(self, machine):
        pass

    def on_stop(self, machine):
        raise Halt("allocation failure path")

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_memcpy(self, machine):
        self.put(machine.regs[RDI], self.data(machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = machine.regs[RDI]

    def on_expect(self, machine):
        raise Panicked("no first dex")

    def on_recorder(self, machine):
        self.events.append(("recorder", machine.regs[RSI]))

    def on_hash(self, machine):
        self.expect(machine.regs[RDI] in self.hashers, "hasher word")
        self.expect(self.data(machine.regs[RSI], 20) == self.op.user, "hashed user")
        machine.regs[RAX] = HASH_VALUE

    def on_core(self, machine):
        out, bridge, action, votes, ctx, holder = (machine.regs[reg] for reg in (RDI, RSI, RDX, RCX, R8, R9))
        top = machine.regs[RSP]
        self.expect(bridge == self.state + S_BRIDGE and action == ACTION and votes == VOTES and ctx == self.state + S_CTX, "core arguments")
        self.expect(self.read(holder) == self.state + S_LISTED, "listed set argument")
        self.expect(self.data(self.read(top), 12) == NOW, "time argument")
        self.events.append(("core",))
        self.write(out, self.op.core, 2)
        if self.op.core == TAG_OK:
            self.write(out + 2, self.op.result, 1)
        else:
            self.put(out + 2, ERROR_TAIL)

    def on_row(self, machine):
        self.expect(machine.regs[RDI] == self.state + S_ROWS, "row map")
        user = self.data(machine.regs[RSI], 20)
        if user not in self.rows:
            at = self.alloc(0x40)
            self.put(at, bytes(0x40))
            self.write(at + R_A, self.scenario.row_a)
            self.write(at + R_B, self.scenario.row_b)
            self.rows[user] = at
        machine.regs[RAX] = self.rows[user]

    def on_first_seen(self, machine):
        self.expect(machine.regs[RDI] == self.state, "first seen state")
        self.events.append(("first_seen", self.data(machine.regs[RSI], 20)))

    def on_balance(self, machine):
        self.events.append(("balance", machine.regs[RDI] == self.dexes, self.data(machine.regs[RSI], 20), machine.regs[RDX]))

    def on_ledger(self, machine):
        at, users, time_at, digest, record = (machine.regs[reg] for reg in (RDI, RSI, RDX, RCX, R8))
        self.expect(at == self.state + S_LEDGER and self.read(users) == 1 and self.read(users + 0x10) == 1, "ledger list")
        self.events.append(("ledger", self.data(self.read(users + 8), 20), self.data(time_at, 12), self.data(digest, 32), self.read(record), self.read(record + 8)))

    def table(self, kind, stride):
        """A 32-bucket table; returns the control address. Kind says where the user sits."""
        ctrl = bytearray(b"\xff" * (CAPACITY + 16))
        rows = {}
        if kind == "hit":
            ctrl[3] = H2
            rows[3] = self.op.user
        elif kind == "same_h2":
            ctrl[3] = H2
            rows[3] = OTHER
        elif kind == "same_h2_then_hit":
            ctrl[3] = ctrl[4] = H2
            rows[3], rows[4] = OTHER, self.op.user
        elif kind == "last_word_differs":
            ctrl[3] = H2
            rows[3] = self.op.user[:16] + b"\x00\x00\x00\x00"
        elif kind == "last_byte_differs":
            ctrl[3] = H2
            rows[3] = self.op.user[:19] + b"\x00"
        elif kind == "full_group_then_hit":
            for index in range(3, 19):
                ctrl[index] = 0x11
            ctrl[19] = H2
            rows[19] = self.op.user
        elif kind == "full_group_miss":
            for index in range(3, 19):
                ctrl[index] = 0x11
        elif kind != "miss":
            raise Halt("unknown table kind")
        ctrl[CAPACITY:CAPACITY + 16] = ctrl[:16]
        block = self.alloc(CAPACITY * stride + CAPACITY + 16)
        base = block + CAPACITY * stride
        self.put(block, bytes(CAPACITY * stride))
        self.put(base, bytes(ctrl))
        for index, key in rows.items():
            self.put(base - (index + 1) * stride, key)
        return base

    def fresh(self, scenario):
        memory = self.machine.memory
        memory.reset(USED)
        self.top = ARENA
        self.events = []
        self.scenario = scenario
        self.rows = {}
        self.state = HEAP_BASE + 0x70000
        memory.put_bytes(self.state, bytes(0x4000))
        self.put(self.state + S_NOW, NOW)

    def build(self, op):
        self.hashers = set()
        scenario = self.scenario
        dexes = self.dexes = self.alloc(DEX_SIZE * max(len(scenario.dexes), 1))
        self.put(dexes, bytes(DEX_SIZE * max(len(scenario.dexes), 1)))
        self.write(self.state + S_DEXES_PTR, dexes)
        self.write(self.state + S_DEXES_LEN, len(scenario.dexes))
        for index, kind in enumerate(scenario.dexes):
            at = dexes + index * DEX_SIZE
            if kind != "empty":
                self.write(at + D_COUNT, 1)
                self.write(at + D_CTRL, self.table(kind, DEX_BUCKET))
                self.write(at + D_MASK, CAPACITY - 1)
                self.hashers.add(at + D_HASHER)
            self.write(at + D_TOTAL, self.total if index == 0 else 0x4444)
        if scenario.base != "empty":
            self.write(self.state + S_COUNT, 1)
            self.write(self.state + S_CTRL, self.table(scenario.base, STATE_BUCKET))
            self.write(self.state + S_MASK, CAPACITY - 1)
            self.hashers.add(self.state + S_HASHER)

    def dump(self):
        rows = {}
        for user, at in self.rows.items():
            rows[user] = (self.read(at + R_FIRST, 1), self.read(at + R_A), self.read(at + R_B))
        total = self.read(self.dexes + D_TOTAL) if self.scenario.dexes else None
        return total, rows

    def perform(self, op):
        memory = self.machine.memory
        memory.put_bytes(OUT, bytes([0xEE]) * 0x70)
        self.events = []
        self.op = op
        self.build(op)
        self.put(ACTION, struct.pack("<Q", op.usd) + bytes(0x18) + DIGEST + bytes([op.kind]) + bytes(7) + op.user + bytes(0x10))
        self.put(VOTES, bytes(0x40))
        self.machine.run(CREDIT, {RDI: OUT, RSI: self.state, RDX: VOTES, RCX: ACTION})
        tag = self.read(OUT, 2)
        view = (tag,)
        if tag == TAG_LIMIT:
            view = (tag, self.read(OUT + 8))
        elif tag == TAG_KIND:
            view = (tag, self.read(OUT + 2, 1), self.read(OUT + 3, 1))
        elif tag == TAG_CORE_ERROR:
            view = (tag, self.data(OUT + 2, 0x5E))
        return view, tuple(self.events)

    def run(self, scenario):
        self.fresh(scenario)
        self.total = scenario.total
        trace = []
        for op in scenario.ops:
            try:
                view, events = self.perform(op)
            except Panicked as stop:
                trace.append(("panic", stop.args[0], ()))
                break
            self.total = self.read(self.dexes + D_TOTAL) if self.scenario.dexes else 0
            trace.append((view, events, self.dump()))
        return trace


class Op:
    def __init__(self, **fields):
        defaults = dict(usd=USD, user=USER, kind=0, core=TAG_OK, result=1)
        defaults.update(fields)
        self.__dict__.update(defaults)

    def __repr__(self):
        return "credit"


class Scenario:
    def __init__(self, name, ops=None, dexes=("miss",), base="miss", total=1000, row_a=7, row_b=9):
        self.name = name
        self.ops = ops or [Op()]
        self.dexes, self.base = tuple(dexes), base
        self.total, self.row_a, self.row_b = total, row_a, row_b


# ---- the rule list; it is written from the path description, never from fixture reads ----

KNOWN = ("hit", "same_h2_then_hit", "full_group_then_hit")


def add_i64(left, right):
    """Signed add; returns (sum saturated at the top, overflowed)."""
    signed = left - (1 << 64) if left >> 63 else left
    total = signed + right
    if total > I64_MAX:
        return I64_MAX, True
    return total & MASK[8], False


class Model:
    def __init__(self, scenario):
        self.scenario = scenario
        self.total = scenario.total
        self.rows = {}

    def row(self, user):
        return self.rows.setdefault(user, [0, self.scenario.row_a, self.scenario.row_b])

    def apply(self, op):
        scenario = self.scenario
        if op.usd >= AMOUNT_LIMIT:
            return (TAG_LIMIT, op.usd), ()
        if op.kind:
            return (TAG_KIND, 0, op.kind), ()
        events = [("core",)]
        if op.core != TAG_OK:
            return (TAG_CORE_ERROR, ERROR_TAIL), tuple(events)
        if not op.result & 1:
            return (TAG_OK,), tuple(events)
        known = any(kind in KNOWN for kind in scenario.dexes) or scenario.base in KNOWN
        if not known:
            self.row(op.user)[0] = 1
            events.append(("first_seen", op.user))
        if not scenario.dexes:
            raise Panicked("no first dex")
        events.append(("balance", True, op.user, op.usd))
        self.total, over = add_i64(self.total, op.usd)
        if over:
            events.append(("recorder", LOCATION_TOTAL))
        events.append(("ledger", op.user, NOW, DIGEST, 0x8000000000000001, to_bits(float(op.usd) / 1000000.0)))
        row = self.row(op.user)
        part = op.usd // 10000
        for index in (1, 2):
            row[index], over = add_i64(row[index], part)
            if over:
                events.append(("recorder", LOCATION_ROW))
        return (TAG_OK,), tuple(events)

    def snapshot(self):
        return (self.total if self.scenario.dexes else None), {user: tuple(row) for user, row in self.rows.items()}


def spec_run(scenario):
    model = Model(scenario)
    trace = []
    for op in scenario.ops:
        try:
            view, events = model.apply(op)
        except Panicked as stop:
            trace.append(("panic", stop.args[0], ()))
            break
        trace.append((view, events, model.snapshot()))
    return trace


def named_scenarios():
    limit = AMOUNT_LIMIT
    top = I64_MAX
    return [Scenario("gate_limit", [Op(usd=limit)]), Scenario("gate_limit_minus_one", [Op(usd=limit - 1)], total=0), Scenario("gate_above_limit", [Op(usd=limit + 9)]),
            Scenario("gate_kind_one", [Op(kind=1)]), Scenario("gate_kind_six", [Op(kind=6)]), Scenario("gate_kind_ff", [Op(kind=0xFF)]), Scenario("gate_limit_before_kind", [Op(usd=limit, kind=1)]),
            Scenario("core_status_copied", [Op(core=TAG_CORE_ERROR)]), Scenario("core_result_zero", [Op(result=0)]), Scenario("core_result_two_bit_clear", [Op(result=2)]), Scenario("core_result_three_bit_set", [Op(result=3)], dexes=("hit",)),
            Scenario("new_user", [Op()]), Scenario("new_user_two_dexes", [Op()], dexes=("miss", "miss")), Scenario("new_user_tables_empty", [Op()], dexes=("empty",), base="empty"),
            Scenario("known_first_dex", [Op()], dexes=("hit",)), Scenario("known_second_dex", [Op()], dexes=("miss", "hit")), Scenario("known_third_dex", [Op()], dexes=("empty", "miss", "hit")), Scenario("known_base_table", [Op()], base="hit"), Scenario("known_both", [Op()], dexes=("hit",), base="hit"),
            Scenario("probe_same_h2_other_key", [Op()], dexes=("same_h2",)), Scenario("probe_same_h2_then_key", [Op()], dexes=("same_h2_then_hit",)), Scenario("probe_full_group_then_key", [Op()], dexes=("full_group_then_hit",)), Scenario("probe_full_group_miss", [Op()], dexes=("full_group_miss",)),
            Scenario("probe_last_word_differs", [Op()], dexes=("last_word_differs",)), Scenario("probe_last_byte_differs", [Op()], dexes=("last_byte_differs",)),
            Scenario("base_same_h2_other_key", [Op()], base="same_h2"), Scenario("base_same_h2_then_key", [Op()], base="same_h2_then_hit"), Scenario("base_full_group_then_key", [Op()], base="full_group_then_hit"), Scenario("base_full_group_miss", [Op()], base="full_group_miss"),
            Scenario("base_last_word_differs", [Op()], base="last_word_differs"), Scenario("base_last_byte_differs", [Op()], base="last_byte_differs"), Scenario("base_only_with_empty_dex", [Op()], dexes=("empty",), base="hit"),
            Scenario("no_dex_new_user_panics", [Op()], dexes=()), Scenario("no_dex_known_panics", [Op()], dexes=(), base="hit"), Scenario("no_dex_result_zero_is_fine", [Op(result=0)], dexes=()),
            Scenario("total_only_first_dex", [Op()], dexes=("miss", "hit")), Scenario("total_saturates", [Op()], total=top - 5), Scenario("total_exact_top", [Op()], total=top - USD), Scenario("total_negative_word", [Op()], total=MASK[8] - 3),
            Scenario("row_saturates_a", [Op()], row_a=top - 5), Scenario("row_saturates_b", [Op()], row_b=top - 5), Scenario("row_saturates_both", [Op()], row_a=top - 5, row_b=top - 6), Scenario("row_exact_top", [Op()], row_a=top - USD // 10000, row_b=top - USD // 10000),
            Scenario("scale_below_one_unit", [Op(usd=9999)]), Scenario("scale_one_unit", [Op(usd=10000)]), Scenario("scale_zero", [Op(usd=0)]), Scenario("scale_limit", [Op(usd=limit - 1)], total=0, row_a=0, row_b=0), Scenario("two_deposits", [Op(), Op(usd=20000)], dexes=("hit",)), Scenario("two_users", [Op(), Op(user=OTHER)])]


def lcg(seed):
    value = seed
    while True:
        value = (value * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield value >> 33


def vector_scenarios(count):
    source = lcg(0x1540)
    out = []
    kinds = ("miss", "hit", "same_h2", "same_h2_then_hit", "full_group_then_hit", "full_group_miss", "last_byte_differs", "empty")
    for index in range(count):
        dexes = tuple(kinds[next(source) % 8] for _ in range(1 + next(source) % 3))
        base = kinds[next(source) % 8]
        usd = (next(source) << 25 | next(source)) % AMOUNT_LIMIT
        out.append(Scenario("vector_%d" % index, [Op(usd=usd), Op(usd=next(source) % 100000000)], dexes=dexes, base=base, total=next(source)))
    return out


def describe(trace):
    parts = []
    for step in trace:
        if step[0] == "panic":
            parts.append("panic " + step[1])
            continue
        view, events, _ = step
        marks = [event[0] for event in events if event[0] != "core"]
        parts.append("%#x" % view[0] + ("(" + "+".join(marks) + ")" if marks else ""))
    return " ".join(parts)


def check_all(harness, scenarios):
    done = []
    for scenario in scenarios:
        got = harness.run(scenario)
        want = spec_run(scenario)
        if got != want:
            for left, right, op in zip(got, want, scenario.ops):
                if left != right:
                    raise EvidenceError("scenario %s op %s differs:\n%r\n%r" % (scenario.name, op, left[:2], right[:2]))
            raise EvidenceError("scenario %s length differs" % scenario.name)
        done.append((scenario, got))
    return done


def direct_sites(image, targets):
    start, text = image.text_bytes()
    wanted = set(targets)
    hits = collections.defaultdict(list)
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text):
            target = start + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in wanted:
                hits[target].append(start + at)
    return hits


def slot_sites(image, slots):
    start, text = image.text_bytes()
    wanted = set(slots)
    hits = collections.defaultdict(list)
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text):
            slot = start + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
            if slot in wanted:
                hits[slot].append(start + at)
    # A slot can also be loaded into a register and called there; 0x5775c88 is.
    for match in re.finditer(b"[\\x48\\x4c]\\x8b[\\x05\\x0d\\x15\\x1d\\x25\\x2d\\x35\\x3d]", text):
        at = match.start()
        if at + 7 <= len(text):
            slot = start + at + 7 + struct.unpack_from("<i", text, at + 3)[0]
            if slot in wanted:
                hits[slot].append(start + at)
    return hits


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in STATUS_TAGS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 160])
        at = data.find(b"\x48\x8d\x35")
        if at >= 0 and data[at + 7] == 0xBA:
            text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
            size = struct.unpack_from("<I", data, at + 8)[0]
            rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
            continue
        at = data.find(b"\x48\x8d\x15")
        if at < 0:
            rows.append(("%#x" % tag, "%#x" % arm, "not a plain text arm"))
            continue
        piece = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        offset = image.offset(piece)
        size = image.blob[offset]
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[offset + 1:offset + 1 + size]).decode("latin1").encode("ascii", "replace").decode() + "{}"))
    return rows


def edits_for(image, rows, seen, full):
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        if full:
            at = displacement_at(row, data)
            if at is not None:
                edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def first_failure(harness, scenarios, wants):
    for scenario, want in zip(scenarios, wants):
        try:
            if harness.run(scenario) != want:
                return scenario
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error):
            return scenario
    return None


SLOT_ROWS = ((SLOT_CORE, "deposit core", 0x374E2E0), (SLOT_RECORDER, "overflow recorder", 0x358DCD0))
TWIN = 0x4D055F0


def slot_rows(image, through):
    relative = image.relative()
    rows = []
    for slot, role, target in SLOT_ROWS:
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target, len(through[slot])))
    target = relative.get(SLOT_LEDGER)
    if target is None:
        raise EvidenceError("ledger slot has no relocation")
    rows.append(("%#x" % SLOT_LEDGER, "ledger push, not run", "%#x" % target, len(through[SLOT_LEDGER])))
    return rows


def site_rows(image):
    hits = direct_sites(image, (CREDIT, TWIN))
    rows = []
    for target in (CREDIT, TWIN):
        rows.append(("%#x" % target, len(hits[target]), " ".join("%#x" % site for site in hits[target]), " ".join("%#x" % image.fde(site)[0] for site in hits[target])))
    return rows


def constant_rows(image, table):
    rows = table[CREDIT]
    limit = next(row for row in rows if row.va == 0x27123E4)
    divide = next(row for row in rows if row.va == 0x27128B8)
    shift = next(row for row in rows if row.va == 0x27128C8)
    at = image.offset(USD_SCALE_AT)
    scale = struct.unpack_from("<d", image.blob, at)[0]
    multiplier = struct.unpack_from("<Q", divide.data, 2)[0]
    if struct.unpack_from("<Q", limit.data, 2)[0] != AMOUNT_LIMIT or scale != 1000000.0 or multiplier != 0x346DC5D63886594B or shift.b != ("i", 0xB):
        raise EvidenceError("credit constants moved")
    for value in (9999, 10000, 19999, 20000, AMOUNT_LIMIT - 1, 5000000):
        if (value * multiplier >> 64) >> 11 != value // 10000:
            raise EvidenceError("multiplier is not a division by 10000")
    return [("%#x" % limit.va, limit.data.hex(), "amount limit", "%#x" % AMOUNT_LIMIT), ("%#x" % USD_SCALE_AT, bytes(image.blob[at:at + 8]).hex(), "f64 divisor of the record", "1000000.0"),
            ("%#x" % divide.va, divide.data.hex(), "multiplier, with the shift below", "%#x" % multiplier), ("%#x" % shift.va, shift.data.hex(), "shift right after mul", "floor division by 10000")]


def location_rows(image):
    relative = image.relative()
    return [("%#x" % slot, role) + image.location(slot, relative) for slot, role in ((LOCATION_TOTAL, "dex +0x238 overflow"), (LOCATION_ROW, "row +0x10 and +0x18 overflow"))]


KEY_ROWS = ((CREDIT, 0x27123F1, "amount limit", "jcc"), (CREDIT, 0x27123F9, "byte +0x40 test", "jcc"), (CREDIT, 0x2712486, "core", "calli"), (CREDIT, 0x2712496, "core status", "cmp"), (CREDIT, 0x271249E, "result bit", "test"), (CREDIT, 0x27124CE, "dex stride", "imul3"),
            (CREDIT, 0x27125D1, "dex table count", "cmp"), (CREDIT, 0x271263B, "state table count", "cmp"), (CREDIT, 0x2712736, "first seen byte", "mov"), (CREDIT, 0x2712754, "first seen call", "call"), (CREDIT, 0x2712779, "f64 of the amount", "addsd"), (CREDIT, 0x271277D, "over 1000000.0", "divsd"), (CREDIT, 0x27127E3, "balance call", "call"),
            (CREDIT, 0x27127F2, "total word", "add"), (CREDIT, 0x271288B, "ledger push", "calli"), (CREDIT, 0x27128C5, "row divide", "mul"), (CREDIT, 0x27128D3, "row +0x10", "add"), (CREDIT, 0x27128E8, "row +0x18", "add"), (CREDIT, 0x27129BD, "no first dex", "calli"))


def key_rows(image, table):
    rows = []
    for target, va, text, op in KEY_ROWS:
        row = next((item for item in table[target] if item.va == va), None)
        if row is None or row.op != op:
            raise EvidenceError("row %#x is %s" % (va, row.op if row else None))
        rows.append(("%#x" % target, "%#x" % va, row.data.hex(), op, text))
    return rows


def run_mutants(image, table, seen, scenarios):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, scenarios, [spec_run(scenario) for scenario in scenarios]) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    results = []
    wants = [spec_run(scenario) for scenario in scenarios]
    for va, kind, patch in edits_for(image, table[CREDIT], seen, True):
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        hit = first_failure(harness, scenarios, wants)
        results.append((va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else "class: tail of a copied status record, stub argument, or unread word"))
    return results


def analyse(image, mutate=True, vectors=200):
    harness = Harness(image)
    scenarios = named_scenarios()
    named = check_all(harness, scenarios)
    check_all(harness, vector_scenarios(vectors))
    seen = set(harness.machine.seen)
    table = {CREDIT: decode_range(image, *image.exact_fde(CREDIT))}
    unreached = [row.va for row in table[CREDIT] if row.va not in seen and row.op not in ("int3", "nop", "ud2")]
    through = slot_sites(image, tuple(row[0] for row in SLOT_ROWS) + (SLOT_LEDGER,))
    result = dict(table=table, named=named, scenarios=scenarios, vector_count=vectors, unreached=unreached, slots=slot_rows(image, through), sites=site_rows(image), constants=constant_rows(image, table), locations=location_rows(image), statuses=status_rows(image), keys=key_rows(image, table))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, scenarios)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("address", "size", "bytes", "operation"), [("%#x" % row.va, row.size, row.data.hex(), row.op) for row in result["table"][CREDIT]])
    tsv("unreached.tsv", ("row",), [("%#x" % va,) for va in result["unreached"]])
    tsv("slots.tsv", ("slot", "role", "relative_target", "call_sites"), result["slots"])
    tsv("call-sites.tsv", ("function", "sites", "site_list", "caller_functions"), result["sites"])
    tsv("constants.tsv", ("at", "bytes", "role", "value"), result["constants"])
    tsv("locations.tsv", ("record", "role", "path", "line", "column"), result["locations"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    tsv("scenarios.tsv", ("scenario", "operations", "outcome"), [(scenario.name, len(scenario.ops), describe(trace)) for scenario, trace in result["named"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": 1, "instructions": len(result["table"][CREDIT]), "named_scenarios": len(result["scenarios"]), "named_operations": sum(len(scenario.ops) for scenario in result["scenarios"]), "vector_scenarios": result["vector_count"], "unreached_rows": len(result["unreached"])}
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"), "survived": sum(1 for r in rows if r[2] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
