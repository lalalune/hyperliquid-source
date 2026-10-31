#!/usr/bin/env python3
"""Pin node #94 ValidatorL1Vote and ValidatorL1Stream: variant gates, tracker rows, 49 row cap, 2/3 and 1/5 stake quorum, rate range.

0x22cdb40 is the action handler, 0x27067d0 the host that clones and applies, 0x3949140 the tracker body, 0x325e1f0 tests one row
for a voter, 0x2fe2d80 orders the action keys, 0x3946120 and 0x3941380 store a vote and read quorum, 0x33edb10 is the stake test,
0x33c0850 inserts a row, 0x21e0370 + 0x2706e40 + 0x33a7e30 store the validator rate. The real bytes run under recording stubs over
real B-tree nodes, a separately written rule list predicts every run, and every reached conditional row, immediate and field
offset is mutated. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/validator_l1_vote.py --out <dir>
"""

import argparse
import bisect
import datetime
import hashlib
import json
import multiprocessing
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
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 60000
WORKERS = 4


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
SHIFTS = {1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
        if kind in (2, 3, 4, 5, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 5: "imul1", 6: "div"}[kind], rm, w=w)
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
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movlps", rm, ("x", reg), 8)
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
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
        if two == 0xBD:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrdi", rm, ("r", reg), width, target=value)
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

    def reset(self, used=None):
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
        if not count:
            return b""
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return (self.statics[addr] & ((1 << 8 * count) - 1)).to_bytes(count, "little")
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

    def run(self, entry, args):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
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
            hook = self.calls.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            value = self.get(row.a, 8)
            product = left * (value - (1 << 64) if value & SIGN[8] else value)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
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
        elif op == "movlps":
            self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
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
        elif op in ("shld", "shrd", "shrdi"):
            bits = 8 * width
            count = (self.regs[RCX] if op == "shrd" else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
        elif op == "ror":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) if count else value)
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
                result = left / right
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
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
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


def wrap32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


HANDLER = 0x22CDB40
HOST = 0x27067D0
BODY = 0x3949140
COUNT = 0x325E1F0
KEY_CMP = 0x2FE2D80
TRACK = 0x3946120
QUORUM = 0x3941380
STAKE_TEST = 0x33EDB10
ROW_ENTRY = 0x33C0850
STREAM_WRAP = 0x21E0370
STREAM = 0x2706E40
UPSERT = 0x33A7E30
RATIO = 0x3BDE1F0
TARGETS = (HANDLER, HOST, BODY, COUNT, KEY_CMP, TRACK, QUORUM, STAKE_TEST, ROW_ENTRY, STREAM_WRAP, STREAM, UPSERT)
NAMES = {HANDLER: "handler", HOST: "host", BODY: "tracker_body", COUNT: "voted_in_row", KEY_CMP: "key_compare", TRACK: "add_vote", QUORUM: "quorum", STAKE_TEST: "stake_test", ROW_ENTRY: "row_entry",
         STREAM_WRAP: "stream_wrapper", STREAM: "stream_body", UPSERT: "stream_upsert"}
SLOT_BODY = 0x5774980
SLOT_COMPARE = 0x576E488
SLOT_COPY = 0x576DFE0
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_UNWRAP = 0x576E470
SLOT_ADD = 0x576E118
SLOT_EXPECT = 0x576E468
SLOT_TIME_ADD = 0x576E8A8
SLOT_DATE_ADD = 0x576E8B0
SLOT_ACTIVE = 0x5775128
SLOT_STAKES = 0x5775C90
SLOT_STAKE_TEST = 0x5775CC0
SLOT_RATIO = 0x5776230
SLOT_TOKEN = 0x5773D18
SLOT_PARSE = 0x57731D8
SLOT_FLOAT = 0x5773968
DROP_PAYLOAD = 0x399C180
DROP_KEY = 0x337DA10
DROP_STATUS = 0x3999770
DROP_STAKES = 0x33F0DA0
DROP_SET = 0x33F3A90
DROP_ACTION = 0x2784160
DROP_PARSE = 0x3762510
OUTER_ROW = 0x33C13C0
INNER_ROW = 0x33C0270
SET_INSERT = 0x339BFC0
CLONE_SET = 0x33E31F0
LIST_KEYS = 0x3BB6560
ITER_DROP = 0x33B1E80
LEAF_INSERT = 0x2F27570
STREAM_LEAF = 0x2F0CF20
INNER_CMP = 0x2FE28E0
CLONE_INNER = 0x27AA1E0
CLONE_OUTER = 0x23C9DF0
APPLY = 0x2387390
STATUS_TABLE = 0x59A8D0
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_UNKNOWN = 0x91
TAG_INVALID = 0x94
TAG_TOO_MANY = 0x36
TAG_LENGTH = 0x143
TAG_INPUT = 0x140
TAG_FLOAT = 0xAB
CAP = 49
TTL = 604800
STRONG = 2.0 / 3.0
WEAK = 0.2
BASE_WORD = 0x800000000000000A
INNER_ALLOWED = 0x37C
TOP = MASK[8]

E_TIME = 0x60
E_CHAIN = 0x8F2
E_S = 0x8F8
E_VALIDATORS = 0x908
E_STREAM = 0x3268
E_TRACKER = 0x3678
E_SIZE = 0x3B00
S_ALLOWED = 0x120
S_PROFILES = 0x150
S_ALLOW_ALL = 0x290
T_GUARD = 0
T_ROWS = 0x10
T_HVS = 0x28
T_HC = 0x40
T_ACTIVE = 0x50
R_NAME = 0
R_HC = 0x18
R_BUCKETS = 0x28
R_STAKES = 0x40
R_RATIO = 0x58
R_EXPIRE = 0x60
R_DONE = 0x6C
P_SIGNER = 0x40
ROW_SIZE = 0x70
KEY_SIZE = 0x80
OUT_SIZE = 0x70

OUT = HEAP_BASE + 0x200
ACTION = HEAP_BASE + 0x300
CALLER = HEAP_BASE + 0x400
PAIR = HEAP_BASE + 0x440
COUNT_ROW = HEAP_BASE + 0x480
STATE = HEAP_BASE + 0x1000
NODES = HEAP_BASE + 0x5000
ARENA = HEAP_BASE + 0x70000
USED = 0x7C000
FILL = 0xCC
BASE_DATE = (2026 << 13) | (304 << 4) | 5


class Layout:
    def __init__(self, key_size, val_size, val_at, key_at, len_at, edge_at, parent_at, slot_at):
        self.key_size, self.val_size, self.val_at, self.key_at = key_size, val_size, val_at, key_at
        self.len_at, self.edge_at, self.parent_at, self.slot_at = len_at, edge_at, parent_at, slot_at
        self.size = edge_at + 12 * 8


ADDRESS_SET = Layout(20, 0, 0xE8, 8, 0xE6, 0xE8, 0, 0xE4)
STAKE_MAP = Layout(20, 8, 8, 0x60, 0x13E, 0x140, 0, 0x13C)
VALIDATOR_MAP = Layout(20, 0x10, 0, 0xB8, 0x196, 0x198, 0xB0, 0x194)
PROFILE_MAP = Layout(20, 0x58, 0, 0x3D0, 0x4AE, 0x4B0, 0x3C8, 0x4AC)
ROW_TREE = Layout(KEY_SIZE, ROW_SIZE, 0x580, 0, 0xA5A, 0xA60, 0xA50, 0xA58)
OUTER_MAP = Layout(0, 0x20, 0, 0, 0x16A, 0x170, 0x160, 0x168)
INNER_MAP = Layout(0, 0x30, 0, 0, 0x21A, 0x220, 0x210, 0x218)
STREAM_MAP = Layout(20, 0x18, 8, 0x110, 0x1EE, 0x1F0, 0, 0x1EC)
PATTERN = bytes((index * 7 + 0x40) & 0xFF for index in range(0x60))


def address_of(index):
    if index >= 200:
        return bytes([0x30 + (at & 3) for at in range(19)]) + bytes([index - 200])
    return bytes([0x20 + index]) + bytes((0xA0 + index + at * 5) & 0xFF for at in range(19))


def address_index(key):
    index = key[0] - 0x20
    if address_of(index) != key:
        raise Halt("address bytes")
    return index


def pack_time(value):
    return struct.pack("<iII", *value)


def date_of(year, ordinal, flags=5):
    return (year << 13) | (ordinal << 4) | flags


def day_number(date):
    return datetime.date(date >> 13, 1, 1).toordinal() + ((date >> 4) & 0x1FF) - 1


def date_at(number):
    day = datetime.date.fromordinal(number)
    return date_of(day.year, day.timetuple().tm_yday)


T0 = (BASE_DATE, 3600, 9)


def later(value, seconds):
    return (value[0], value[1] + seconds, value[2])


def rhs_rejected(rhs):
    """The body compares rhs + 0xffff574000000000 with 0xfffeae7ffffeae81: days outside the i32 range panic."""
    return ((rhs + 0xFFFF574000000000) & TOP) < 0xFFFEAE7FFFFEAE81


class Pay:
    """One ValidatorL1VoteAction value as the wire would give it."""

    def __init__(self, k, text=b"", addr=1, flag=0, number=0, addrs=(1, 2, 3, 4), inner=None, body=0):
        self.k, self.text, self.addr, self.flag, self.number, self.addrs, self.inner, self.body = k, text, addr, flag, number, addrs, inner, body

    def word(self):
        return self.inner if self.k == 6 else BASE_WORD + self.k

    def key(self):
        k = self.k
        if k == 0:
            return (0, self.text)
        if k == 1:
            return (1, address_of(self.addr), self.flag)
        if k == 2:
            return (2, self.text, address_of(self.addr))
        if k in (3, 5):
            return (k, self.text, self.flag)
        if k == 4:
            return (4, self.number, self.flag)
        if k == 7:
            return (7, self.number) + tuple(address_of(index) for index in self.addrs)
        return (6, self.inner, self.body)


class Op:
    def __init__(self, caller, pay=None, apply=TAG_OK, stakes=None, active=None, token=TAG_OK, text=b"", parse=TAG_OK, number=0.5, float_ok=True, kind="vote", pair=(True, True), row=0, tracker_active=None, hvs=None, now=None):
        self.caller, self.pay, self.apply, self.stakes, self.active, self.token = caller, pay, apply, stakes, active, token
        self.text, self.parse, self.number, self.float_ok, self.kind, self.pair, self.row = text, parse, number, float_ok, kind, pair, row
        self.tracker_active, self.hvs, self.now = tracker_active, hvs, now


class Case:
    FIELDS = dict(chain=3, enabled=True, allow_all=False, allowed=(1, 2, 3, 4, 5), profiles=None, active=None, stakes=((1, 100), (2, 100), (3, 100)), hvs=(), hc=(0.0, 0.0), rows=(), ops=(), validators=(1, 2, 3), stream=(), now=T0, rhs=0, date_fail=False,
                  caller_junk=0)

    def __init__(self, name, kind, **fields):
        self.name = name
        self.kind = kind
        for key, value in self.FIELDS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.FIELDS:
                raise EvidenceError("field " + key)
            setattr(self, key, value)
        if self.profiles is None:
            self.profiles = tuple((index, index + 16) for index in self.allowed)
        if self.active is None:
            self.active = tuple((index + 16, 1) for index in self.allowed)


class Panic(Exception):
    pass


def seed(pay, stakes=((1, 100), (2, 100), (3, 100)), voters=(), listed=(), fin=None, ratio=STRONG, expire=None, done=0, hc=(0.0, 0.0)):
    return dict(pay=pay, stakes=dict(stakes), voters=set(voters), listed=set(listed), fin=fin, ratio=ratio, expire=expire or later(T0, 1000), done=done, hc=hc)


class Spec:
    """Rule list written apart from the bytes: predicts status, flag, stub events and the full tracker state."""

    def __init__(self, case):
        self.case = case
        self.rows = {}
        for row in case.rows:
            copy = dict(row)
            copy["voters"], copy["listed"] = set(row["voters"]), set(row["listed"])
            self.rows[row["pay"].key()] = copy
        self.stream = {}
        for index, bits, time in case.stream:
            self.stream[index] = (bits, time)
        self.stakes = dict(case.stakes)
        self.active = dict(case.active)
        self.enabled = case.enabled
        self.hvs = set(case.hvs)
        self.now = case.now
        self.events = []

    def quorum(self, row):
        voted = 0
        for index in row["voters"]:
            if index in row["stakes"]:
                voted += row["stakes"][index]
                if voted > TOP:
                    raise Panic("add_overflow")
        total = 0
        for value in row["stakes"].values():
            total += value
            if total > TOP:
                raise Panic("add_overflow")
        ratio = float(voted) > float(total) * row["ratio"]
        q = row["hc"][0]
        hits = len(row["listed"] & self.hvs)
        if q == 0.0:
            listed = True
        else:
            listed = float(hits) > q * float(len(self.hvs))
        return ratio and listed

    def add_vote(self, row, caller):
        finished = False
        for kind in (0, 1):
            member = caller in row["stakes"] if kind == 0 else caller in self.hvs
            if not member:
                continue
            if row["fin"] is None:
                row["fin"] = 0x100
            before = (row["fin"] & 0xFF) != 0 or self.quorum(row)
            (row["voters"] if kind == 0 else row["listed"]).add(caller)
            if before:
                continue
            if self.quorum(row):
                row["fin"] = 1
                finished = True
        return finished

    def expire(self):
        date, seconds, frac = self.now
        total = seconds + TTL
        days, kept = divmod(total, 86400)
        rhs = days * 86400 + self.case.rhs
        if rhs_rejected(rhs):
            raise Panic("date_overflow")
        whole = abs(rhs) // 86400
        self.events.append(("date_add",))
        if self.case.date_fail:
            raise Panic("date_overflow")
        return (date_at(day_number(date) + (whole if rhs >= 0 else -whole)), kept, frac)

    def body(self, op):
        """Returns (status, flag)."""
        case = self.case
        caller = op.caller
        if not case.allow_all and caller not in case.allowed:
            self.events.append(("drop_payload",))
            return TAG_INVALID, 0
        if not self.enabled:
            self.events.append(("drop_payload",))
            return TAG_INVALID, 0
        if sum(1 for row in self.rows.values() if caller in row["voters"] or caller in row["listed"]) > CAP:
            self.events.append(("drop_payload",))
            return TAG_TOO_MANY, 0
        key = op.pay.key()
        row = self.rows.get(key)
        if row is None:
            self.events.append(("active", case.chain))
            profile = dict(case.profiles).get(caller)
            failed = None
            if profile is None:
                failed = TAG_UNKNOWN
            else:
                self.events.append(("drop_status", TAG_UNKNOWN))
                if profile not in self.active:
                    failed = TAG_INVALID
            if failed is not None:
                self.events.append(("drop_stakes",))
                self.events.append(("drop_payload",))
                return failed, 0
            expire = self.expire()
            self.events.append(("stakes", case.chain))
            self.events.append(("alloc", 15))
            self.events.append(("drop_stakes",))
            row = dict(pay=op.pay, stakes=dict(self.stakes), voters=set(), listed=set(), fin=None, ratio=WEAK if op.pay.k == 6 else STRONG, expire=expire, done=0, hc=case.hc)
            self.rows[key] = row
        else:
            self.events.append(("drop_key",))
            if caller not in row["stakes"]:
                return TAG_INVALID, 0
        finished = self.add_vote(row, caller)
        if finished:
            row["done"] = 1
        return TAG_OK, int(finished)

    def vote(self, op):
        pay = op.pay
        k = pay.k
        size = len(pay.text)
        if k in (0, 3, 5):
            if size > 100:
                return ("err", TAG_LENGTH, False)
            if size > 20:
                return ("err", TAG_INPUT, False)
        if k == 2:
            self.events.append(("token",))
            if op.token != TAG_OK:
                return ("err", op.token, True)
        if k == 6:
            word = pay.inner
            inner = (word ^ (1 << 63)) if word >> 63 else 3
            if inner > 63 or not INNER_ALLOWED >> inner & 1:
                return ("err", TAG_INPUT, False)
            self.events.append(("clone_outer",))
            self.events.append(("clone_inner",))
        status, flag = self.body(op)
        if status != TAG_OK:
            self.events.append(("drop_action",))
            return ("err", status, False)
        if not flag:
            self.events.append(("drop_action",))
            return ("ok", 0)
        if k == 6:
            self.events.append(("clone_inner",))
        self.events.append(("apply", k))
        self.events.append(("drop_action",))
        if op.apply != TAG_OK:
            return ("err", op.apply, True)
        return ("ok", 1)

    def rate(self, op):
        case = self.case
        size = len(op.text)
        result = None
        if op.caller not in case.validators:
            result = ("err", TAG_UNKNOWN, False)
        elif size > 100:
            result = ("err", TAG_LENGTH, False)
        else:
            self.events.append(("parse",))
            if op.parse != TAG_OK:
                result = ("err", op.parse, True)
            else:
                self.events.append(("to_float",))
                if not op.float_ok:
                    result = ("err", TAG_FLOAT, False)
                else:
                    self.events.append(("drop_parse",))
                    value = op.number
                    bits = to_bits(value)
                    absolute = bits & ~(1 << 63)
                    if value != value or absolute == 0x7FF << 52 or (bits >> 63 and absolute != 0) or value > 1.0:
                        result = ("err", TAG_INPUT, False)
                    else:
                        self.stream[op.caller] = (bits, self.now)
                        result = ("ok", 0)
        if size:
            self.events.append(("free", size))
        return result

    def count(self, op):
        row = self.case.rows[op.row]
        first, second = op.pair
        if first and op.caller in row["voters"] and row["fin"] is not None:
            return 1
        if second and op.caller in row["listed"] and row["fin"] is not None:
            return 1
        return 0

    def step(self, op):
        if op.stakes is not None:
            self.stakes = dict(op.stakes)
        if op.active is not None:
            self.active = dict(op.active)
        if op.tracker_active is not None:
            self.enabled = op.tracker_active
        if op.hvs is not None:
            self.hvs = set(op.hvs)
        if op.now is not None:
            self.now = op.now
        if op.kind == "stream":
            return self.rate(op)
        if op.kind == "count":
            return ("value", self.count(op))
        return self.vote(op)

    def state(self, frozen):
        rows = []
        for key in sorted(self.rows):
            row = self.rows[key]
            rows.append((key, row["hc"], tuple(sorted(row["voters"])) if row["fin"] is not None else None, tuple(sorted(row["listed"])) if row["fin"] is not None else None, row["fin"],
                         tuple(sorted(row["stakes"].items())), to_bits(row["ratio"]), row["expire"], row["done"]))
        return tuple(rows), tuple(sorted(self.stream.items())), frozen


def spec_run(case, frozen):
    spec = Spec(case)
    results = []
    try:
        for op in case.ops:
            results.append(spec.step(op))
    except Panic as stop:
        return "panic", stop.args[0], tuple(results), tuple(spec.events)
    return "done", tuple(results), tuple(spec.events), spec.state(frozen)


def capacity(height):
    return 7 if height == 0 else 4 * capacity(height - 1) + 3


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((HOST, BODY, COUNT, KEY_CMP, TRACK, QUORUM, STAKE_TEST, RATIO, ROW_ENTRY, STREAM, UPSERT))
        statics = machine.memory.statics
        hooks = {SLOT_COMPARE: self.on_compare, SLOT_COPY: self.on_copy, SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_ALLOC_FAIL: self.on_stop, SLOT_UNWRAP: self.on_stop, SLOT_ADD: self.on_add, SLOT_EXPECT: self.on_expect,
                 SLOT_TIME_ADD: self.on_time_add, SLOT_DATE_ADD: self.on_date_add, SLOT_ACTIVE: self.on_active, SLOT_STAKES: self.on_stakes, SLOT_TOKEN: self.on_token, SLOT_PARSE: self.on_parse, SLOT_FLOAT: self.on_float}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        statics[SLOT_BODY] = BODY
        statics[SLOT_STAKE_TEST] = STAKE_TEST
        statics[SLOT_RATIO] = RATIO
        machine.calls = {DROP_PAYLOAD: self.on_drop_payload, DROP_KEY: self.on_drop_key, DROP_STATUS: self.on_drop_status, DROP_STAKES: self.on_drop_stakes, DROP_SET: self.on_nothing, DROP_ACTION: self.on_drop_action, DROP_PARSE: self.on_drop_parse,
                         OUTER_ROW: self.on_outer, INNER_ROW: self.on_inner, SET_INSERT: self.on_set_insert, CLONE_SET: self.on_clone_set, LIST_KEYS: self.on_list_keys, ITER_DROP: self.on_iter_drop, LEAF_INSERT: self.on_leaf, STREAM_LEAF: self.on_stream_leaf,
                         INNER_CMP: self.on_inner_cmp, CLONE_INNER: self.on_clone_inner, CLONE_OUTER: self.on_clone_outer, APPLY: self.on_apply}
        self.events = []
        self.case = None
        self.op = None
        self.stakes = {}
        self.active = {}
        self.next_node = NODES
        self.arena = ARENA
        self.frozen_digest = None

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def on_compare(self, machine):
        regs = machine.regs
        size = regs[RDX]
        self.expect(size <= 0x200, "compare length")
        left, right = self.bytes_at(regs[RDI], size), self.bytes_at(regs[RSI], size)
        result = 0 if left == right else 0x1234 if left > right else -0x1234
        regs[RAX] = (0x5A5A5A5A << 32) | result & MASK[4]

    def on_copy(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] <= 0x400, "copy length")
        if regs[RDX]:
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def allocate(self, size):
        at = self.arena
        self.arena += (size + 15) & ~15
        self.expect(self.arena < HEAP_BASE + USED, "arena")
        self.machine.memory.put_bytes(at, bytes([FILL]) * size)
        return at

    def on_alloc(self, machine):
        if machine.regs[RDI] in (14, 15):
            self.events.append(("alloc", machine.regs[RDI]))
        machine.regs[RAX] = self.allocate(machine.regs[RDI])

    def on_free(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] & MASK[4] == 0 and regs[RSI] and regs[RDI] >= ARENA, "free size")
        self.events.append(("free", regs[RSI]))

    def on_stop(self, machine):
        raise Panicked("unwrap")

    def on_add(self, machine):
        raise Panicked("add_overflow")

    def on_expect(self, machine):
        self.expect(machine.regs[RSI] == 0x26, "panic text size")
        self.expect(self.bytes_at(machine.regs[RDI], 0x26) == b"`NaiveDateTime + TimeDelta` overflowed", "panic text")
        raise Panicked("date_overflow")

    def on_time_add(self, machine):
        regs = machine.regs
        seconds, frac = self.read(regs[RSI], 4), self.read(regs[RSI] + 4, 4)
        self.expect(regs[RDX] == TTL and regs[RCX] & MASK[4] == 0, "time delta")
        total = seconds + regs[RDX]
        days, kept = divmod(total, 86400)
        out = regs[RDI]
        self.word(out, kept, 4)
        self.word(out + 4, frac, 4)
        self.word(out + 8, (days * 86400 + self.case.rhs) & MASK[8])

    def on_date_add(self, machine):
        regs = machine.regs
        self.events.append(("date_add",))
        if self.case.date_fail:
            regs[RAX] = 0
            return
        regs[RAX] = date_at(day_number(wrap32(regs[RDI])) + wrap32(regs[RSI]))

    def map_out(self, out, layout, pairs):
        items = [(address_of(index), struct.pack("<Q", value)) for index, value in sorted(pairs.items())]
        root, height = self.tree(layout, items) if items else (0, 0)
        self.word(out, root)
        self.word(out + 8, height)
        self.word(out + 0x10, len(items))

    def on_active(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == STATE + E_S and regs[RCX] == STATE + E_S and regs[RDX] & 0xFF == self.case.chain, "active arguments")
        self.events.append(("active", regs[RDX] & 0xFF))
        self.map_out(regs[RDI], STAKE_MAP, self.active)

    def on_stakes(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == STATE + E_S and regs[RSI] & 0xFF == self.case.chain, "stakes arguments")
        self.events.append(("stakes", regs[RSI] & 0xFF))
        self.map_out(regs[RDI], STAKE_MAP, self.stakes)

    def on_token(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == ACTION + 8, "token argument")
        self.events.append(("token",))
        out = regs[RDI]
        self.machine.memory.put_bytes(out, PATTERN)
        self.word(out, self.op.token, 2)

    def on_parse(self, machine):
        regs = machine.regs
        op = self.op
        self.expect(self.bytes_at(regs[RSI], regs[RDX]) == op.text, "parse text")
        self.events.append(("parse",))
        out = regs[RDI]
        self.machine.memory.put_bytes(out, PATTERN)
        self.word(out, op.parse, 2)

    def on_float(self, machine):
        regs = machine.regs
        self.expect(self.bytes_at(regs[RDI], 16) == PATTERN[4:8] + PATTERN[8:16] + PATTERN[16:20], "decimal words")
        self.events.append(("to_float",))
        machine.xmm_result = to_bits(self.op.number)
        regs[RAX] = 0xABCD00 | int(self.op.float_ok)

    def on_nothing(self, machine):
        pass

    def on_drop_payload(self, machine):
        self.events.append(("drop_payload",))

    def on_drop_key(self, machine):
        self.events.append(("drop_key",))

    def on_drop_status(self, machine):
        self.events.append(("drop_status", self.read(machine.regs[RDI], 2)))

    def on_drop_stakes(self, machine):
        self.events.append(("drop_stakes",))

    def on_drop_action(self, machine):
        self.events.append(("drop_action",))

    def on_drop_parse(self, machine):
        self.expect(self.read(machine.regs[RDI], 2) == TAG_FLOAT, "parse drop value")
        self.events.append(("drop_parse",))

    def on_outer(self, machine):
        regs = machine.regs
        out, entry, value = regs[RDI], regs[RSI], regs[RDX]
        holder, node = self.read(entry), self.read(entry + 8)
        self.expect(node == 0 and self.read(entry + 0x10) == 0, "outer map holds one row")
        self.expect(self.read(value) == 0 and self.read(value + 0x10) == 0 and self.read(value + 0x18, 2) == 0x100, "outer default")
        node = self.empty_node(OUTER_MAP)
        self.insert_row(OUTER_MAP, node, 0, b"", self.bytes_at(value, 0x20))
        self.word(holder, node)
        self.word(holder + 8, 0)
        self.word(holder + 0x10, 1)
        self.word(out, node)
        self.word(out + 8, 0)
        self.word(out + 0x10, 0)

    def on_inner(self, machine):
        regs = machine.regs
        out, entry, value = regs[RDI], regs[RSI], regs[RDX]
        holder, node = self.read(entry), self.read(entry + 8)
        self.expect(node == 0 and self.read(entry + 0x10) == 0, "inner map holds one row")
        self.expect(all(self.read(value + at) == 0 for at in (0, 0x10, 0x18, 0x28)), "inner default")
        node = self.empty_node(INNER_MAP)
        self.insert_row(INNER_MAP, node, 0, b"", self.bytes_at(value, 0x30))
        self.word(holder, node)
        self.word(holder + 8, 0)
        self.word(holder + 0x10, 1)
        self.word(out, node)
        self.word(out + 8, 0)
        self.word(out + 0x10, 0)

    def on_set_insert(self, machine):
        regs = machine.regs
        holder, key = regs[RDI], self.bytes_at(regs[RSI], 20)
        keys = {found for found, _ in self.rows(ADDRESS_SET, self.read(holder), self.read(holder + 8))} if self.read(holder) else set()
        keys.add(key)
        root, height = self.tree(ADDRESS_SET, [(found, b"") for found in sorted(keys)])
        self.word(holder, root)
        self.word(holder + 8, height)
        self.word(holder + 0x10, len(keys))

    def on_clone_set(self, machine):
        regs = machine.regs
        self.word(regs[RDI], regs[RSI])
        self.word(regs[RDI] + 8, regs[RDX])
        self.word(regs[RDI] + 0x10, len(self.rows(ADDRESS_SET, regs[RSI], regs[RDX])))

    def on_list_keys(self, machine):
        regs = machine.regs
        out, it = regs[RDI], regs[RSI]
        root, height, left = self.read(it + 0x10), self.read(it + 0x18), self.read(it + 0x40)
        present = self.read(it) & 1
        self.expect(self.read(it) == self.read(it + 0x20) and self.read(it + 8) == 0 and self.read(it + 0x28) == 0 and self.read(it + 0x30) == root and self.read(it + 0x38) == height, "key iterator")
        if not present:
            self.expect(left == 0, "empty iterator")
            root = 0
        self.word(out, root)
        self.word(out + 8, height)
        self.word(out + 0x10, left)

    def on_iter_drop(self, machine):
        it = machine.regs[RSI]
        if self.read(it):
            root, height = self.read(it + 0x10), self.read(it + 0x18)
            self.expect(self.read(it) == 1 and self.read(it + 0x20) == 1 and self.read(it + 8) == 0 and self.read(it + 0x28) == 0 and self.read(it + 0x30) == root and self.read(it + 0x38) == height, "drop iterator")
            self.expect(self.read(it + 0x40) == len(self.rows(ADDRESS_SET, root, height)), "drop iterator length")
        else:
            self.expect(self.read(it + 0x20) == 0 and self.read(it + 0x40) == 0, "empty drop iterator")
        self.word(machine.regs[RDI], 0)

    def on_leaf(self, machine):
        regs = machine.regs
        out, handle, key, value = regs[RDI], regs[RSI], regs[RDX], regs[RCX]
        node, height, index = self.read(handle), self.read(handle + 8), self.read(handle + 0x10)
        self.expect(height == 0 and self.read(regs[R8]) == STATE + E_TRACKER + T_ROWS, "leaf handle")
        self.insert_row(ROW_TREE, node, index, self.bytes_at(key, KEY_SIZE), self.bytes_at(value, ROW_SIZE))
        self.word(out, node)
        self.word(out + 8, 0)
        self.word(out + 0x10, index)

    def on_stream_leaf(self, machine):
        regs = machine.regs
        out, handle, key, value = regs[RDI], regs[RSI], regs[RDX], regs[RCX]
        node, height, index = self.read(handle), self.read(handle + 8), self.read(handle + 0x10)
        self.expect(height == 0, "leaf handle")
        self.insert_row(STREAM_MAP, node, index, self.bytes_at(key, 20), self.bytes_at(value, 0x18))

    def on_inner_cmp(self, machine):
        regs = machine.regs
        left = (self.read(regs[RDI]), self.read(regs[RDI] + 8))
        right = (self.read(regs[RSI]), self.read(regs[RSI] + 8))
        regs[RAX] = 0x7700 | (0 if left == right else 1 if left > right else 0xFF)

    def on_clone_inner(self, machine):
        machine.memory.copy(machine.regs[RDI], machine.regs[RSI], KEY_SIZE)
        self.events.append(("clone_inner",))

    def on_clone_outer(self, machine):
        self.expect(machine.regs[RSI] == ACTION, "outer clone source")
        machine.memory.copy(machine.regs[RDI], machine.regs[RSI], KEY_SIZE)
        self.events.append(("clone_outer",))

    def on_apply(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == STATE, "apply state")
        self.expect(self.view_key(self.bytes_at(regs[RSI], KEY_SIZE)) == self.op.pay.key(), "apply payload")
        self.events.append(("apply", self.op.pay.k))
        machine.memory.put_bytes(regs[RDI], PATTERN)
        self.word(regs[RDI], self.op.apply, 2)

    def rows(self, layout, root, height):
        """In-order rows of one real tree: (key bytes, value address)."""
        found = []
        if not root:
            return found
        count = self.read(root + layout.len_at, 2)
        self.expect(count <= 11, "node length")
        for at in range(count):
            if height:
                found.extend(self.rows(layout, self.read(root + layout.edge_at + 8 * at), height - 1))
            found.append((self.bytes_at(root + layout.key_at + layout.key_size * at, layout.key_size) if layout.key_size else b"", root + layout.val_at + layout.val_size * at))
        if height:
            found.extend(self.rows(layout, self.read(root + layout.edge_at + 8 * count), height - 1))
        return found

    def insert_row(self, layout, node, index, key, value):
        count = self.read(node + layout.len_at, 2)
        self.expect(count < 11 and index <= count, "leaf room")
        memory = self.machine.memory
        for at in range(count, index, -1):
            memory.put_bytes(node + layout.key_at + layout.key_size * at, self.bytes_at(node + layout.key_at + layout.key_size * (at - 1), layout.key_size))
            memory.put_bytes(node + layout.val_at + layout.val_size * at, self.bytes_at(node + layout.val_at + layout.val_size * (at - 1), layout.val_size))
        memory.put_bytes(node + layout.key_at + layout.key_size * index, key)
        memory.put_bytes(node + layout.val_at + layout.val_size * index, value)
        self.word(node + layout.len_at, count + 1, 2)

    def empty_node(self, layout):
        return self.node(layout, (), ())

    def node(self, layout, items, children):
        base = self.next_node
        self.next_node += layout.size + 0x10
        self.expect(self.next_node < ARENA, "node area")
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * (layout.size + 0x10))
        for at, (key, value) in enumerate(items):
            if layout.key_size:
                memory.put_bytes(base + layout.key_at + layout.key_size * at, key)
            if layout.val_size:
                memory.put_bytes(base + layout.val_at + layout.val_size * at, value)
        for at in range(len(items), 11):
            if layout.val_size:
                memory.put_bytes(base + layout.val_at + layout.val_size * at, b"\xFF" * layout.val_size)
            if layout.key_size == 20:
                memory.put_bytes(base + layout.key_at + 20 * at, bytes(20))
        self.word(base + layout.len_at, len(items), 2)
        self.word(base + layout.parent_at, 0)
        for slot, child in enumerate(children):
            self.word(base + layout.edge_at + 8 * slot, child)
            self.word(child + layout.parent_at, base)
            self.word(child + layout.slot_at, slot, 2)
        return base

    def build(self, layout, items, height):
        if height == 0:
            return self.node(layout, items, ())
        size = len(items)
        low = (size - 3) // 4
        extra = (size - 3) - low * 4
        children, separators, at = [], [], 0
        for part in range(4):
            take = low + (1 if part < extra else 0)
            children.append(self.build(layout, items[at:at + take], height - 1))
            at += take
            if part < 3:
                separators.append(items[at])
                at += 1
        return self.node(layout, separators, children)

    def tree(self, layout, items):
        height = 0
        while capacity(height) < len(items):
            height += 1
        return self.build(layout, list(items), height), height

    def holder(self, at, layout, items):
        if not items:
            self.word(at, 0)
            self.word(at + 8, 0xB1B1)
            self.word(at + 0x10, 0)
            return
        root, height = self.tree(layout, items)
        self.word(at, root)
        self.word(at + 8, height)
        self.word(at + 0x10, len(items))

    def address_set(self, at, indexes):
        self.holder(at, ADDRESS_SET, [(address_of(index), b"") for index in sorted(indexes)])

    def write_pay(self, pay):
        data = bytearray((0xD0 + index) & 0xFF for index in range(KEY_SIZE))
        data[0:8] = struct.pack("<Q", pay.word())
        k = pay.k
        if k in (0, 2, 3, 5):
            pointer = self.allocate(max(len(pay.text), 1))
            self.machine.memory.put_bytes(pointer, pay.text)
            data[8:0x20] = struct.pack("<QQQ", len(pay.text) + 3, pointer, len(pay.text))
        if k == 1:
            data[8] = pay.flag
            data[9:0x1D] = address_of(pay.addr)
        if k == 2:
            data[0x20:0x34] = address_of(pay.addr)
        if k in (3, 5):
            data[0x20] = pay.flag
        if k == 4:
            data[8:0x10] = struct.pack("<Q", pay.number)
            data[0x10] = pay.flag
        if k == 7:
            data[8:0x10] = struct.pack("<Q", pay.number)
            for at, index in zip((0x10, 0x24, 0x38, 0x4C), pay.addrs):
                data[at:at + 20] = address_of(index)
        if k == 6:
            data[8:0x10] = struct.pack("<Q", pay.body)
        return bytes(data)

    def view_key(self, data):
        word = struct.unpack_from("<Q", data)[0]
        k = word - BASE_WORD if word >= BASE_WORD else 6
        tail = {1: 0x1D, 4: 0x11, 6: 0x10, 7: 0x60}.get(k)
        if tail is not None:
            self.expect(data[tail:] == bytes((0xD0 + index) & 0xFF for index in range(tail, KEY_SIZE)), "key tail")
        if k in (0, 2, 3, 5):
            pointer, size = struct.unpack_from("<QQ", data, 0x10)
            text = self.bytes_at(pointer, size)
        if k == 0:
            return (0, text)
        if k == 1:
            return (1, data[9:0x1D], data[8])
        if k == 2:
            return (2, text, data[0x20:0x34])
        if k in (3, 5):
            return (k, text, data[0x20])
        if k == 4:
            return (4, struct.unpack_from("<Q", data, 8)[0], data[0x10])
        if k == 7:
            return (7, struct.unpack_from("<Q", data, 8)[0], data[0x10:0x24], data[0x24:0x38], data[0x38:0x4C], data[0x4C:0x60])
        return (6, word, struct.unpack_from("<Q", data, 8)[0])

    def row_value(self, row):
        """The 0x70 byte value of one seeded row."""
        memory = self.machine.memory
        name = self.allocate(15)
        memory.put_bytes(name, b"l1_vote_tracker")
        area = self.allocate(0x80)
        memory.put_bytes(area, bytes([FILL]) * 0x80)
        self.word(area, 15)
        self.word(area + 8, name)
        self.word(area + 0x10, 15)
        memory.put_bytes(area + R_HC, struct.pack("<dd", *row["hc"]))
        self.word(area + R_BUCKETS, 0)
        self.word(area + R_BUCKETS + 8, 0)
        self.word(area + R_BUCKETS + 0x10, 0)
        if row["fin"] is not None:
            inner_value = self.allocate(0x30)
            self.address_set(inner_value, row["voters"])
            self.address_set(inner_value + 0x18, row["listed"])
            inner = self.empty_node(INNER_MAP)
            self.insert_row(INNER_MAP, inner, 0, b"", self.bytes_at(inner_value, 0x30))
            outer_value = self.allocate(0x20)
            self.word(outer_value, inner)
            self.word(outer_value + 8, 0)
            self.word(outer_value + 0x10, 1)
            self.word(outer_value + 0x18, row["fin"])
            outer = self.empty_node(OUTER_MAP)
            self.insert_row(OUTER_MAP, outer, 0, b"", self.bytes_at(outer_value, 0x20))
            self.word(area + R_BUCKETS, outer)
            self.word(area + R_BUCKETS + 0x10, 1)
        self.map_out(area + R_STAKES, STAKE_MAP, row["stakes"])
        memory.put_bytes(area + R_RATIO, struct.pack("<d", row["ratio"]))
        memory.put_bytes(area + R_EXPIRE, pack_time(row["expire"]))
        self.word(area + R_DONE, row["done"], 1)
        return self.bytes_at(area, ROW_SIZE)

    def frozen(self):
        data = bytearray(self.bytes_at(STATE, E_SIZE))
        for at in (E_TRACKER + T_ROWS, E_STREAM):
            data[at:at + 0x18] = bytes(0x18)
        return hashlib.sha256(bytes(data) + self.bytes_at(CALLER, 20)).hexdigest()

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(STATE, bytes([FILL]) * E_SIZE)
        self.next_node = NODES
        self.arena = ARENA
        self.events = []
        self.case = case
        self.stakes = dict(case.stakes)
        self.active = dict(case.active)
        memory.put_bytes(STATE + E_TIME, pack_time(case.now))
        self.word(STATE + E_CHAIN, case.chain, 1)
        s = STATE + E_S
        self.address_set(s + S_ALLOWED, case.allowed)
        self.word(s + S_ALLOW_ALL, int(case.allow_all), 1)
        profiles = []
        for index, signer in sorted(case.profiles):
            value = bytearray(bytes([0xF0]) * 0x58)
            value[P_SIGNER:P_SIGNER + 20] = address_of(signer)
            profiles.append((address_of(index), bytes(value)))
        self.holder(s + S_PROFILES, PROFILE_MAP, profiles)
        self.holder(STATE + E_VALIDATORS, VALIDATOR_MAP, [(address_of(index), bytes(0x10)) for index in sorted(case.validators)])
        t = STATE + E_TRACKER
        self.word(t + T_ACTIVE, int(case.enabled), 1)
        self.address_set(t + T_HVS, case.hvs)
        memory.put_bytes(t + T_HC, struct.pack("<dd", *case.hc))
        items = [(self.write_pay(row["pay"]), self.row_value(row)) for row in sorted(case.rows, key=lambda row: row["pay"].key())]
        self.holder(t + T_ROWS, ROW_TREE, items)
        self.seed_rows = None
        stream = []
        for index, bits, time in sorted(case.stream):
            stream.append((address_of(index), struct.pack("<Q", bits) + pack_time(time) + bytes(4)))
        self.holder(STATE + E_STREAM, STREAM_MAP, stream)
        self.frozen_digest = self.frozen()

    def state(self):
        t = STATE + E_TRACKER
        holder = t + T_ROWS
        found = []
        size = self.read(holder + 0x10)
        rows = self.rows(ROW_TREE, self.read(holder), self.read(holder + 8)) if size else []
        self.expect(len(rows) == size, "row count")
        for key, at in rows:
            self.expect(self.read(at) == 15 and self.bytes_at(self.read(at + 8), self.read(at + 0x10)) == b"l1_vote_tracker", "row name")
            hc = struct.unpack("<dd", self.bytes_at(at + R_HC, 16))
            voters = listed = fin = None
            outer, outer_size = self.read(at + R_BUCKETS), self.read(at + R_BUCKETS + 0x10)
            if outer_size:
                self.expect(outer_size == 1, "one bucket")
                spot = self.rows(OUTER_MAP, outer, self.read(at + R_BUCKETS + 8))[0][1]
                fin = self.read(spot + 0x18, 2)
                self.expect(self.read(spot + 0x10) == 1, "one inner row")
                inner = self.rows(INNER_MAP, self.read(spot), self.read(spot + 8))[0][1]
                voters = tuple(address_index(found_key) for found_key, _ in self.rows(ADDRESS_SET, self.read(inner), self.read(inner + 8)))
                listed = tuple(address_index(found_key) for found_key, _ in self.rows(ADDRESS_SET, self.read(inner + 0x18), self.read(inner + 0x20)))
            stakes = tuple((address_index(found_key), self.read(value)) for found_key, value in self.rows(STAKE_MAP, self.read(at + R_STAKES), self.read(at + R_STAKES + 8)))
            self.expect(self.read(at + R_STAKES + 0x10) == len(stakes), "stake length")
            found.append((self.view_key(key), hc, voters, listed, fin, stakes, self.read(at + R_RATIO), struct.unpack("<iII", self.bytes_at(at + R_EXPIRE, 12)), self.read(at + R_DONE, 1)))
        holder = STATE + E_STREAM
        size = self.read(holder + 0x10)
        rates = self.rows(STREAM_MAP, self.read(holder), self.read(holder + 8)) if size else []
        self.expect(len(rates) == size, "stream count")
        stream = tuple((address_index(key), (self.read(at), struct.unpack("<iII", self.bytes_at(at + 8, 12)))) for key, at in rates)
        return tuple(found), stream, self.frozen()

    def prepare(self, op):
        if op.stakes is not None:
            self.stakes = dict(op.stakes)
        if op.active is not None:
            self.active = dict(op.active)
        if op.tracker_active is not None:
            self.word(STATE + E_TRACKER + T_ACTIVE, int(op.tracker_active), 1)
        if op.hvs is not None:
            self.address_set(STATE + E_TRACKER + T_HVS, op.hvs)
        if op.now is not None:
            self.machine.memory.put_bytes(STATE + E_TIME, pack_time(op.now))
        self.frozen_digest = self.frozen()

    def vote_out(self):
        raw = self.bytes_at(OUT, OUT_SIZE)
        if raw[0] == 9:
            if raw[1] not in (0, 1):
                raise Halt("flag byte")
            return ("ok", raw[1])
        if raw[0] != 14:
            raise Halt("result tag %d" % raw[0])
        return ("err", struct.unpack_from("<H", raw, 8)[0], raw[0xA:0x68] == PATTERN[2:])

    def stream_out(self):
        raw = self.bytes_at(OUT, OUT_SIZE)
        if raw[0] == 13:
            return ("ok", 0)
        if raw[0] != 14:
            raise Halt("result tag %d" % raw[0])
        return ("err", struct.unpack_from("<H", raw, 8)[0], raw[0xA:0x68] == PATTERN[2:])

    def run_op(self, op):
        self.op = op
        self.prepare(op)
        memory = self.machine.memory
        memory.stack[:] = memory.fresh[0]
        memory.put_bytes(OUT, bytes([0xEE]) * OUT_SIZE)
        memory.put_bytes(CALLER, address_of(op.caller))
        self.frozen_digest = self.frozen()
        if op.kind == "stream":
            pointer = self.allocate(max(len(op.text), 1))
            memory.put_bytes(pointer, op.text)
            memory.put_bytes(ACTION, struct.pack("<QQQ", len(op.text), pointer, len(op.text)))
            self.machine.run(STREAM_WRAP, {RDI: OUT, RSI: ACTION, RDX: CALLER, RCX: STATE})
            return self.stream_out()
        if op.kind == "count":
            row = sorted(self.case.rows, key=lambda row: row["pay"].key()).index(self.case.rows[op.row])
            spot = self.rows(ROW_TREE, self.read(STATE + E_TRACKER + T_ROWS), self.read(STATE + E_TRACKER + T_ROWS + 8))[row][1]
            pair = bytearray(0x2A)
            pair[0] = int(op.pair[0])
            pair[1:0x15] = address_of(op.caller)
            pair[0x15] = int(op.pair[1])
            pair[0x16:0x2A] = address_of(op.caller)
            memory.put_bytes(PAIR, bytes(pair))
            return ("value", self.machine.run(COUNT, {RDI: spot, RSI: PAIR}) & 0xFF)
        memory.put_bytes(ACTION, self.write_pay(op.pay))
        before = self.bytes_at(ACTION, KEY_SIZE)
        self.machine.run(HANDLER, {RDI: OUT, RSI: ACTION, RDX: CALLER, RCX: STATE})
        if self.bytes_at(ACTION, KEY_SIZE) != before:
            raise Halt("action changed")
        return self.vote_out()

    def run(self, case):
        self.fresh(case)
        results = []
        try:
            for op in case.ops:
                results.append(self.run_op(op))
        except Panicked as stop:
            return "panic", stop.args[0], tuple(results), tuple(self.events)
        digest = self.state()
        self.expect(digest[2] == self.frozen_digest, "frozen words")
        return "done", tuple(results), tuple(self.events), digest


def vector_pool():
    return (Pay(0, b"ab"), Pay(1, addr=2, flag=1), Pay(2, b"TOK", addr=3), Pay(3, b"dex", flag=1), Pay(3, b"dex", flag=0), Pay(4, number=5, flag=1), Pay(5, b"coin", flag=1), Pay(6, inner=(1 << 63) + 2, body=7), Pay(6, inner=0x40, body=9), Pay(7, number=2))


def named_cases():
    cases = []

    def add(name, **fields):
        cases.append(Case(name, "vote", **fields))

    one = Pay(4, number=1, flag=1)
    many = tuple(range(1, 16))
    # gate
    add("gate_not_allowed", ops=(Op(9, one),))
    add("gate_allowed_empty", allowed=(), profiles=(), active=(), ops=(Op(1, one),))
    add("gate_allow_all_stranger", allow_all=True, profiles=((9, 25),), active=((25, 1),), stakes=((9, 10),), ops=(Op(9, one),))
    add("gate_disabled_allowed", enabled=False, ops=(Op(1, one),))
    add("gate_disabled_allow_all", enabled=False, allow_all=True, ops=(Op(1, one),))
    add("gate_tall_allowed_hit", allowed=many, ops=(Op(1, one), Op(8, one), Op(15, one)))
    add("gate_tall_allowed_miss", allowed=tuple(index * 2 for index in range(1, 16)), profiles=(), active=(), ops=(Op(3, one), Op(31, one),))
    add("gate_tall_validators", allowed=many, profiles=tuple((index, index + 16) for index in many), stakes=tuple((index, 7) for index in many), ops=(Op(9, one),))
    # new row
    add("new_row_no_profile", profiles=(), ops=(Op(1, one),))
    add("new_row_other_profile", profiles=((2, 18),), ops=(Op(1, one),))
    add("new_row_profile_left_miss", profiles=((2, 18), (3, 19)), ops=(Op(1, one),))
    add("new_row_tall_profiles", allowed=many, profiles=tuple((index, index + 16) for index in many), active=tuple((index + 16, 1) for index in many), ops=(Op(1, one), Op(3, Pay(4, number=2)), Op(14, Pay(4, number=3))))
    add("new_row_active_empty", active=(), ops=(Op(1, one),))
    add("new_row_signer_inactive", active=((18, 1),), ops=(Op(1, one),))
    add("new_row_tall_active_miss", active=tuple((index + 40, 1) for index in many), ops=(Op(1, one),))
    add("new_row_tall_active_hit", allowed=many, profiles=tuple((index, index + 16) for index in many), active=tuple((index + 16, 1) for index in many), stakes=((14, 5),), ops=(Op(14, one),))
    add("new_row_key_is_validator_set_signer", profiles=((1, 30),), active=((30, 1),), ops=(Op(1, one),))
    add("new_row_not_in_stakes_no_bucket", stakes=((2, 100),), ops=(Op(1, one), Op(3, one)))
    add("new_row_empty_stakes", stakes=(), ops=(Op(1, one), Op(2, one)))
    add("new_row_hvs_only", stakes=((2, 100),), hvs=(1,), ops=(Op(1, one),))
    add("new_row_both_sets", hvs=(1, 2), hc=(0.25, 3.5), ops=(Op(1, one),))
    add("new_row_copies_hc", hc=(0.0, 7.25), ops=(Op(1, one),))
    add("new_row_chain_one", chain=1, ops=(Op(1, one),))
    add("new_row_expire_day_roll", now=(BASE_DATE, 80000, 3), ops=(Op(1, one),))
    add("new_row_date_fail", date_fail=True, ops=(Op(1, one),))
    add("new_row_rhs_low", rhs=-0x8000000000000, ops=(Op(1, one),))
    add("new_row_rhs_range_low_edge", rhs=-(0xA8C000000000 - 86400 * 7) - 0x1000000, ops=(Op(1, one),))
    add("new_row_rhs_high", rhs=0x10000000000000, ops=(Op(1, one),))
    add("new_row_rhs_within", rhs=86400 * 3, ops=(Op(1, one),))
    low = (0xFFFEAE7FFFFEAE81 - 0xFFFF574000000000) & TOP
    low -= 1 << 64
    add("new_row_rhs_lowest_kept", rhs=low - TTL, date_fail=True, ops=(Op(1, one),))
    add("new_row_rhs_below_lowest", rhs=low - TTL - 1, date_fail=True, ops=(Op(1, one),))
    add("new_row_rhs_highest_kept", rhs=0xA8C000000000 - 1 - TTL, date_fail=True, ops=(Op(1, one),))
    add("new_row_rhs_above_highest", rhs=0xA8C000000000 - TTL, date_fail=True, ops=(Op(1, one),))
    add("new_row_rhs_part_day", rhs=86399, ops=(Op(1, one),))
    add("new_row_rhs_negative_part_day", rhs=-(86400 * 7 + 1000), ops=(Op(1, one),))
    # quorum
    three = ((1, 100), (2, 100), (3, 100))
    add("quorum_two_of_three_exact_short", stakes=three, ops=(Op(1, one), Op(2, one)))
    add("quorum_three_of_three", stakes=three, ops=(Op(1, one), Op(2, one), Op(3, one)))
    add("quorum_just_over", stakes=((1, 201), (2, 99)), ops=(Op(1, one),))
    add("quorum_just_under", stakes=((1, 200), (2, 100)), ops=(Op(1, one),))
    add("quorum_weak_at_fifth_short", stakes=((1, 60), (2, 240)), ops=(Op(1, Pay(6, inner=(1 << 63) + 2)), ))
    add("quorum_weak_over_fifth", stakes=((1, 61), (2, 239)), ops=(Op(1, Pay(6, inner=(1 << 63) + 2)),))
    add("quorum_weak_niche_word", stakes=((1, 61), (2, 239)), ops=(Op(1, Pay(6, inner=0x20)),))
    add("quorum_strong_each_named_variant", stakes=((1, 61), (2, 239)), ops=tuple(Op(1, pay) for pay in (Pay(0, b"a"), Pay(1), Pay(2, b"T"), Pay(3, b"d"), Pay(4), Pay(5, b"c"), Pay(7))))
    add("quorum_one_vote_only_once", stakes=three, ops=(Op(1, one), Op(1, one), Op(1, one)))
    add("quorum_second_vote_after_finish", stakes=three, ops=(Op(1, one), Op(2, one), Op(3, one), Op(3, one), Op(1, one)))
    add("quorum_large_stakes_float", stakes=((1, 1 << 60), (2, 1 << 61)), ops=(Op(2, one), Op(1, one)))
    add("quorum_precision_loss", stakes=((1, (1 << 62) + 1), (2, (1 << 62) - 1), (3, 1 << 62)), ops=(Op(1, one), Op(2, one)))
    add("quorum_stake_sum_overflow", stakes=((1, 1 << 63), (2, 1 << 63)), ops=(Op(1, one),))
    add("quorum_voted_sum_overflow", rows=(seed(one, stakes=((1, 1 << 63), (2, 1 << 63)), voters=(1, 2), fin=0x100),), ops=(Op(1, one),))
    add("quorum_zero_total", stakes=((1, 0), (2, 0)), ops=(Op(1, one), Op(2, one)))
    add("quorum_tall_stake_map", allowed=many, profiles=tuple((index, index + 16) for index in many), active=tuple((index + 16, 1) for index in many), stakes=tuple((index, index * 10) for index in many), ops=tuple(Op(index, one) for index in (15, 14, 13, 12, 11, 10, 9, 8, 7)))
    add("quorum_tall_voter_set", allowed=many, profiles=tuple((index, index + 16) for index in many), active=tuple((index + 16, 1) for index in many), stakes=tuple((index, 1) for index in many), ops=tuple(Op(index, one) for index in many))
    add("quorum_hc_blocks_stake", hvs=(1, 2, 3, 4), hc=(0.5, 0.0), stakes=((1, 100),), ops=(Op(1, one),))
    add("quorum_hc_then_listed", allowed=(1, 2, 3, 4), hvs=(1, 2, 3, 4), hc=(0.5, 0.0), stakes=((1, 100), (2, 1), (3, 1)), ops=(Op(1, one), Op(2, one), Op(3, one)))
    add("hvs_only_can_open_but_not_join", allowed=(1, 2, 3), hvs=(1, 2), stakes=((3, 100),), ops=(Op(1, one), Op(2, one), Op(3, one)))
    add("quorum_hc_listed_first", allowed=(1, 2, 3, 4), hvs=(2, 3, 4), hc=(0.5, 0.0), stakes=((1, 100), (2, 1)), rows=(seed(one, stakes=((1, 100), (2, 1)), hc=(0.5, 0.0), voters=(2,), listed=(3, 4), fin=0x100),), ops=(Op(2, one), Op(1, one)))
    add("quorum_hc_row_copy_wins", hvs=(1, 2, 3, 4), hc=(0.75, 0.0), allowed=(1, 2, 3, 4), rows=(seed(one, stakes=((1, 100),), hc=(0.0, 0.0)),), ops=(Op(1, one),))
    add("quorum_before_already_true_no_finish", rows=(seed(one, voters=(1, 2, 3), fin=0x100),), ops=(Op(1, one), Op(2, one)))
    add("quorum_before_true_by_hvs_change", allowed=(1, 2, 3, 4), hc=(0.5, 0.0), hvs=(3,), rows=(seed(one, hc=(0.5, 0.0), voters=(1, 2, 3), listed=(3,), fin=0x100),), ops=(Op(1, one), Op(2, one, hvs=(3, 4, 5, 6))))
    add("finish_writes_row_done", stakes=((1, 100),), ops=(Op(1, one),))
    add("done_row_has_no_gate", stakes=((1, 100), (2, 100)), rows=(seed(one, stakes=((1, 100), (2, 100)), voters=(1,), fin=0x100, done=1),), ops=(Op(2, one),))
    add("finished_bucket_ignores_quorum", stakes=((1, 100), (2, 100)), rows=(seed(one, stakes=((1, 100), (2, 100)), voters=(), fin=1),), ops=(Op(1, one), Op(2, one)))
    add("quorum_voter_outside_snapshot_tall", rows=(seed(one, stakes=tuple((index * 2, 1) for index in range(1, 16)), voters=(3, 5, 7, 2, 30), fin=0x100),), allowed=(4, 6), ops=(Op(4, one), Op(6, one)))
    add("quorum_voter_outside_leaf_snapshot", rows=(seed(one, stakes=((2, 5), (4, 5)), voters=(3, 9, 1), fin=0x100),), allowed=(2, 4), ops=(Op(2, one),))
    add("hvs_tall_hit_and_miss", allowed=(1, 8, 15, 16), hvs=tuple(range(1, 16)), stakes=((1, 1), (8, 1), (15, 1), (16, 1)), ops=(Op(1, one), Op(8, one), Op(15, one), Op(16, one)))
    add("hvs_tall_even_miss", allowed=(3, 8, 14), hvs=tuple(index * 2 for index in range(1, 16)), stakes=((3, 1), (8, 1), (14, 1)), ops=(Op(3, one), Op(8, one), Op(14, one)))
    add("hvs_second_set_tall_ratio", allowed=tuple(range(1, 16)), hvs=tuple(range(1, 16)), hc=(0.5, 0.0), stakes=tuple((index, 1) for index in range(1, 16)), ops=tuple(Op(index, one) for index in (15, 3, 9, 1, 12, 6, 4, 13)))
    # row hit
    add("row_hit_caller_outside_snapshot", rows=(seed(one, stakes=((2, 100),)),), ops=(Op(1, one),))
    add("row_hit_empty_snapshot", rows=(seed(one, stakes=()),), ops=(Op(1, one),))
    add("row_hit_no_active_call", rows=(seed(one),), active=(), profiles=(), ops=(Op(1, one),))
    add("row_hit_keeps_expire", rows=(seed(one, expire=later(T0, 5)),), now=later(T0, 90000), ops=(Op(1, one),))
    add("row_hit_keeps_old_stakes", stakes=((1, 100), (2, 100), (3, 100)), ops=(Op(1, one), Op(2, one, stakes=((2, 900), (3, 1))), Op(3, one)))
    add("row_hit_ignores_new_active", ops=(Op(1, one), Op(2, one, active=()),))
    add("row_hit_tall_snapshot", allowed=many, rows=(seed(one, stakes=tuple((index, 1) for index in many)),), ops=(Op(1, one), Op(14, one), Op(15, one)))
    add("row_hit_tall_snapshot_miss", allowed=(2, 4, 16), rows=(seed(one, stakes=tuple((index * 2 + 1, 1) for index in range(10))),), ops=(Op(2, one), Op(4, one), Op(16, one)))
    add("past_expire_row_still_counts", rows=(seed(one, expire=(BASE_DATE - 16, 0, 0)),), ops=(Op(1, one),))
    add("disable_later", ops=(Op(1, one), Op(2, one, tracker_active=False)))
    # cap
    filled = tuple(seed(Pay(4, number=index + 1), stakes=((1, 1), (2, 1)), voters=(1,), fin=0x100) for index in range(49))
    add("cap_49_rows_passes", rows=filled, ops=(Op(1, Pay(4, number=500)),))
    add("cap_49_then_50_then_stop", rows=filled, stakes=((1, 1), (2, 1)), ops=(Op(1, Pay(4, number=500)), Op(1, Pay(4, number=501))))
    add("cap_50_rows_refused", rows=filled + (seed(Pay(4, number=900), voters=(1,), fin=0x100),), ops=(Op(1, Pay(4, number=500)),))
    add("cap_refuses_existing_row_too", rows=filled + (seed(Pay(4, number=900), voters=(1,), fin=0x100),), ops=(Op(1, Pay(4, number=900)),))
    add("cap_is_per_caller", rows=filled + (seed(Pay(4, number=900), voters=(1,), fin=0x100),), ops=(Op(2, Pay(4, number=500)),))
    add("cap_counts_listed", rows=tuple(seed(Pay(4, number=index + 1), stakes=((2, 1),), listed=(1,), fin=0x100) for index in range(50)), ops=(Op(1, Pay(4, number=500)),))
    add("cap_counts_finished_and_done", rows=tuple(seed(Pay(4, number=index + 1), voters=(1,), fin=1, done=1) for index in range(50)), ops=(Op(1, Pay(4, number=500)),))
    add("cap_ignores_rows_without_bucket", rows=tuple(seed(Pay(4, number=index + 1)) for index in range(55)), ops=(Op(1, Pay(4, number=500)),))
    add("cap_mixed_shape_rows", rows=tuple(seed(Pay(4, number=index + 1), voters=(1,) if index % 2 else (2,), fin=0x100) for index in range(40)), ops=(Op(1, Pay(4, number=999)), Op(2, Pay(4, number=999))))
    add("cap_only_first_row_voted", rows=tuple(seed(Pay(4, number=index + 1), voters=(1,) if index == 0 else (2,), fin=0x100) for index in range(60)), ops=(Op(1, Pay(4, number=999)),))
    add("cap_only_last_row_voted", rows=tuple(seed(Pay(4, number=index + 1), voters=(1,) if index == 59 else (2,), fin=0x100) for index in range(60)), ops=(Op(1, Pay(4, number=999)),))
    add("cap_every_third_row", rows=tuple(seed(Pay(4, number=index + 1), voters=(1,) if index % 3 == 0 else (2,), fin=0x100) for index in range(120)), ops=(Op(1, Pay(4, number=999)), Op(2, Pay(4, number=999))))
    # variants
    add("handler_string_100_long", ops=(Op(1, Pay(0, b"x" * 101)),))
    add("handler_string_100_edge", ops=(Op(1, Pay(0, b"x" * 100)),))
    add("handler_string_21", ops=(Op(1, Pay(0, b"x" * 21)),))
    add("handler_string_20_ok", ops=(Op(1, Pay(0, b"x" * 20)),))
    add("handler_string_empty", ops=(Op(1, Pay(0, b"")),))
    add("handler_dex_101", ops=(Op(1, Pay(3, b"x" * 101)),))
    add("handler_dex_21", ops=(Op(1, Pay(3, b"x" * 21)),))
    add("handler_dex_20", ops=(Op(1, Pay(3, b"x" * 20, flag=1)),))
    add("handler_coin_101", ops=(Op(1, Pay(5, b"x" * 101)),))
    add("handler_coin_21", ops=(Op(1, Pay(5, b"x" * 21)),))
    add("handler_coin_20", ops=(Op(1, Pay(5, b"x" * 20, flag=1)),))
    add("handler_coin_empty", ops=(Op(1, Pay(5, b"")),))
    add("handler_dex_empty", ops=(Op(1, Pay(3, b"", flag=1)),))
    add("handler_token_refused", ops=(Op(1, Pay(2, b"BAD"), token=0xEB),))
    add("handler_token_passes", stakes=((1, 100),), ops=(Op(1, Pay(2, b"TOK", addr=7)),))
    add("handler_token_empty", stakes=((1, 100),), ops=(Op(1, Pay(2, b"", addr=7)),))
    add("handler_token_long_no_limit", ops=(Op(1, Pay(2, b"x" * 150, addr=7)),))
    add("handler_plain_variants", ops=(Op(1, Pay(1, addr=3, flag=1)), Op(1, Pay(4, number=9)), Op(1, Pay(7, number=3))))
    add("handler_inner_tags", ops=tuple(Op(1, Pay(6, inner=(1 << 63) + tag)) for tag in range(10)))
    add("handler_inner_high_word", ops=(Op(1, Pay(6, inner=BASE_WORD + 6)),))
    add("handler_inner_niche_zero", ops=(Op(1, Pay(6, inner=0)),))
    add("handler_inner_top_niche", ops=(Op(1, Pay(6, inner=(1 << 63) - 1)),))
    add("apply_each_variant", stakes=((1, 100),), ops=tuple(Op(1, pay) for pay in (Pay(0, b"a"), Pay(1), Pay(2, b"T"), Pay(3, b"d"), Pay(4), Pay(5, b"c"), Pay(6, inner=(1 << 63) + 2), Pay(7))))
    add("apply_fails_keeps_finished", stakes=((1, 100), (2, 1)), ops=(Op(1, one, apply=0xEA), Op(2, one), Op(1, one)))
    add("apply_fails_inner", stakes=((1, 100),), ops=(Op(1, Pay(6, inner=(1 << 63) + 2), apply=0x141),))
    add("apply_string_payload_clone", stakes=((1, 100),), ops=(Op(1, Pay(5, b"coin", flag=1)),))
    # keys
    add("key_text_prefix", ops=(Op(1, Pay(0, b"abc")), Op(1, Pay(0, b"ab")), Op(1, Pay(0, b"abcd")), Op(2, Pay(0, b"ab"))))
    add("key_text_differs", ops=(Op(1, Pay(0, b"abd")), Op(1, Pay(0, b"abc"))))
    add("key_flag_splits_dex", ops=(Op(1, Pay(3, b"dex", flag=1)), Op(1, Pay(3, b"dex", flag=0)), Op(2, Pay(3, b"dex", flag=1))))
    add("key_flag_splits_coin", ops=(Op(1, Pay(5, b"dex", flag=1)), Op(1, Pay(5, b"dex", flag=0))))
    add("key_dex_text_first", ops=(Op(1, Pay(3, b"b", flag=0)), Op(1, Pay(3, b"a", flag=1)), Op(1, Pay(3, b"c", flag=1))))
    add("key_kinds_do_not_mix", ops=(Op(1, Pay(3, b"dex")), Op(1, Pay(5, b"dex")), Op(1, Pay(0, b"dex"))))
    add("key_user_bytes", ops=(Op(1, Pay(1, addr=2, flag=1)), Op(1, Pay(1, addr=3, flag=1)), Op(1, Pay(1, addr=2, flag=0)), Op(2, Pay(1, addr=3, flag=1))))
    add("key_token_text_then_address", ops=(Op(1, Pay(2, b"T", addr=2)), Op(1, Pay(2, b"T", addr=3)), Op(1, Pay(2, b"S", addr=9)), Op(2, Pay(2, b"T", addr=3))))
    add("key_token_number_then_flag", ops=(Op(1, Pay(4, number=2, flag=1)), Op(1, Pay(4, number=2, flag=0)), Op(1, Pay(4, number=1, flag=1)), Op(2, Pay(4, number=2, flag=0))))
    add("key_top_bit_number", ops=(Op(1, Pay(4, number=1 << 63)), Op(1, Pay(4, number=1)), Op(1, Pay(7, number=1 << 63)), Op(1, Pay(7, number=2))))
    add("key_top_bit_number_rising", ops=(Op(1, Pay(4, number=2)), Op(1, Pay(4, number=1 << 63)), Op(1, Pay(7, number=2)), Op(1, Pay(7, number=1 << 63)), Op(2, Pay(7, number=1 << 63))))
    add("key_dex_prefix", ops=(Op(1, Pay(3, b"abc")), Op(1, Pay(3, b"ab")), Op(1, Pay(3, b"abcd")), Op(2, Pay(3, b"ab")), Op(1, Pay(5, b"abc")), Op(1, Pay(5, b"ab")), Op(1, Pay(5, b"abcd"))))
    add("key_token_prefix", ops=(Op(1, Pay(2, b"abc")), Op(1, Pay(2, b"ab")), Op(1, Pay(2, b"abcd")), Op(2, Pay(2, b"ab"))))
    add("key_user_last_byte", ops=(Op(1, Pay(1, addr=201)), Op(1, Pay(1, addr=200)), Op(1, Pay(1, addr=202))))
    add("key_token_address_last_byte", ops=(Op(1, Pay(2, b"T", addr=201)), Op(1, Pay(2, b"T", addr=200)), Op(1, Pay(2, b"T", addr=202))))
    add("key_aqa_last_bytes", ops=tuple(Op(1, Pay(7, number=1, addrs=addrs)) for addrs in ((201, 201, 201, 201), (200, 201, 201, 201), (201, 200, 201, 201), (201, 201, 200, 201), (201, 201, 201, 200))))
    add("key_aqa_addresses", ops=(Op(1, Pay(7, number=1, addrs=(1, 2, 3, 4))), Op(1, Pay(7, number=1, addrs=(2, 2, 3, 4))), Op(1, Pay(7, number=1, addrs=(1, 3, 3, 4))), Op(1, Pay(7, number=1, addrs=(1, 2, 4, 4))), Op(1, Pay(7, number=1, addrs=(1, 2, 3, 5))), Op(2, Pay(7, number=1, addrs=(1, 2, 3, 5)))))
    add("key_inner_stub_compare", ops=(Op(1, Pay(6, inner=(1 << 63) + 2, body=2)), Op(1, Pay(6, inner=(1 << 63) + 2, body=1)), Op(2, Pay(6, inner=(1 << 63) + 2, body=2))))
    add("key_first_row_search_tall", rows=tuple(seed(Pay(4, number=index * 2)) for index in range(1, 30)), ops=(Op(1, Pay(4, number=8)), Op(1, Pay(4, number=44)), Op(2, Pay(4, number=45)), Op(2, Pay(4, number=1))))
    add("key_insert_into_seed_leaf", rows=(seed(Pay(4, number=2)), seed(Pay(4, number=6))), ops=(Op(1, Pay(4, number=4)), Op(1, Pay(4, number=1)), Op(1, Pay(4, number=9))))
    # stream
    stream = dict(ops=())

    def rate(name, *ops, **fields):
        cases.append(Case(name, "stream", ops=ops, **fields))

    def st(caller, text=b"0.05", **fields):
        return Op(caller, kind="stream", text=text, **fields)

    rate("stream_ok", st(1))
    rate("stream_not_validator", st(9))
    rate("stream_no_validators", st(1), validators=())
    rate("stream_101", st(1, b"1" * 101))
    rate("stream_100", st(1, b"1" * 100))
    rate("stream_empty_text", st(1, b""))
    rate("stream_not_validator_long", st(9, b"1" * 101))
    rate("stream_parse_error", st(1, parse=0x13F))
    rate("stream_float_fail", st(1, float_ok=False))
    rate("stream_zero", st(1, number=0.0))
    rate("stream_negative_zero", st(1, number=-0.0))
    rate("stream_one", st(1, number=1.0))
    rate("stream_over_one", st(1, number=1.0000000000000002))
    rate("stream_two", st(1, number=2.0))
    rate("stream_negative", st(1, number=-0.5))
    rate("stream_negative_one", st(1, number=-1.0))
    rate("stream_negative_big", st(1, number=-1e300))
    rate("stream_negative_subnormal", st(1, number=-5e-324))
    rate("stream_negative_top_subnormal", st(1, number=-2.2250738585072009e-308))
    rate("stream_negative_min_normal", st(1, number=-2.2250738585072014e-308))
    rate("stream_subnormal", st(1, number=5e-324))
    rate("stream_negative_max", st(1, number=-1.7976931348623157e308))
    rate("stream_max", st(1, number=1.7976931348623157e308))
    rate("stream_inf", st(1, number=float("inf")))
    rate("stream_negative_inf", st(1, number=float("-inf")))
    rate("stream_nan", st(1, number=float("nan")))
    rate("stream_replaces", st(1, number=0.1), st(1, number=0.2, now=later(T0, 60)))
    rate("stream_replace_new_fraction", st(1, number=0.1), st(1, number=0.2, now=(BASE_DATE + 16, 7, 77)))
    rate("stream_replace_keeps_old_on_range", st(1, number=0.1), st(1, number=1.5))
    rate("stream_order", st(2, number=0.2), st(1, number=0.1), st(3, number=0.3))
    rate("stream_seed_rows", st(2, number=0.25), stream=((1, to_bits(0.5), T0), (3, to_bits(0.75), T0)))
    rate("stream_seed_many", st(8, number=0.25), st(11, number=0.3), stream=tuple((index, to_bits(0.5), T0) for index in (1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 14)), validators=tuple(range(1, 16)))
    rate("stream_tall_validators", st(1), st(15), st(16), validators=tuple(range(1, 16)))
    # direct count
    row = (seed(one, voters=(1,), listed=(2,), fin=0x100),)

    def direct(name, *ops, rows=row):
        cases.append(Case(name, "count", rows=rows, ops=ops))

    def ct(caller, first, second, row=0):
        return Op(caller, kind="count", pair=(first, second), row=row)

    direct("count_first_hit", ct(1, True, True))
    direct("count_second_hit", ct(2, True, True))
    direct("count_miss", ct(3, True, True))
    direct("count_first_only_miss_second", ct(2, True, False))
    direct("count_second_only_miss_first", ct(1, False, True))
    direct("count_neither", ct(1, False, False))
    direct("count_second_only_hit", ct(2, False, True))
    direct("count_no_bucket", ct(1, True, True), rows=(seed(one),))
    direct("count_tall_sets", ct(12, True, True), ct(25, True, True), ct(16, True, True), ct(40, True, True), ct(19, True, True), rows=(seed(one, voters=tuple(range(1, 15)), listed=tuple(range(20, 34)), fin=0x100),))
    return cases


def lcg(seed_value):
    state = seed_value

    def pick(limit):
        nonlocal state
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        return (state >> 8) % limit

    return pick


def vector_cases(count):
    pick = lcg(7001)
    cases = []
    pool = vector_pool()
    for number in range(count):
        size = 1 + pick(6)
        validators = tuple(index for index in range(1, 10) if pick(3))
        allowed = tuple(index for index in range(1, 10) if pick(4))
        profiles = tuple((index, index + 16) for index in allowed if pick(5))
        active = tuple((index + 16, 1) for index in range(1, 10) if pick(4))
        stakes = tuple((index, pick(5) * 50) for index in range(1, 10) if pick(3))
        hvs = tuple(index for index in range(1, 10) if pick(3) == 0)
        q = (0.0, 0.25, 0.5, 1.0)[pick(4)]
        ops = []
        for _ in range(4 + pick(10)):
            caller = 1 + pick(9)
            if pick(5) == 0:
                ops.append(Op(caller, kind="stream", text=b"1" * (pick(4) * 40), number=(0.0, 0.25, 1.0, 1.5, -0.5)[pick(5)], parse=TAG_OK if pick(6) else 0x13F, float_ok=bool(pick(7))))
            else:
                pay = pool[pick(len(pool))]
                ops.append(Op(caller, pay, apply=TAG_OK if pick(4) else 0xEA))
        cases.append(Case("v%d" % number, "vote", allowed=allowed, profiles=profiles, active=active, stakes=stakes, hvs=hvs, hc=(q, 0.0), validators=validators, ops=tuple(ops), enabled=bool(pick(8)), allow_all=pick(9) == 0))
    return cases


def check_cases(harness, cases, reach=None):
    outcomes = []
    for at, case in enumerate(cases):
        before = set()
        if reach is not None:
            harness.machine.seen, before = set(), harness.machine.seen
        got = harness.run(case)
        if reach is not None:
            for va in harness.machine.seen:
                reach.setdefault(va, []).append(at)
            harness.machine.seen |= before
        want = spec_run(case, harness.frozen_digest)
        if got != want:
            raise EvidenceError("case %s: %r != %r" % (case.name, got, want))
        outcomes.append(got)
    return outcomes


def direct_to(image, target):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text) and start + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            hits.append(start + at)
    return hits


def slot_sites(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text) and start + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            hits.append(start + at)
    return hits


COPIES = ((HOST, 0x4CF1650), (HOST, 0x4CF1CC0), (STREAM, 0x4CF2330), (STREAM, 0x4CF2680))


def caller_rows(image):
    relative = image.relative()
    rows = []
    for slot, target, role, count in ((SLOT_BODY, BODY, "tracker_body", 3), (SLOT_STAKES, 0x336D5B0, "stake_snapshot", 2), (SLOT_ACTIVE, 0x3C10FA0, "validators_at_round", 10), (SLOT_STAKE_TEST, STAKE_TEST, "stake_test", None), (SLOT_RATIO, RATIO, "listed_ratio", None)):
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        sites = sorted(slot_sites(image, slot))
        if count is not None and len(sites) != count:
            raise EvidenceError("slot %#x has %d sites" % (slot, len(sites)))
        rows.append(("slot %#x" % slot, role, "%#x" % target, len(sites), " ".join("%#x" % site for site in sites[:12])))
    for target, role, count in ((HOST, "host", 1), (STREAM, "stream_body", 1), (COUNT, "voted_in_row", 1), (TRACK, "add_vote", 1), (QUORUM, "quorum", 2), (ROW_ENTRY, "row_entry", 2), (APPLY, "apply", None)):
        sites = sorted(direct_to(image, target))
        if count is not None and len(sites) != count:
            raise EvidenceError("%#x has %d direct calls" % (target, len(sites)))
        rows.append(("direct", role, "%#x" % target, len(sites), " ".join("%#x" % site for site in sites[:12])))
    return rows


def copy_rows(image):
    rows = []
    for primary, copy in COPIES:
        one = decode_range(image, *image.exact_fde(primary))
        two = decode_range(image, *image.exact_fde(copy))
        same = [row.op for row in one] == [row.op for row in two] and [row.size for row in one] == [row.size for row in two]
        if not same:
            raise EvidenceError("copy shape %#x" % copy)
        differs = sum(1 for left, right in zip(one, two) if left.data != right.data)
        mark = 0x2706A7B if primary == HOST else 0x270706A
        at = next(index for index, row in enumerate(one) if row.va == mark)
        shift = struct.unpack_from("<i", two[at].data, 3)[0] - struct.unpack_from("<i", one[at].data, 3)[0]
        rows.append(("%#x" % primary, "%#x" % copy, len(one), differs, "%#x" % shift, ",".join(sorted({left.op for left, right in zip(one, two) if left.data != right.data}))))
    return rows


TABLES = ((0x3D845C, "handler_gate"), (0x3D847C, "handler_clone"), (0x3ED770, "host_clone_first"), (0x3ED790, "host_clone_second"), (0x57AD5C, "key_compare"), (0x3DE198, "apply"))
VARIANT_SHAPE = (
    ("newtype String", "+8 cap, +0x10 ptr, +0x18 len", "unnamed in the rodata list; apply builds vote tag 0x34", "inference"),
    ("tuple (bool, address)", "+8 flag, +9 address", "QuarantineUser; apply builds vote tag 0x2c", "inference"),
    ("tuple (String, address)", "String, +0x20 address", "CanonicalTokenDeployer; apply writes state +0x280", "inference"),
    ("tuple (String, bool)", "String, +0x20 flag", "DisablePerpDex; word 0x800000000000000d in the serde body 0x1f4daa0", "observation"),
    ("tuple (u64, bool)", "+8 token, +0x10 flag", "AlignedQuoteToken; apply bounds the u64 by state +0x218", "inference"),
    ("tuple (String, bool)", "String, +0x20 flag", "AllowHip3GrowthMode", "inference"),
    ("nested action", "word0 is the niche of an inner enum", "forwarded to 0x2749880", "observation"),
    ("struct, 5 fields", "+8 u64, addresses +0x10 +0x24 +0x38 +0x4c", "ModifyAqav2; keys technicalStaker treasuryStaker treasuryEvmAddress evmRebalanceContract", "inference"),
)


APPLY_CALLS = ((0x2387400, 0x3331D60), (0x2387554, 0x2355F40), (0x2387481, 0x3CB0170), (0x23876B6, 0x3332380), (0x238744F, 0x274DB00), (0x23877A5, 0x3332080), (0x23875FC, 0x2749880), (0x2387760, 0x2745F50))


def first_call(image, k):
    va, target = APPLY_CALLS[k]
    base = image.offset(va)
    code = image.blob[base:base + 32]
    row = decode(lambda at, count: code[at - va:at - va + count], va)
    found = row.target if row.op == "call" else image.relative().get(row.a[4]) if row.op == "calli" else None
    if found != target:
        raise EvidenceError("apply call %#x" % va)
    return "%#x" % target


def variant_rows(image):
    rows = []
    arms = {}
    for table, name in TABLES:
        base = image.offset(table)
        arms[name] = [table + struct.unpack_from("<i", image.blob, base + 4 * k)[0] for k in range(8)]
    for k in range(8):
        shape, layout, label, status = VARIANT_SHAPE[k]
        word = "%#x" % (BASE_WORD + k) if k != 6 else "any at or below 0x8000000000000009"
        rows.append((k, word, shape, layout, label, status, "%.17g" % (WEAK if k == 6 else STRONG)) + tuple("%#x" % arms[name][k] for _, name in TABLES) + (first_call(image, k),))
    return rows


FIELDS = (
    ("prune_bucket_guard", 0x5A5F96, 18, T_GUARD, 0x3948300, "4c89fe"), ("atT", 0x5A74C5, 3, T_ROWS, 0x394833F, "498d7710"), ("active", 0x5A5FA8, 6, T_ACTIVE, 0x394835B, "410fb67750"),
    ("hvs", 0x5A74C8, 3, T_HVS, 0x39483F2, "498d5728"), ("hc", 0x5A74CB, 2, T_HC, 0x394842B, "4983c740"),
)
CONSTANTS = (
    ('pending_cap', 0x39494f6, '4983ff31', 'cmp r15, 49; jbe passes: 50 voted rows refuse with 0x36'),
    ('allow_all_read', 0x394915f, '80b89002000000', 'S +0x290: allow_all_validators skips the allowed set'),
    ('allowed_read', 0x3949184, '4c8b8020010000', 'S +0x120: allowed_validators root'),
    ('active_read', 0x3949256, '807e5000', 'tracker +0x50: active byte'),
    ('key_stride', 0x39495cd, '41c1e507', 'shl r13d, 7: tracker keys are 0x80 bytes'),
    ('value_stride', 0x3949632, '496bc770', 'imul rax, r15, 0x70: tracker values are 0x70 bytes'),
    ('value_stakes_root', 0x3949636, '488b8c03c0050000', 'value +0x40 at node +0x580: the stake snapshot root'),
    ('done_store', 0x394986a, '41c6476c01', 'value +0x6c = 1 after a finish; no row in this function reads it'),
    ('quorum_word', 0x3949528, '48b80a00000000000080', 'word0 below this value is variant 6'),
    ('quorum_table_index', 0x3949532, '4939010f9244240f', 'cmp word0; setb selects the f64 table index'),
    ('quorum_table_load', 0x3949986, 'f20f1004c8', 'movsd xmm0, table[index]'),
    ('ttl_seconds', 0x3949b93, 'ba803a0900', 'edx = 604800: 7 days added to the block time'),
    ('name_tail', 0x3949c69, '48b95f747261636b6572', 'tail of the 15 byte text l1_vote_tracker'),
    ('name_head', 0x3949c77, '48b96c315f766f74655f', 'head of the 15 byte text l1_vote_tracker'),
    ('profile_root', 0x3949962, '4c8ba350010000', 'S +0x150: validator_to_profile root'),
    ('profile_signer', 0x3949a56, '0f104500', 'row +0x40: signer read through the rbp walk'),
    ('inner_mask', 0x22cdc2e, 'be7c030000', 'esi = 0x37c: inner tags 2,3,4,5,6,8,9 pass'),
    ('inner_bit', 0x22cdc33, '480fa3ce', 'bt rsi, rcx'),
    ('handler_len_limit', 0x22cdbf9, '4883f864', 'len above 100 refuses with 0x143: variants 0 and 5'),
    ('handler_len_short', 0x22cdc08, '4883f815', 'len at or above 21 refuses with 0x140: variants 0 and 5'),
    ('handler_dex_limit', 0x22cdcb4, '4983fc64', 'len above 100 refuses with 0x143: variant 3'),
    ('handler_dex_short', 0x22cdd1e, '4983fc14', 'len above 20 refuses with 0x140: variant 3'),
    ('host_tracker', 0x2706a7b, '498db778360000', 'lea rsi, [r15 + 0x3678]: tracker in the state'),
    ('host_chain', 0x27067f7, '0fb686f2080000', 'state +0x8f2: chain byte'),
    ('stream_len_limit', 0x2706f1d, '4883fa64', 'text above 100 refuses with 0x143'),
    ('stream_map', 0x270706a, '4881c668320000', 'state +0x3268: risk_free_rate map'),
    ('stream_validators', 0x2706e5f, '488b8e08090000', 'state +0x908: validator membership root'),
    ('stake_compare', 0x33ee267, 'f20f595718', 'mulsd xmm2, [rdi + 0x18]: total times the row ratio'),
    ('stake_strict', 0x33ee26c, '660f2ec20f97c0', 'ucomisd; seta: voted must be strictly above'),
    ('bucket_finished', 0x394674d, '66c743180100', 'bucket +0x18 word = 1 at a finish'),
)
TEXTS = (b"struct ValidatorL1VoteTracker with 5 elements", b"struct ValidatorL1StreamTracker with 1 element", b"struct ValidatorL1StreamAction with 1 element", b"risk_free_rate", b"riskFreeRate", b"struct variant ValidatorL1VoteAction::ModifyAqav2 with 5 elements",
         b"tuple variant ValidatorL1VoteAction::AlignedQuoteToken with 2 elements", b"tuple variant ValidatorL1VoteAction::QuarantineUser with 2 elements", b"tuple variant ValidatorL1VoteAction::AllowHip3GrowthMode with 2 elements",
         b"tuple variant ValidatorL1VoteAction::CanonicalTokenDeployer with 2 elements", b"tuple variant ValidatorL1VoteAction::DisablePerpDex with 2 elements", b"technicalStakertreasuryStakertreasuryEvmAddressevmRebalanceContract")


def field_rows(image):
    rows = []
    for name, key, size, offset, proof, form in FIELDS:
        text = bytes(image.blob[image.offset(key):image.offset(key) + size]).decode("ascii")
        if text != name:
            raise EvidenceError("key text %s" % text)
        want = bytes.fromhex(form)
        if bytes(image.blob[image.offset(proof):image.offset(proof) + len(want)]) != want:
            raise EvidenceError("field proof %#x" % proof)
        rows.append((name, "%#x" % key, "%#x" % offset, "%#x" % proof, form))
    return rows


def constant_rows(image):
    rows = []
    for name, va, form, note in CONSTANTS:
        want = bytes.fromhex(form)
        if bytes(image.blob[image.offset(va):image.offset(va) + len(want)]) != want:
            raise EvidenceError("constant row %s" % name)
        rows.append((name, "%#x" % va, form, note))
    pair = struct.unpack_from("<dd", image.blob, image.offset(0x209510))
    if pair != (STRONG, WEAK):
        raise EvidenceError("quorum table")
    rows.append(("quorum_table", "0x209510", bytes(image.blob[image.offset(0x209510):image.offset(0x209510) + 16]).hex(), "f64 pair: index 0 is %.17g, index 1 is %.17g" % pair))
    bound = struct.unpack_from("<d", image.blob, image.offset(0x20A730))[0]
    if bound != 1.0:
        raise EvidenceError("rate bound")
    rows.append(("rate_bound", "0x20a730", bytes(image.blob[image.offset(0x20A730):image.offset(0x20A730) + 8]).hex(), "f64 %.17g: a rate strictly above it refuses with 0x140" % bound))
    head = bytes(image.blob[image.offset(0x1F4DABF):image.offset(0x1F4DABF) + 10])
    if struct.unpack_from("<Q", head, 2)[0] - 5 != BASE_WORD + 3:
        raise EvidenceError("disable perp dex word")
    rows.append(("disable_perp_dex_word", "0x1f4dabf", head.hex(), "serde body of DisablePerpDex writes this value minus 5 at 0x1f4db22: variant 3"))
    for wanted in TEXTS:
        at = image.blob.find(wanted)
        if at < 0:
            raise EvidenceError("missing text")
        rows.append(("wire_text", "%#x" % at, "", wanted.decode("ascii")))
    return rows


STATUS = (TAG_TOO_MANY, TAG_UNKNOWN, TAG_INVALID, TAG_FLOAT, TAG_INPUT, TAG_LENGTH)


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in STATUS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
        at = data.find(b"\x48\x8d\x35")
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0]
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
    return rows


def edits_for(image, rows, seen):
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


def first_failure(harness, cases):
    for case in cases:
        try:
            got = harness.run(case)
            if got != spec_run(case, harness.frozen_digest):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, TypeError, struct.error):
            return case
    return None


OPEN = "open: no named case tells this edit apart and it was not analysed further"
I, D, C = "immediate", "displacement", "condition"
CLASSES = (
    ("inner tags 2 and 3 both pass the mask, so a niche word mapped to 2 instead of 3 passes the same way", ((0x22CDC21, I),)),
    ("pointer word for a free on a path that does not free; the refusal bytes past the status are stale stack", ((0x22CDCBA, I),)),
    ("dangling pointer of an empty text: 0 instead of 1 copies nothing and is never read", tuple((va, I) for va in (0x22CDE25, 0x22CDE60, 0x22CDE8F, 0x22CDEBE, 0x270698C, 0x27069C8, 0x2706A01, 0x2706A32, 0x2706C82, 0x21E03AB))),
    ("copy of bytes past the status of a tracker refusal: the body writes only the status, so these bytes are stale stack", tuple((va, D) for va in (0x2706B6A, 0x2706B77, 0x2706B9C, 0x2706BA1, 0x2706BA6, 0x2706BAB, 0x2706BB4))),
    ("bound or pointer of the unrolled eight step tree descent: no tree here is that tall", ((0x3949335, I), (0x3949418, I), (0x33EDBD5, I), (0x33EDCB8, I), (0x33EDDD5, I), (0x33EDEB8, I), (0x33EDCA3, D), (0x33EDEA3, D))),
    ("length read at the first row of a descended leaf: index 0 is below any length", ((0x33EDE33, D),)),
    ("None test of the Option key: the niche word 0x8000000000000012 is never an action", ((0x39496C3, I), (0x39496CD, I))),
    ("one more byte in a copy of the vacant entry; that byte is not read", ((0x3949B67, I),)),
    ("low byte of the tail word of the name; the head word store rewrites that byte", ((0x3949C69, I),)),
    ("compare length 21 instead of 20: the next byte is equal in every fixture key", tuple((va, I) for va in (0x2FE2E9A, 0x2FE2ED6, 0x2FE2EFD, 0x2FE2F24, 0x2FE2F99))),
    ("arm for an absent half of the voter pair: the only caller passes two present addresses", tuple((va, I) for va in (0x3946159, 0x394615B, 0x3946249, 0x3946263, 0x3946290, 0x39463A1, 0x39463A7))),
    ("guard for a second finish in one call, which the finished byte rules out", ((0x394621D, I), (0x39468B4, I), (0x39468BC, C), (0x3946905, I))),
    ("test on a map with a zero size key: it holds at most one row", ((0x39464F4, I), (0x39464F4, D), (0x39464FC, C), (0x3946618, I), (0x3946618, D), (0x3946620, C), (0x3946753, I), (0x3946753, D), (0x3946758, C), (0x3946919, I))),
    ("scale of an index that is always 0 in a fresh node", ((0x394660F, I), (0x39466B0, I), (0x33C0A1F, I), (0x33C0A68, I))),
    ("flag written on a path where the next row rewrites it", ((0x39466BC, I),)),
    ("move of the cloned sets into the return value: the body reads word 0 and drops the rest", ((0x39467BF, I), (0x39467C8, I), (0x39467E9, D), (0x39467FA, D), (0x3946859, D), (0x394685D, D), (0x39468A5, D), (0x39468A9, D), (0x39468AD, D), (0x39469D3, D), (0x39469EF, D), (0x39469F3, D))),
    ("iterator built only for the drop stub, which frees nothing here", ((0x394140D, C), (0x39414F0, C))),
    ("both arms read the same sum for a non null stake map", ((0x33EDD36, I),)),
    ("sixth argument of the leaf insert stub, a zero size allocator reference", ((0x33C08D9, D),)),
    ("one more byte in a node allocation", ((0x33C092D, I), (0x33A7FFB, I))),
    ("parent word of a fresh root: this path never climbs from it", ((0x33C0941, I), (0x33C0941, D), (0x33A800F, I))),
    ("copy into a stack guard that only an unwind reads", tuple((va, D) for va in (0x33C0962, 0x33C096B, 0x33C0974, 0x33C097D, 0x33C0989, 0x33C098D, 0x33C0991, 0x33C09A8, 0x33C09B5, 0x33C09C2, 0x33C09D3, 0x33C09D8, 0x33C09DD))),
    ("length of a fresh node, which is 0", ((0x33C0A02, D), (0x33C0A09, I), (0x33A8031, I))),
    ("fourth return word of the row insert, unread by the body", ((0x33C0ACD, D),)),
    ("old rate returned to the stream body, which drops it unread", ((0x33A7F12, D), (0x33A7F1B, D), (0x33A807C, I), (0x33A807C, D))),
)
EXPECTED_SURVIVORS = {edit: text for text, edits in CLASSES for edit in edits}
POOL = {}
MUTANT_CASES = 30


def run_one(task):
    va, patch = task
    harness = Harness(POOL["image"], patch)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    places = POOL["reach"][va]
    places = places[::max(1, len(places) // MUTANT_CASES)]
    chosen = [POOL["cases"][at] for at in places]
    return first_failure(harness, chosen) is not None


def run_mutants(image, table, seen, cases, reach):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    POOL.update(image=image, cases=cases, reach=reach)
    rows = [(target,) + edit for target in TARGETS for edit in edits_for(image, table[target], seen)]
    tasks = [(row[1], row[3]) for row in rows]
    try:
        with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
            killed = pool.map(run_one, tasks, 8)
    except OSError:
        killed = [run_one(task) for task in tasks]
    return [(va, kind, "killed", "whole run") if dead else (va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), OPEN)) for (_, va, kind, _), dead in zip(rows, killed)]


def analyse(image, mutate=True, vectors=300):
    harness = Harness(image)
    cases = named_cases()
    reach = {}
    outcomes = check_cases(harness, cases, reach)
    seen = set(reach)
    check_cases(harness, vector_cases(vectors))
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, callers=caller_rows(image), constants=constant_rows(image), fields=field_rows(image), statuses=status_rows(image), variants=variant_rows(image), copies=copy_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, reach)
    return result


def describe(outcome):
    if outcome[0] == "panic":
        return outcome[1], " ".join(short(item) for item in outcome[2]), ",".join(str(event[0]) for event in outcome[3]), ""
    digest = hashlib.sha256(repr(outcome[3]).encode()).hexdigest()[:16]
    return "done", " ".join(short(item) for item in outcome[1]), ",".join(str(event[0]) for event in outcome[2]), digest


def short(item):
    if item[0] == "err":
        return "%#x" % item[1]
    return "%s:%d" % (item[0], item[1])


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("callers.tsv", ("reach", "role", "target", "sites", "addresses"), result["callers"])
    tsv("copies.tsv", ("function", "copy", "rows", "rows_with_other_bytes", "state_offset_shift", "operations_with_other_bytes"), result["copies"])
    tsv("constants.tsv", ("name", "address", "bytes", "note"), result["constants"])
    tsv("field-names.tsv", ("key", "key_address", "offset", "proof_address", "proof_bytes"), result["fields"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("variants.tsv", ("k", "word0", "shape", "layout", "label", "label_status", "stake_ratio") + tuple(name for _, name in TABLES) + ("apply_first_call",), result["variants"])
    tsv("outcomes.tsv", ("entry", "case", "end", "results", "events", "state_digest"), [(case.kind, case.name) + describe(outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    groups = {}
    for case in result["cases"]:
        groups[case.kind] = groups.get(case.kind, 0) + 1
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "operations": sum(len(case.ops) for case in result["cases"]), "vector_cases": result["vector_count"], "named_by_entry": groups,
    }
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
