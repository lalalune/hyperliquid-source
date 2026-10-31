#!/usr/bin/env python3
"""Pin the node #94 bridge retention step 0x374f170 and its three block step gates from ELF bytes.

On the first block of a new date the step takes the block time minus 7 days on chain byte 3 and 1 day on any
other, raises last_pruned_deposit_block_number to the highest block of a finished deposit at or before that
time, then removes every finished deposit at or below the new floor and every finished withdrawal at or before
the time. Real bytes run for the gates, the scan, both extract iterators and the B-tree removal chains on real
trees; a separately written rule list predicts every row, word and cutoff, and reached rows are mutated. No
objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/bridge_retention_prune.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
import json
import math
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
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            left -= (left >> 63) << 64
            right -= (right >> 63) << 64
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
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



PRUNE = 0x374F170
FIRST_DEPOSIT = 0x2FE0C90
FIRST_WITHDRAWAL = 0x2FE12A0
NEXT_DEPOSIT = 0x3314DD0
NEXT_WITHDRAWAL = 0x3314FF0
REMOVE_DEPOSIT = 0x2FDA610
REMOVE_WITHDRAWAL = 0x2FD6640
LEAF_DEPOSIT = 0x2FCBD60
LEAF_WITHDRAWAL = 0x2FCC6E0
FIX_DEPOSIT = (0x2FB0340, 0x2FA60E0, 0x2FAD9F0)
FIX_WITHDRAWAL = (0x2FAFEE0, 0x2FA4EE0, 0x2FABDC0)
TIME_SUB = 0x151D080
TIME_ADD = 0x15206E0
DATE_ADD = 0x151F870
SERIALIZER = 0x22155C0

NAMES = {PRUNE: "bridge_prune", FIRST_DEPOSIT: "first_edge_deposits", FIRST_WITHDRAWAL: "first_edge_withdrawals", NEXT_DEPOSIT: "extract_next_deposits", NEXT_WITHDRAWAL: "extract_next_withdrawals",
         REMOVE_DEPOSIT: "remove_kv_deposits", REMOVE_WITHDRAWAL: "remove_kv_withdrawals", LEAF_DEPOSIT: "remove_leaf_deposits", LEAF_WITHDRAWAL: "remove_leaf_withdrawals",
         FIX_DEPOSIT[0]: "merge_deposits", FIX_DEPOSIT[1]: "steal_a_deposits", FIX_DEPOSIT[2]: "steal_b_deposits", FIX_WITHDRAWAL[0]: "merge_withdrawals", FIX_WITHDRAWAL[1]: "steal_a_withdrawals", FIX_WITHDRAWAL[2]: "steal_b_withdrawals",
         TIME_SUB: "time_minus_seconds", TIME_ADD: "time_of_day_add", DATE_ADD: "date_add_days"}
TARGETS = tuple(sorted(NAMES))
MUTATED = (PRUNE, NEXT_DEPOSIT, NEXT_WITHDRAWAL, FIRST_DEPOSIT, FIRST_WITHDRAWAL, REMOVE_DEPOSIT, REMOVE_WITHDRAWAL, LEAF_DEPOSIT, LEAF_WITHDRAWAL) + FIX_DEPOSIT + FIX_WITHDRAWAL
FULL = (PRUNE, NEXT_DEPOSIT, NEXT_WITHDRAWAL)
SHARED = (TIME_SUB, TIME_ADD, DATE_ADD)

SLOT_PRUNE = 0x5773A60
SLOT_TIME_SUB = 0x576F748
SLOT_TIME_ADD = 0x576E8A8
SLOT_DATE_ADD = 0x576E8B0
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_NONE = 0x576E470
SLOT_EXPECT = 0x576E468
STOP_SLOTS = (0x576E098, 0x576E108, 0x576E118, 0x576E150, 0x576DFC8, 0x576EB38)
MARK_BASE = 0x7700000000


class Gate:
    def __init__(self, name, owner, start, skip, after, chain, bridge):
        self.name, self.owner, self.start, self.skip, self.after, self.chain, self.bridge = name, owner, start, skip, after, chain, bridge


GATES = (Gate("a", 0x22297C0, 0x2229F90, 0x222A013, 0x222A013, 0x8F2, 0x3398), Gate("b", 0x470E9A0, 0x470F170, 0x470F1F3, 0x470F1F3, 0x8F2, 0x3398), Gate("c", 0x47162D0, 0x4716FBF, 0x4716BBB, 0x4717046, 0x1372, 0x3E18))
GATE_SEQUENCE = {"a": 0, "b": 1, "c": 2}
PRUNE_SITES = (0x222A00D, 0x470F1ED, 0x4717040)

SECONDS_LONG = 0x93A80
SECONDS_SHORT = 0x15180
LONG_CHAIN = 3

B_DEPOSITS = 0x100
B_WITHDRAWALS = 0x118
B_BAL = 0x130
B_LAST = 0x138
B_SIZE = 0x140


class Layout:
    def __init__(self, name, key_at, key_size, val_at, val_size, parent, index, count, size, offset):
        self.name, self.key_at, self.key_size, self.val_at, self.val_size = name, key_at, key_size, val_at, val_size
        self.parent, self.index, self.count, self.size, self.offset = parent, index, count, size, offset


DEPOSIT_NODE = Layout("finished_deposits_data", 0, 0x40, 0x2C8, 0x28, 0x2C0, 0x480, 0x482, 0x488, B_DEPOSITS)
WITHDRAWAL_NODE = Layout("finished_withdrawal_to_time", 0, 0x20, 0x168, 0x0C, 0x160, 0x1EC, 0x1EE, 0x1F0, B_WITHDRAWALS)
LAYOUTS = (DEPOSIT_NODE, WITHDRAWAL_NODE)

# key load row, key text address, text, field load row, bridge offset; read from the serializer 0x22155c0
FIELDS = ((0x2215638, 0x3D6926, "eth_id_to_deposit_votes", None, 0), (0x2215675, 0x3D693D, "finished_deposits_data", 0x2215693, B_DEPOSITS), (0x22156B6, 0x3D6953, "withdrawal_signatures", 0x22156D4, 0x40),
          (0x22156F4, 0x3D6968, "withdrawal_finalized_votes", 0x2215712, 0x70), (0x2215732, 0x3D6982, "finished_withdrawal_to_time", 0x2215750, B_WITHDRAWALS))

ARENA = HEAP_BASE + 0x1000
USED = 0x80000
ARENA_END = HEAP_BASE + 0x70000
STATE = HEAP_BASE + 0x70000
STATE_SIZE = 0x4000
CUT_AT = HEAP_BASE + 0x200
PREV_AT = HEAP_BASE + 0x300
S_NOW = 0x60
SLICE_RSP = STACK_TOP - 0x800
FILL = 0xB7
TAG_HIGH = 0x8000000000000000


def bridge_image(scenario_fill=FILL):
    return bytes((scenario_fill + index) & 0xFF for index in range(B_SIZE))


def pack_time(value):
    return struct.pack("<iII", *value)


def deposit_key(block, seed):
    tail = bytes((seed + index) & 0xFF for index in range(0x20))
    return struct.pack("<QQQ", block, seed * 3 + 1, seed * 5 + 2) + tail + bytes([seed % 6]) + bytes(7)


def deposit_value(seed, time):
    return struct.pack("<Q", 5000000 + seed) + pack_time(time) + bytes((0x40 + seed + index) & 0xFF for index in range(20))


def withdrawal_key(seed):
    return bytes((0x20 + seed + index) & 0xFF for index in range(20)) + struct.pack("<Q", seed * 7 + 1) + bytes((seed & 0xFF,)) * 4


def deposit_order(row):
    return struct.unpack_from("<QQ", row[0])


def deposit_items(rows):
    return sorted(((deposit_key(block, seed), deposit_value(seed, time)) for seed, (block, time) in enumerate(rows)), key=deposit_order)


def withdrawal_items(rows):
    return sorted((withdrawal_key(seed), pack_time(time)) for seed, time in enumerate(rows))


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        statics[SLOT_TIME_SUB] = TIME_SUB
        statics[SLOT_TIME_ADD] = TIME_ADD
        statics[SLOT_DATE_ADD] = DATE_ADD
        statics[SLOT_PRUNE] = PRUNE
        table = {SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_NONE: self.on_none, SLOT_EXPECT: self.on_expect}
        for slot in STOP_SLOTS:
            table[slot] = self.on_stop
        for slot, hook in table.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.top = ARENA
        self.live = {}

    def expect(self, condition, text):
        if not condition:
            raise Halt("fixture check failed: " + text)

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
        self.live[at] = size
        return at

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.get(at) == size, "freed node size")
        del self.live[at]

    def on_copy(self, machine):
        self.put(machine.regs[RDI], self.data(machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = machine.regs[RDI]

    def on_none(self, machine):
        raise Panicked("iterator ended early")

    def on_expect(self, machine):
        raise Panicked(self.data(machine.regs[RDI], machine.regs[RSI]).decode("ascii"))

    def on_stop(self, machine):
        raise Halt("panic path reached")

    def build(self, layout, items, tight):
        """Build a valid tree; returns (root, height). `tight` makes nodes as small as the rules allow."""
        def capacity(height):
            return 12 ** (height + 1) - 1

        def smallest(height):
            return 5 if height == 0 else 5 + 6 * smallest(height - 1)

        def node(entries, edges=()):
            size = layout.size + 12 * 8 if edges else layout.size
            at = self.alloc(size)
            self.put(at, bytes([0xDD]) * size)
            self.write(at + layout.parent, 0)
            self.write(at + layout.count, len(entries), 2)
            for index, (key, value) in enumerate(entries):
                self.put(at + layout.key_at + index * layout.key_size, key)
                self.put(at + layout.val_at + index * layout.val_size, value)
            for index, child in enumerate(edges):
                self.write(at + layout.size + 8 * index, child)
                self.write(child + layout.parent, at)
                self.write(child + layout.index, index, 2)
            return at

        def make(rows, height, is_root):
            if height == 0:
                return node(rows)
            count = len(rows)
            least = 2 if is_root else 6
            options = [wide for wide in range(least, 13) if (count - wide + 1) // wide >= smallest(height - 1) and (count - wide + 1 + wide - 1) // wide <= capacity(height - 1)]
            self.expect(options, "no child count")
            wide = options[-1] if tight else options[0]
            share = count - wide + 1
            children, separators, at = [], [], 0
            for index in range(wide):
                take = share // wide + (1 if index < share % wide else 0)
                children.append(make(rows[at:at + take], height - 1, False))
                at += take
                if index < wide - 1:
                    separators.append(rows[at])
                    at += 1
            return node(separators, children)

        height = 0
        while capacity(height) < len(items):
            height += 1
        return make(items, height, True), height

    def walk(self, layout, at, height, is_root, nodes):
        nodes.add(at)
        count = self.read(at + layout.count, 2)
        self.expect(count <= 11, "node over full")
        self.expect(is_root or count >= 5, "node under full")
        self.expect(height == 0 or count >= 1, "empty inner node")
        rows = []
        for index in range(count + 1):
            if height:
                child = self.read(at + layout.size + 8 * index)
                self.expect(self.read(child + layout.parent) == at and self.read(child + layout.index, 2) == index, "parent link")
                rows += self.walk(layout, child, height - 1, False, nodes)
            if index < count:
                rows.append((self.data(at + layout.key_at + index * layout.key_size, layout.key_size), self.data(at + layout.val_at + index * layout.val_size, layout.val_size)))
        return rows

    def view(self, layout, nodes):
        base = self.bridge + layout.offset
        root, height, length = self.read(base), self.read(base + 8), self.read(base + 16)
        if root == 0:
            self.expect(length == 0, "length of a null root")
            return ()
        rows = self.walk(layout, root, height, True, nodes)
        self.expect(len(rows) == length, "length word")
        self.expect(rows == sorted(rows, key=deposit_order if layout is DEPOSIT_NODE else None), "key order")
        return tuple(rows)

    def dump(self):
        nodes = set()
        rows = (self.view(DEPOSIT_NODE, nodes), self.view(WITHDRAWAL_NODE, nodes))
        self.expect(nodes == set(self.live), "node left behind")
        image = self.data(self.bridge, B_SIZE)
        rest = image[:B_DEPOSITS] + image[B_BAL:B_LAST] + image[B_LAST + 8:]
        return rows, self.read(self.bridge + B_LAST), rest == self.rest

    def fresh(self, scenario):
        memory = self.machine.memory
        memory.reset(USED)
        self.top = ARENA
        self.live = {}
        self.scenario = scenario
        gate = GATES[GATE_SEQUENCE[scenario.gate]] if scenario.gate else GATES[0]
        self.gate = gate
        self.bridge = STATE + gate.bridge
        memory.put_bytes(STATE, bytes(STATE_SIZE))
        image = bridge_image()
        self.rest = image[:B_DEPOSITS] + image[B_BAL:B_LAST] + image[B_LAST + 8:]
        self.put(self.bridge, image)
        self.write(self.bridge + B_LAST, scenario.last)
        for layout, items, empty in ((DEPOSIT_NODE, deposit_items(scenario.deposits), scenario.deposit_root), (WITHDRAWAL_NODE, withdrawal_items(scenario.withdrawals), scenario.withdrawal_root)):
            base = self.bridge + layout.offset
            if items or empty == "leaf":
                root, height = self.build(layout, items, scenario.tight)
            else:
                root, height = 0, 0
            self.write(base, root)
            self.write(base + 8, height)
            self.write(base + 16, len(items))
        self.write(STATE + gate.chain, scenario.chain, 1)
        self.put(STATE + S_NOW, bytes(12))

    def slice(self, op):
        machine = self.machine
        gate = self.gate
        self.put(STATE + S_NOW, pack_time(op.now))
        self.put(PREV_AT, pack_time(op.prev))
        regs = [POISON] * 16
        regs[R12], regs[RBX], regs[R14], regs[RSP] = STATE, STATE + S_NOW, PREV_AT, SLICE_RSP
        machine.regs = regs
        pc, limit, cache = gate.start, machine.step_limit, machine.cache
        stops = (gate.skip, gate.after)
        machine.xmm = [POISON | POISON << 64] * 16
        events = []
        while pc not in stops:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(machine.read_code, pc)
                cache[pc] = row
            machine.seen.add(pc)
            machine.steps += 1
            if pc == PRUNE:
                self.expect(machine.regs[RDI] == self.bridge, "prune argument")
                events.append(("prune", self.data(machine.regs[RSI], 12)))
            pc = machine.step(row)
        return (pc,) + tuple(events)

    def perform(self, op):
        if op.prev is None:
            self.put(CUT_AT, pack_time(op.cut))
            self.machine.run(PRUNE, {RDI: self.bridge, RSI: CUT_AT})
            return ()
        stop = self.slice(op)
        return stop[1:]

    def run(self, scenario):
        self.fresh(scenario)
        trace = []
        for op in scenario.ops:
            try:
                events = self.perform(op)
            except Panicked as stop:
                trace.append(("panic", stop.args[0], ()))
                break
            trace.append((events, self.dump()))
        return trace


class Op:
    def __init__(self, cut=None, prev=None, now=None):
        self.cut, self.prev, self.now = cut, prev, now

    def __repr__(self):
        return "direct" if self.prev is None else "step"


class Scenario:
    def __init__(self, name, ops, deposits=(), withdrawals=(), last=0, gate=None, chain=0, tight=False, deposit_root="null", withdrawal_root="null"):
        self.name, self.ops = name, ops
        self.deposits, self.withdrawals = tuple(deposits), tuple(withdrawals)
        self.last, self.gate, self.chain, self.tight = last, gate, chain, tight
        self.deposit_root, self.withdrawal_root = deposit_root, withdrawal_root


# ---- the rule list; it is written from the path description, never from fixture reads ----


def days_before_year(year):
    year -= 1
    return 365 * year + year // 4 - year // 100 + year // 400


def is_leap(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def year_flags(year):
    weekday = (days_before_year(year)) % 7
    letters = (0o16, 0o17, 0o11, 0o12, 0o13, 0o14, 0o15)
    value = letters[weekday]
    return value & 7 if is_leap(year) else value


def date_word(year, ordinal):
    return (year << 13) | (ordinal << 4) | year_flags(year)


def day_number(word):
    return days_before_year(word >> 13) + ((word >> 4) & 0x1FF)


def word_of_day(number):
    year = number * 400 // 146097 + 1
    while days_before_year(year) >= number:
        year -= 1
    while days_before_year(year + 1) < number:
        year += 1
    return date_word(year, number - days_before_year(year))


FIRST_YEAR = -262143
LAST_YEAR = 262142
EXPECT_TEXT = "`NaiveDateTime - TimeDelta` overflowed"


def minus_seconds(time, seconds):
    word, secs, nanos = time
    total = day_number(word) * 86400 + secs - seconds
    number, rest = divmod(total, 86400)
    if number <= days_before_year(FIRST_YEAR):
        raise Panicked(EXPECT_TEXT)
    return word_of_day(number), rest, nanos


def time_key(time):
    return time[0], time[1], time[2]


class Model:
    def __init__(self, scenario):
        self.scenario = scenario
        self.deposits = [(block, time, seed) for seed, (block, time) in enumerate(scenario.deposits)]
        self.withdrawals = list(enumerate(scenario.withdrawals))
        self.last = scenario.last

    def prune(self, cut):
        floor = self.last
        for block, time, _ in self.deposits:
            if time_key(time) <= time_key(cut) and block > floor:
                floor = block
        self.deposits = [row for row in self.deposits if row[0] > floor]
        self.withdrawals = [row for row in self.withdrawals if time_key(row[1]) > time_key(cut)]
        self.last = floor

    def apply(self, op):
        if op.prev is None:
            self.prune(op.cut)
            return ()
        if op.prev[0] >= op.now[0]:
            return ()
        seconds = SECONDS_LONG if self.scenario.chain == LONG_CHAIN else SECONDS_SHORT
        cut = minus_seconds(op.now, seconds)
        self.prune(cut)
        return (("prune", pack_time(cut)),)

    def snapshot(self):
        deposits = tuple(sorted(((deposit_key(block, seed), deposit_value(seed, time)) for block, time, seed in self.deposits), key=deposit_order))
        withdrawals = tuple(sorted((withdrawal_key(seed), pack_time(time)) for seed, time in self.withdrawals))
        return (deposits, withdrawals), self.last, True


def spec_run(scenario):
    model = Model(scenario)
    trace = []
    for op in scenario.ops:
        try:
            events = model.apply(op)
        except Panicked as stop:
            trace.append(("panic", stop.args[0], ()))
            break
        trace.append((events, model.snapshot()))
    return trace


D0 = date_word(2026, 300)
D1 = date_word(2026, 301)
CUT = (D1, 43200, 500000000)
OLD = (D0, 43200, 500000000)
NEW = (D1, 50000, 1)
NOW = (date_word(2026, 304), 59025, 123456789)
PREV = (date_word(2026, 303), 86399, 900000000)


def step(prev=PREV, now=NOW):
    return Op(prev=prev, now=now)


def direct(cut=CUT):
    return Op(cut=cut)


def older(by):
    return minus_seconds(CUT, by)


def later(by):
    return minus_seconds(CUT, -by)


def signed_word(year, ordinal):
    return date_word(year, ordinal)


def edge_scenarios():
    out = []
    add = lambda name, **fields: out.append(Scenario(name, fields.pop("ops", [direct()]), **fields))
    add("empty_null_roots")
    add("empty_leaf_roots", deposit_root="leaf", withdrawal_root="leaf")
    add("empty_keeps_last", last=77)
    add("one_old_deposit", deposits=[(100, OLD)])
    add("one_new_deposit", deposits=[(100, NEW)])
    add("cut_equal_is_old", deposits=[(100, CUT)])
    add("cut_equal_withdrawal_is_old", withdrawals=[CUT])
    add("nanos_above_is_new", deposits=[(100, (CUT[0], CUT[1], CUT[2] + 1))], withdrawals=[(CUT[0], CUT[1], CUT[2] + 1)])
    add("nanos_below_is_old", deposits=[(100, (CUT[0], CUT[1], CUT[2] - 1))], withdrawals=[(CUT[0], CUT[1], CUT[2] - 1)])
    add("secs_above_is_new", deposits=[(100, (CUT[0], CUT[1] + 1, 0))], withdrawals=[(CUT[0], CUT[1] + 1, 0)])
    add("secs_below_is_old", deposits=[(100, (CUT[0], CUT[1] - 1, 0xFFFFFFFF))], withdrawals=[(CUT[0], CUT[1] - 1, 0xFFFFFFFF)])
    add("date_above_is_new", deposits=[(100, (D1 + 16, 0, 0))], withdrawals=[(D1 + 16, 0, 0)])
    add("date_below_is_old", deposits=[(100, (D1 - 16, 86399, 0xFFFFFFFF))], withdrawals=[(D1 - 16, 86399, 0xFFFFFFFF)])
    minus = date_word(-5, 10)
    add("negative_date_row_is_old", deposits=[(100, (minus, 1, 1))], withdrawals=[(minus, 1, 1)])
    add("negative_date_cut_keeps_positive_row", deposits=[(100, NEW)], withdrawals=[NEW], ops=[direct((minus, 1, 1))])
    add("secs_top_bit_is_unsigned", deposits=[(100, (CUT[0], 0x80000000, 0))], withdrawals=[(CUT[0], 0x80000000, 0)])
    add("nanos_top_bit_is_unsigned", deposits=[(100, (CUT[0], CUT[1], 0x80000000))], withdrawals=[(CUT[0], CUT[1], 0x80000000)])
    add("last_above_blocks_is_kept", deposits=[(100, OLD), (150, NEW)], last=500)
    add("last_between_blocks", deposits=[(100, OLD), (150, NEW), (900, NEW)], last=500)
    add("last_equal_block", deposits=[(500, OLD)], last=500)
    add("last_raised_to_highest_old", deposits=[(100, OLD), (120, OLD), (110, OLD), (900, NEW)], last=5)
    add("new_row_in_lower_block_goes", deposits=[(100, NEW), (120, OLD), (130, NEW)])
    add("new_row_in_same_block_goes", deposits=[(120, NEW), (120, OLD), (121, NEW)])
    add("old_row_in_top_block_takes_all", deposits=[(100, NEW), (110, NEW), (120, OLD)])
    add("block_top_bit_is_unsigned", deposits=[(1 << 63, OLD), (5, NEW), ((1 << 63) + 1, NEW)])
    add("block_all_ones", deposits=[(MASK[8], OLD), (5, NEW)])
    add("last_top_bit", deposits=[(5, OLD), (9, NEW)], last=1 << 63)
    add("maps_are_independent", deposits=[(100, NEW)], withdrawals=[OLD, NEW])
    add("deposits_only", deposits=[(100, OLD), (101, NEW)])
    add("withdrawals_only", withdrawals=[OLD, NEW, CUT, later(1), older(1)])
    add("second_prune_same_cut", deposits=[(100, OLD), (200, NEW)], withdrawals=[OLD, NEW], ops=[direct(), direct()])
    add("rising_cut", deposits=[(100, OLD), (200, NEW)], withdrawals=[OLD, NEW], ops=[direct((D0 - 16, 0, 0)), direct(), direct((D1, 60000, 0))])
    return out


def tree_scenarios():
    out = []
    for size in (5, 11, 12, 13, 23, 24, 40, 71, 72, 130, 143, 144, 170):
        for tight in (False, True):
            label = "%d_%s" % (size, "tight" if tight else "even")
            for keep in sorted({0, 1, size // 3, size // 2, size - 1, size}):
                rows = [(1000 + index * 3, OLD if index < size - keep else NEW) for index in range(size)]
                out.append(Scenario("deposits_%s_keep_%d" % (label, keep), [direct()], deposits=rows, tight=tight))
            patterns = (("all", lambda index: True), ("none", lambda index: False), ("first", lambda index: index < size // 2), ("last", lambda index: index >= size // 2), ("odd", lambda index: index % 2 == 1), ("even", lambda index: index % 2 == 0), ("third", lambda index: index % 3 != 0), ("middle", lambda index: size // 4 <= index < 3 * size // 4), ("ends", lambda index: index < size // 4 or index >= 3 * size // 4))
            for tag, old in patterns:
                rows = [OLD if old(index) else NEW for index in range(size)]
                out.append(Scenario("withdrawals_%s_%s" % (label, tag), [direct()], withdrawals=rows, tight=tight))
    return out


def gate_scenarios():
    out = []
    for gate in ("a", "b", "c"):
        add = lambda name, **fields: out.append(Scenario("gate_%s_%s" % (gate, name), fields.pop("ops", [step()]), gate=gate, **fields))
        now = NOW
        day = 86400
        week = 7 * day
        at = lambda seconds: minus_seconds(now, seconds)
        add("new_day_chain_0", chain=0, deposits=[(100, at(day)), (200, at(day - 1))], withdrawals=[at(day), at(day - 1)])
        add("new_day_chain_1", chain=1, deposits=[(100, at(day))], withdrawals=[at(day + 1)])
        add("new_day_chain_2", chain=2, deposits=[(100, at(day))], withdrawals=[at(week)])
        add("new_day_chain_3_day_old_stays", chain=3, deposits=[(100, at(day))], withdrawals=[at(day)])
        add("new_day_chain_3_week_edge", chain=3, deposits=[(100, at(week)), (200, at(week - 1))], withdrawals=[at(week), at(week - 1)])
        add("new_day_chain_4", chain=4, deposits=[(100, at(day))], withdrawals=[at(day)])
        add("new_day_chain_ff", chain=0xFF, deposits=[(100, at(day))], withdrawals=[at(day)])
        add("same_day_does_nothing", deposits=[(100, OLD)], withdrawals=[OLD], ops=[step(prev=(now[0], 1, 0))])
        add("same_date_later_secs", deposits=[(100, OLD)], withdrawals=[OLD], ops=[step(prev=(now[0], now[1] + 9, 0))])
        add("prev_after_now_does_nothing", deposits=[(100, OLD)], withdrawals=[OLD], ops=[step(prev=(now[0] + 16, 0, 0))])
        add("one_ordinal_step", deposits=[(100, OLD)], withdrawals=[OLD], ops=[step(prev=(now[0] - 16, 86399, 0))])
        add("many_days_gap", deposits=[(100, OLD)], withdrawals=[OLD], ops=[step(prev=(date_word(2020, 1), 0, 0))])
        add("new_year_step", deposits=[(100, OLD)], ops=[step(prev=(date_word(2026, 365), 86399, 0), now=(date_word(2027, 1), 0, 0))])
        add("leap_day_step", deposits=[(100, (date_word(2028, 59), 3600, 0))], withdrawals=[(date_word(2028, 60), 3600, 0)], ops=[step(prev=(date_word(2028, 60), 86399, 0), now=(date_word(2028, 61), 3600, 0))])
        add("year_edge_week_back", chain=3, withdrawals=[(date_word(2025, 360), 7, 0), (date_word(2025, 360), 6, 0)], ops=[step(prev=(date_word(2025, 365), 0, 0), now=(date_word(2026, 2), 7, 9))])
        add("negative_year_step", withdrawals=[(date_word(-3, 5), 1, 0)], ops=[step(prev=(date_word(-3, 6), 1, 0), now=(date_word(-3, 7), 1, 0))])
        add("nanos_carried", withdrawals=[(at(day)[0], at(day)[1], now[2]), (at(day)[0], at(day)[1], now[2] + 1)])
        add("floor_date_panics", withdrawals=[OLD], ops=[step(prev=(date_word(FIRST_YEAR, 1) - 16, 0, 0), now=(date_word(FIRST_YEAR, 1), 100, 0))])
        add("floor_date_plus_one_runs", withdrawals=[(date_word(FIRST_YEAR, 1), 100, 0)], ops=[step(prev=(date_word(FIRST_YEAR, 1), 0, 0), now=(date_word(FIRST_YEAR, 2), 100, 0))])
        add("daily_steps", deposits=[(100, at(3 * day)), (200, at(2 * day)), (300, at(day)), (400, now)], withdrawals=[at(3 * day), at(2 * day), at(day), now], ops=[step(prev=at(day + 3), now=at(2 * day - 1)), step(prev=at(day + 3), now=at(day - 1)), step(prev=at(day), now=now), step(prev=now, now=(now[0], now[1] + 1, 0))])
    return out


def named_scenarios():
    return edge_scenarios() + gate_scenarios() + tree_scenarios()


def lcg(seed):
    value = seed
    while True:
        value = (value * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield value >> 33


def vector_scenarios(count):
    source = lcg(0x3398)
    out = []
    base = (D1, 43200, 500000000)
    for index in range(count):
        size, other = next(source) % 90, next(source) % 90
        last = next(source) % 400
        rows, times = [], []
        for slot in range(size):
            block = next(source) % 400
            rows.append((block, minus_seconds(base, int(next(source) % 200) - 100)))
        for slot in range(other):
            times.append(minus_seconds(base, int(next(source) % 200) - 100))
        cuts = [direct(minus_seconds(base, int(next(source) % 120) - 20 * position)) for position in range(1 + next(source) % 3)]
        out.append(Scenario("vector_%d" % index, cuts, deposits=rows, withdrawals=times, last=last, tight=bool(next(source) & 1)))
    return out


def describe(trace):
    parts = []
    for step_row in trace:
        if step_row[0] == "panic":
            parts.append("panic")
            continue
        events, (rows, last, same) = step_row
        parts.append("%s%d+%d last=%#x" % ("prune " if events else "", len(rows[0]), len(rows[1]), last))
    return " ; ".join(parts)


def check_all(harness, scenarios):
    done = []
    for scenario in scenarios:
        got = harness.run(scenario)
        want = spec_run(scenario)
        if got != want:
            raise EvidenceError("scenario %s differs" % scenario.name)
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
    return hits


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


def gate_rows(image, gate):
    end = gate.after if gate.after > gate.start else gate.skip
    return decode_range(image, gate.start, end)


MUTANT_SCENARIOS = 60
WORKERS = 4
SURVIVED = "class: equal outcome on every scenario that reaches the row, such as a spill slot, a register choice or a word no rule reads"
MUTANT_STATE = {}


def mutant_job(job):
    va, kind, patch = job
    image, order, reach, wants = MUTANT_STATE["image"], MUTANT_STATE["order"], MUTANT_STATE["reach"], MUTANT_STATE["wants"]
    picked = [scenario for scenario in order if va in reach[scenario.name]][:MUTANT_SCENARIOS]
    harness = Harness(image, patch)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    hit = first_failure(harness, picked, [wants[scenario.name] for scenario in picked])
    return va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else SURVIVED


def run_mutants(image, table, seen, scenarios):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    wants, reach, cost = {}, {}, {}
    for scenario in scenarios:
        control.machine.seen = set()
        before = control.machine.steps
        got = control.run(scenario)
        want = spec_run(scenario)
        if got != want:
            raise EvidenceError("an unedited image fails on %s" % scenario.name)
        wants[scenario.name], reach[scenario.name], cost[scenario.name] = want, control.machine.seen, control.machine.steps - before
    order = sorted(scenarios, key=lambda item: (cost[item.name], item.name))
    jobs = []
    for key in sorted(table, key=str):
        rows = table[key]
        jobs += edits_for(image, rows, seen, key in FULL or isinstance(key, str))
    MUTANT_STATE.update(image=image, order=order, reach=reach, wants=wants)
    with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
        return pool.map(mutant_job, jobs, 8)


KEY_ROWS = ((0x2229F93, "date word of the previous time against the block time", "cmp"), (0x2229F95, "not a later date: skip the prune", "jcc"), (0x2229FB5, "chain byte against 3", "cmp"), (0x2229FB7, "604800 seconds", "mov"), (0x2229FBC, "86400 seconds", "mov"), (0x2229FC1, "the long span only on 3", "cmov"), (0x2229FD4, "time minus span", "calli"), (0x2229FDF, "date word 0 is None: panic", "jcc"), (0x2229FE5, "bridge at state +0x3398", "lea"), (0x222A00D, "prune through the slot", "calli"),
            (0x374F187, "read last_pruned_deposit_block_number", "mov"), (0x374F1EA, "block word against the running floor", "cmp"), (0x374F1ED, "floor rises, unsigned", "cmov"), (0x374F3A8, "row date word", "cmp"), (0x374F3B0, "signed date", "set"), (0x374F3E5, "row seconds", "cmp"), (0x374F3E9, "unsigned seconds", "set"), (0x374F3EF, "row nanoseconds", "cmp"), (0x374F3F3, "equal time counts as old", "jcc"), (0x374F4BB, "deposit iterator ends on byte +0x38 = 6", "cmp"), (0x374F56B, "withdrawal iterator ends on date word 0", "cmp"), (0x374F572, "store the floor", "mov"),
            (0x3314E56, "deposit key block word against the floor", "cmp"), (0x3314E59, "at or below the floor: remove", "jcc"), (0x3315077, "withdrawal time date word", "cmp"), (0x331507A, "signed date", "set"), (0x331508F, "withdrawal seconds", "cmp"), (0x3315093, "unsigned seconds", "set"), (0x331509D, "withdrawal nanoseconds", "cmp"), (0x33150A1, "strictly later stays", "jcc"))


def key_rows(image, rows_by_va):
    out = []
    for va, text, op in KEY_ROWS:
        row = rows_by_va.get(va)
        if row is None or row.op != op:
            raise EvidenceError("row %#x is %s" % (va, row.op if row else None))
        out.append(("%#x" % image.fde(va)[0], "%#x" % va, bytes(row.data).hex(), op, text))
    return out


def field_rows(image):
    start, end = image.exact_fde(SERIALIZER)
    rows = {row.va: row for row in decode_range(image, start, end)}
    out = []
    for key_row, text_at, text, field_row, offset in FIELDS:
        row = rows.get(key_row)
        if row is None or row.op != "lea":
            raise EvidenceError("key row %#x moved" % key_row)
        target = row.b[4]
        data = bytes(image.blob[image.offset(text_at):image.offset(text_at) + len(text)])
        if target != text_at or data != text.encode("ascii"):
            raise EvidenceError("key text at %#x moved" % text_at)
        if field_row is None:
            out.append(("%#x" % key_row, text, "none", "+0", "the first field, passed in the base register"))
            continue
        row = rows.get(field_row)
        if row is None or row.op != "lea" or row.b[4] != offset:
            raise EvidenceError("field row %#x moved" % field_row)
        out.append(("%#x" % key_row, text, "%#x" % field_row, "+%#x" % offset, "lea of the field"))
    return out


def gate_table(image):
    out = []
    for gate, site in zip(GATES, PRUNE_SITES):
        rows = gate_rows(image, gate)
        data = b"".join(bytes(row.data) for row in rows)
        if struct.pack("<I", gate.chain) not in data or struct.pack("<I", gate.bridge) not in data or struct.pack("<I", SECONDS_LONG) not in data or struct.pack("<I", SECONDS_SHORT) not in data:
            raise EvidenceError("gate %s constants moved" % gate.name)
        if image.fde(gate.start)[0] != gate.owner or image.fde(site)[0] != gate.owner:
            raise EvidenceError("gate %s owner moved" % gate.name)
        out.append((gate.name, "%#x" % gate.owner, "%#x" % gate.start, "%#x" % gate.skip, "%#x" % gate.after, "%#x" % site, "+%#x" % gate.chain, "+%#x" % gate.bridge, len(rows)))
    return out


def slot_rows(image, through):
    relative = image.relative()
    rows = []
    for slot, role, target in ((SLOT_PRUNE, "bridge prune", PRUNE), (SLOT_TIME_SUB, "time minus seconds", TIME_SUB), (SLOT_TIME_ADD, "time of day add", TIME_ADD), (SLOT_DATE_ADD, "date add days", DATE_ADD)):
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target, len(through[slot])))
    return rows


def site_rows(image, through):
    if through[SLOT_PRUNE] != list(PRUNE_SITES):
        raise EvidenceError("prune sites moved")
    direct = direct_sites(image, (PRUNE, FIRST_DEPOSIT, FIRST_WITHDRAWAL, NEXT_DEPOSIT, NEXT_WITHDRAWAL, REMOVE_DEPOSIT, REMOVE_WITHDRAWAL, LEAF_DEPOSIT, LEAF_WITHDRAWAL))
    rows = [("%#x" % PRUNE, "through slot", " ".join("%#x" % site for site in PRUNE_SITES), " ".join("%#x" % image.fde(site)[0] for site in PRUNE_SITES))]
    for target in (PRUNE, FIRST_DEPOSIT, FIRST_WITHDRAWAL, NEXT_DEPOSIT, NEXT_WITHDRAWAL, REMOVE_DEPOSIT, REMOVE_WITHDRAWAL, LEAF_DEPOSIT, LEAF_WITHDRAWAL):
        rows.append(("%#x" % target, "direct", " ".join("%#x" % site for site in direct[target]) or "none", " ".join("%#x" % image.fde(site)[0] for site in direct[target]) or "none"))
    return rows


def constant_rows(image):
    return [("%#x" % at, bytes(image.blob[image.offset(at):image.offset(at) + size]).hex(), role, value) for at, size, role, value in ((0x2229FB7, 5, "long span, chain byte 3", "604800 s, 7 days"), (0x2229FBC, 5, "short span, every other chain byte", "86400 s, 1 day"), (0x374F4BB, 8, "deposit iterator end byte", "6"), (0x222ADD6, 7, "panic text load", EXPECT_TEXT.replace("`", "")))]


def panic_text(image):
    row = decode(lambda va, count: bytes(image.blob[image.offset(va):image.offset(va) + count]), 0x222ADD6)
    target = row.b[4]
    return bytes(image.blob[image.offset(target):image.offset(target) + len(EXPECT_TEXT)]).decode("ascii")


def analyse(image, mutate=True, vectors=200):
    harness = Harness(image)
    named = check_all(harness, named_scenarios())
    generated = vector_scenarios(vectors)
    check_all(harness, generated)
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    gates = {gate.name: gate_rows(image, gate) for gate in GATES}
    every = {row.va: row for rows in list(table.values()) + list(gates.values()) for row in rows}
    unreached = {NAMES[target]: [row.va for row in rows if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target, rows in table.items()}
    for name, rows in gates.items():
        unreached["gate_" + name] = [row.va for row in rows if row.va not in seen and row.op not in ("int3", "nop", "ud2")]
    if panic_text(image) != EXPECT_TEXT:
        raise EvidenceError("panic text moved")
    through = slot_sites(image, (SLOT_PRUNE, SLOT_TIME_SUB, SLOT_TIME_ADD, SLOT_DATE_ADD))
    result = dict(table=table, gates=gates, named=named, vector_count=vectors, unreached=unreached, keys=key_rows(image, every), fields=field_rows(image), gate_table=gate_table(image), slots=slot_rows(image, through), sites=site_rows(image, through), constants=constant_rows(image))
    if mutate:
        focus = {target: table[target] for target in MUTATED}
        focus.update(gates)
        result["mutations"] = run_mutants(image, focus, seen, [scenario for scenario, _ in named] + generated[:40])
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table = result["table"]
    rows = [(NAMES[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in TARGETS for row in table[target]]
    rows += [("gate_" + name, "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for name, items in sorted(result["gates"].items()) for row in items]
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), rows)
    reach = result["unreached"]
    tsv("path.tsv", ("name", "address", "end", "rows", "unreached_rows", "role"), [(NAMES[target], "%#x" % target, "%#x" % (table[target][-1].va + table[target][-1].size), len(table[target]), len(reach[NAMES[target]]), "shared time helper, run, not edited" if target in SHARED else "run and edited") for target in TARGETS])
    tsv("unreached.tsv", ("function", "row"), [(name, "%#x" % va) for name in sorted(reach) for va in reach[name]])
    tsv("gate-copies.tsv", ("copy", "function", "start", "skip_stop", "after_stop", "prune_site", "chain_byte", "bridge", "rows"), result["gate_table"])
    tsv("fields.tsv", ("key_row", "serde_name", "field_row", "bridge_offset", "note"), result["fields"])
    tsv("node-layouts.tsv", ("map", "key_at", "key_size", "value_at", "value_size", "parent", "parent_index", "count", "leaf_size"), [(item.name, "%#x" % item.key_at, "%#x" % item.key_size, "%#x" % item.val_at, "%#x" % item.val_size, "%#x" % item.parent, "%#x" % item.index, "%#x" % item.count, "%#x" % item.size) for item in LAYOUTS])
    tsv("slots.tsv", ("slot", "role", "relative_target", "call_sites"), result["slots"])
    tsv("call-sites.tsv", ("function", "kind", "site_list", "caller_functions"), result["sites"])
    tsv("constants.tsv", ("at", "bytes", "role", "value"), result["constants"])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    tsv("scenarios.tsv", ("scenario", "operations", "outcome"), [(scenario.name, len(scenario.ops), describe(trace)) for scenario, trace in result["named"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(TARGETS), "gate_copies": len(GATES), "instructions": sum(len(items) for items in table.values()) + sum(len(items) for items in result["gates"].values()), "named_scenarios": len(named), "named_operations": sum(len(scenario.ops) for scenario, _ in named), "vector_scenarios": result["vector_count"], "unreached_rows": sum(len(items) for items in reach.values())}
    if "mutations" in result:
        items = result["mutations"]
        summary["mutations"] = {"total": len(items), "killed": sum(1 for item in items if item[2] == "killed"), "survived": sum(1 for item in items if item[2] == "survived")}
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
