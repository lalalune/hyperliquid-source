#!/usr/bin/env python3
"""Pin the node #94 VoteGlobal arms that set the bridge: fee, voter toggles, listed set, withdrawal flags.

Case 16 stores bridge2_withdraw_fee in the first dex, case 17 walks a capped map of voter keys and inserts or
removes each one, case 95 replaces the listed 20-byte set that the deposit and L1 hash votes read, and case 76
selectors 1 and 5 write the two bytes that the withdraw3 gate reads, where clearing the first also clears oaw.
Real bytes run from the entry of the apply function on real trees; a separately written rule list predicts
every status, row and byte, and reached rows are mutated. No objdump or readelf output is parsed and the binary
is never executed. Standard library only.

    python3 tools/bridge_settings_votes.py --out <dir>
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
HEAP_SIZE = 0x200000
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



VOTE = 0x2355F40
CHECK_TOGGLES = 0x1E802C0
CHECK_LIST = 0x1E7FA70
NEXT_TOGGLE = 0x2872CC0
SET_INSERT = 0x2850460
SET_SPLIT = 0x1AEF670
SET_REMOVE = 0x2867A60
REMOVE_KV = 0x1B23590
REMOVE_LEAF = 0x1B16740
FIXES = (0x1AF9580, 0x1AFB860, 0x1B01650)
DRAIN_LIST = 0x286D260
DROP_LIST = 0x28A8AC0
TWIN = 0x4CAA870
CALLERS = (0x2387390, 0x2704D90)

NAMES = {VOTE: "vote_global_apply", CHECK_TOGGLES: "toggle_map_cap", CHECK_LIST: "list_set_cap", NEXT_TOGGLE: "toggle_next", SET_INSERT: "voter_set_insert", SET_SPLIT: "voter_set_split", SET_REMOVE: "voter_set_remove", REMOVE_KV: "voter_remove_kv", REMOVE_LEAF: "voter_remove_leaf",
         FIXES[0]: "voter_fix_a", FIXES[1]: "voter_fix_b", FIXES[2]: "voter_merge", DRAIN_LIST: "list_set_drain_next", DROP_LIST: "list_set_drop"}
TARGETS = tuple(sorted(NAMES))
MUTATED = (VOTE, CHECK_TOGGLES, CHECK_LIST, NEXT_TOGGLE, SET_INSERT, SET_SPLIT, SET_REMOVE, REMOVE_KV, REMOVE_LEAF) + FIXES
FULL = (VOTE, CHECK_TOGGLES, CHECK_LIST)
PARTIAL = (VOTE,)

SLOT_DEX = 0x5773D80
SLOT_RECORDER = 0x5773190
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
STOP_SLOTS = (0x576E470, 0x576E098, 0x576E108, 0x576E020, 0x576E2E0)
MARK_BASE = 0x7700000000

CASE_TABLE = 0x3DD1B8
SELECTOR_TABLE = 0x3DD380
CASE_BASE = 0x12
CASE_FEE, CASE_TOGGLES, CASE_FLAGS, CASE_LIST = 16, 17, 76, 95
ARM_FEE, ARM_TOGGLES, ARM_FLAGS, ARM_LIST = 0x2356C45, 0x235815D, 0x23582DA, 0x2359474
SELECTOR_HALT, SELECTOR_OAW = 1, 5
ARM_HALT, ARM_OAW = 0x235B43A, 0x235B460
LOCATION_HALT = 0x56A2F98

TAG_OK = 0x186
TAG_LIMIT = 0x13F
TAG_TOO_MANY = 0x143
LIMIT = 0x0CCCCCCCCCCCCCCC
CAP = 10000

S_DEX_LIST = 0x5B8
S_HALT = 0x31A2
S_OAW = 0x34D8
S_LIST = 0x36A0
S_VOTERS = 0x3898
D_FEE = 0x250

STATE_SIZE = 0x4000
STATUS_TABLE = 0x59A8D0


class Layout:
    def __init__(self, name, key_at, key_size, val_at, val_size, parent, index, count, size):
        self.name, self.key_at, self.key_size, self.val_at, self.val_size = name, key_at, key_size, val_at, val_size
        self.parent, self.index, self.count, self.size = parent, index, count, size


TOGGLE_NODE = Layout("action toggle map", 0, 0x20, 0x16C, 1, 0x160, 0x168, 0x16A, 0x178)
VOTER_NODE = Layout("voter set", 0, 0x20, 0, 0, 0x160, 0x168, 0x16A, 0x170)
LIST_NODE = Layout("20-byte set", 8, 0x14, 0, 0, 0, 0xE4, 0xE6, 0xE8)
LAYOUTS = (TOGGLE_NODE, VOTER_NODE, LIST_NODE)

ARENA = HEAP_BASE + 0x80000
USED = HEAP_SIZE
STATE = HEAP_BASE + 0x70000
ARENA_END = HEAP_BASE + HEAP_SIZE
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x300
DEX = HEAP_BASE + 0x500
FEE_BEFORE = 0x1122334455667788
LONG_STEP_LIMIT = 8000000
MUTANT_STEP_LIMIT = 250000


def voter_key(seed):
    return bytes((0x10 + (seed * 37 >> (index % 3 * 4)) + index) & 0xFF for index in range(0x20))


def list_key(seed):
    return bytes((0x31 + (seed * 53 >> (index % 3 * 4)) + index) & 0xFF for index in range(20))


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        table = {SLOT_DEX: self.on_dex, SLOT_RECORDER: self.on_recorder, SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare}
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

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.get(at) == size, "freed node size")
        del self.live[at]

    def on_copy(self, machine):
        self.put(machine.regs[RDI], self.data(machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = machine.regs[RDI]

    def on_compare(self, machine):
        left, right = self.data(machine.regs[RDI], machine.regs[RDX]), self.data(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_stop(self, machine):
        raise Halt("panic path reached")

    def on_dex(self, machine):
        self.expect(machine.regs[RDI] == STATE + S_DEX_LIST and machine.regs[RSI] == 0, "first dex arguments")
        machine.regs[RAX] = DEX

    def on_recorder(self, machine):
        self.events.append(("recorder", machine.regs[RDI], machine.regs[RSI]))

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
                if layout.val_size:
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
            options = [wide for wide in range(least, 13) if (count - wide + 1) // wide >= smallest(height - 1) and (count + wide - 1 - wide + 1) // wide <= capacity(height - 1)]
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

    def tree(self, at, layout, items, tight):
        if items:
            root, height = self.build(layout, items, tight)
        else:
            root, height = 0, 0
        self.write(at, root)
        self.write(at + 8, height)
        self.write(at + 16, len(items))

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
                rows.append(self.data(at + layout.key_at + index * layout.key_size, layout.key_size))
        return rows

    def view(self, at, layout, nodes):
        root, height, length = self.read(at), self.read(at + 8), self.read(at + 16)
        if root == 0:
            return (), length
        rows = self.walk(layout, root, height, True, nodes)
        self.expect(len(rows) == length, "length word")
        self.expect(rows == sorted(rows), "key order")
        return tuple(rows), length

    def dump(self):
        nodes = set()
        voters = self.view(STATE + S_VOTERS, VOTER_NODE, nodes)
        listed = self.view(STATE + S_LIST, LIST_NODE, nodes)
        self.expect(nodes == set(self.live), "node left behind")
        return voters, listed, self.read(DEX + D_FEE), self.read(STATE + S_HALT, 1), self.read(STATE + S_OAW, 1)

    def fresh(self, scenario):
        memory = self.machine.memory
        memory.reset(USED)
        self.top = ARENA
        self.live = {}
        self.scenario = scenario
        memory.put_bytes(STATE, bytes(STATE_SIZE))
        self.put(DEX, bytes(0x300))
        self.write(DEX + D_FEE, FEE_BEFORE)
        self.write(STATE + S_HALT, scenario.halt, 1)
        self.write(STATE + S_OAW, scenario.oaw, 1)
        self.tree(STATE + S_VOTERS, VOTER_NODE, [(key, b"") for key in sorted(scenario.voters)], scenario.tight)
        self.tree(STATE + S_LIST, LIST_NODE, [(key, b"") for key in sorted(scenario.listed)], scenario.tight)

    def perform(self, op):
        memory = self.machine.memory
        memory.put_bytes(OUT, bytes([0xEE]) * 0x70)
        memory.put_bytes(ACTION, bytes([0xCC]) * 0x60)
        self.events = []
        self.write(ACTION, CASE_BASE + op.case)
        if op.case == CASE_FEE:
            self.write(ACTION + 8, op.value)
        elif op.case == CASE_FLAGS:
            self.write(ACTION + 8, op.selector, 1)
            self.write(ACTION + 9, op.value, 1)
        elif op.case == CASE_TOGGLES:
            self.tree(ACTION + 8, TOGGLE_NODE, [(key, bytes([flag])) for key, flag in sorted(op.rows)], op.tight)
        else:
            self.tree(ACTION + 8, LIST_NODE, [(key, b"") for key in sorted(op.rows)], op.tight)
            if op.declared is not None:
                self.write(ACTION + 8 + 16, op.declared)
        self.machine.run(VOTE, {RDI: OUT, RSI: ACTION, RDX: STATE})
        tag = self.read(OUT, 2)
        view = (tag,)
        if tag == TAG_LIMIT:
            view = (tag, self.read(OUT + 8))
        return view, tuple(self.events)

    def run(self, scenario):
        self.fresh(scenario)
        trace = []
        if scenario.long and self.machine.step_limit < LONG_STEP_LIMIT:
            saved, self.machine.step_limit = self.machine.step_limit, LONG_STEP_LIMIT
        else:
            saved = None
        try:
            for op in scenario.ops:
                view, events = self.perform(op)
                trace.append((view, events, self.dump()))
        finally:
            if saved is not None:
                self.machine.step_limit = saved
        return trace


class Op:
    def __init__(self, case, value=0, selector=0, rows=(), tight=False, declared=None):
        self.case, self.value, self.selector, self.rows, self.tight, self.declared = case, value, selector, tuple(rows), tight, declared

    def __repr__(self):
        return "case %d" % self.case


class Scenario:
    def __init__(self, name, ops, voters=(), listed=(), halt=0, oaw=0, tight=False, long=False):
        self.name, self.ops = name, ops
        self.voters, self.listed = tuple(voters), tuple(listed)
        self.halt, self.oaw, self.tight, self.long = halt, oaw, tight, long


# ---- the rule list; it is written from the path description, never from fixture reads ----


class Model:
    def __init__(self, scenario):
        self.voters = set(scenario.voters)
        self.listed = set(scenario.listed)
        self.listed_length = len(self.listed)
        self.fee = FEE_BEFORE
        self.halt, self.oaw = scenario.halt, scenario.oaw

    def apply(self, op):
        if op.case == CASE_FEE:
            if op.value >= LIMIT:
                return (TAG_LIMIT, op.value), ()
            self.fee = op.value
            return (TAG_OK,), ()
        if op.case == CASE_FLAGS:
            bit = op.value & 1
            if op.selector == SELECTOR_OAW:
                self.oaw = bit
                return (TAG_OK,), ()
            self.halt = bit
            if bit:
                return (TAG_OK,), (("recorder", 3, LOCATION_HALT),)
            self.oaw = 0
            return (TAG_OK,), ()
        declared = len(op.rows) if op.declared is None else op.declared
        if declared > CAP:
            return (TAG_TOO_MANY,), ()
        if op.case == CASE_TOGGLES:
            for key, flag in sorted(op.rows):
                if flag:
                    self.voters.add(key)
                else:
                    self.voters.discard(key)
            return (TAG_OK,), ()
        self.listed = set(op.rows)
        self.listed_length = declared
        return (TAG_OK,), ()

    def snapshot(self):
        return (tuple(sorted(self.voters)), len(self.voters)), (tuple(sorted(self.listed)), self.listed_length), self.fee, self.halt, self.oaw


def spec_run(scenario):
    model = Model(scenario)
    trace = []
    for op in scenario.ops:
        view, events = model.apply(op)
        trace.append((view, events, model.snapshot()))
    return trace


def voters(count, start=0):
    return [voter_key(start + seed) for seed in range(count)]


def listed(count, start=0):
    return [list_key(start + seed) for seed in range(count)]


def fee_scenarios():
    return [Scenario("fee_zero", [Op(CASE_FEE, 0)]), Scenario("fee_one_usdc", [Op(CASE_FEE, 1000000)]), Scenario("fee_limit_minus_one", [Op(CASE_FEE, LIMIT - 1)]), Scenario("fee_limit", [Op(CASE_FEE, LIMIT)]), Scenario("fee_above_limit", [Op(CASE_FEE, LIMIT + 1)]), Scenario("fee_top_bit", [Op(CASE_FEE, 1 << 63)]),
            Scenario("fee_two_votes", [Op(CASE_FEE, 7), Op(CASE_FEE, 9)]), Scenario("fee_refused_keeps_old", [Op(CASE_FEE, 7), Op(CASE_FEE, LIMIT)])]


def flag_scenarios():
    out = []
    for halt in (0, 1):
        for oaw in (0, 1):
            for value in (0, 1, 2, 3, 0xFF, 0xFE):
                out.append(Scenario("halt_from_%d%d_to_%x" % (halt, oaw, value), [Op(CASE_FLAGS, value, SELECTOR_HALT)], halt=halt, oaw=oaw))
                out.append(Scenario("oaw_from_%d%d_to_%x" % (halt, oaw, value), [Op(CASE_FLAGS, value, SELECTOR_OAW)], halt=halt, oaw=oaw))
    out.append(Scenario("halt_on_oaw_on_halt_off", [Op(CASE_FLAGS, 1, SELECTOR_HALT), Op(CASE_FLAGS, 1, SELECTOR_OAW), Op(CASE_FLAGS, 0, SELECTOR_HALT)]))
    out.append(Scenario("oaw_set_with_no_halt_stays", [Op(CASE_FLAGS, 1, SELECTOR_OAW), Op(CASE_FLAGS, 1, SELECTOR_HALT)]))
    return out


def toggle_scenarios():
    base = voters(40)
    out = [Scenario("toggle_empty_map_empty_set", [Op(CASE_TOGGLES)]), Scenario("toggle_insert_one", [Op(CASE_TOGGLES, rows=[(voter_key(1), 1)])]), Scenario("toggle_remove_missing_from_empty", [Op(CASE_TOGGLES, rows=[(voter_key(1), 0)])]), Scenario("toggle_insert_present", [Op(CASE_TOGGLES, rows=[(voter_key(1), 1)])], voters=[voter_key(1)]),
           Scenario("toggle_remove_present", [Op(CASE_TOGGLES, rows=[(voter_key(1), 0)])], voters=[voter_key(1)]), Scenario("toggle_remove_missing", [Op(CASE_TOGGLES, rows=[(voter_key(2), 0)])], voters=[voter_key(1)]), Scenario("toggle_flag_two_inserts", [Op(CASE_TOGGLES, rows=[(voter_key(1), 2)])]), Scenario("toggle_flag_ff_inserts", [Op(CASE_TOGGLES, rows=[(voter_key(1), 0xFF)])]),
           Scenario("toggle_mixed", [Op(CASE_TOGGLES, rows=[(key, index % 2) for index, key in enumerate(base[:20])])], voters=base[10:30]), Scenario("toggle_last_byte_differs", [Op(CASE_TOGGLES, rows=[(voter_key(1)[:31] + bytes([voter_key(1)[31] ^ 1]), 0)])], voters=[voter_key(1)]), Scenario("toggle_first_byte_differs", [Op(CASE_TOGGLES, rows=[(bytes([voter_key(1)[0] ^ 1]) + voter_key(1)[1:], 1)])], voters=[voter_key(1)]),
           Scenario("toggle_empty_map_keeps_set", [Op(CASE_TOGGLES)], voters=base[:12]), Scenario("toggle_two_votes", [Op(CASE_TOGGLES, rows=[(key, 1) for key in base[:15]]), Op(CASE_TOGGLES, rows=[(key, 0) for key in base[:15]])])]
    for size in (5, 11, 12, 13, 24, 60, 90, 145, 200, 320):
        for tight in (False, True):
            label = "%d_%s" % (size, "tight" if tight else "even")
            rows = voters(size)
            out.append(Scenario("toggle_grow_%s" % label, [Op(CASE_TOGGLES, rows=[(key, 1) for key in rows], tight=tight)]))
            out.append(Scenario("toggle_shrink_%s" % label, [Op(CASE_TOGGLES, rows=[(key, 0) for key in rows], tight=tight)], voters=rows, tight=tight))
            out.append(Scenario("toggle_half_%s" % label, [Op(CASE_TOGGLES, rows=[(key, index & 1) for index, key in enumerate(rows)], tight=tight)], voters=rows, tight=tight))
            out.append(Scenario("toggle_third_%s" % label, [Op(CASE_TOGGLES, rows=[(key, 0) for index, key in enumerate(sorted(rows)) if index % 3], tight=tight)], voters=rows, tight=tight))
            out.append(Scenario("toggle_tail_%s" % label, [Op(CASE_TOGGLES, rows=[(key, 0) for key in sorted(rows)[size // 3:]], tight=tight)], voters=rows, tight=tight))
    out.append(Scenario("toggle_cap_exact", [Op(CASE_TOGGLES, rows=[(key, 0) for key in voters(CAP)])], long=True))
    out.append(Scenario("toggle_cap_over", [Op(CASE_TOGGLES, rows=[(key, 1) for key in voters(CAP + 1)])], voters=voters(3), long=True))
    return out


def list_scenarios():
    out = [Scenario("list_empty_on_empty", [Op(CASE_LIST)]), Scenario("list_empty_clears", [Op(CASE_LIST)], listed=listed(9)), Scenario("list_one", [Op(CASE_LIST, rows=listed(1))]), Scenario("list_replaces_not_merges", [Op(CASE_LIST, rows=listed(3, 100))], listed=listed(3)), Scenario("list_same_rows", [Op(CASE_LIST, rows=listed(3))], listed=listed(3)), Scenario("list_two_votes", [Op(CASE_LIST, rows=listed(3)), Op(CASE_LIST, rows=listed(14, 7))]),
           Scenario("list_over_cap_keeps_old", [Op(CASE_LIST, rows=listed(CAP + 1))], listed=listed(3), long=True), Scenario("list_cap_exact", [Op(CASE_LIST, rows=listed(CAP))], listed=listed(5), long=True)]
    for size in (5, 11, 12, 24, 90, 145, 200, 900):
        out.append(Scenario("list_old_%d" % size, [Op(CASE_LIST, rows=listed(4, 500))], listed=listed(size)))
        out.append(Scenario("list_new_%d" % size, [Op(CASE_LIST, rows=listed(size))], listed=listed(4, 500), tight=True))
    return out


def named_scenarios():
    return fee_scenarios() + flag_scenarios() + toggle_scenarios() + list_scenarios()


def lcg(seed):
    value = seed
    while True:
        value = (value * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield value >> 33


def vector_scenarios(count):
    source = lcg(0x36A0)
    out = []
    for index in range(count):
        present = [voter_key(next(source) % 150) for _ in range(next(source) % 100)]
        rows = {}
        for _ in range(next(source) % 100):
            rows[voter_key(next(source) % 150)] = next(source) % 3
        again = {}
        for _ in range(next(source) % 60):
            again[voter_key(next(source) % 150)] = next(source) % 2
        old = [list_key(next(source) % 200) for _ in range(next(source) % 80)]
        new = [list_key(next(source) % 200) for _ in range(next(source) % 80)]
        ops = [Op(CASE_TOGGLES, rows=rows.items(), tight=bool(next(source) & 1)), Op(CASE_LIST, rows=set(new)), Op(CASE_TOGGLES, rows=again.items()), Op(CASE_FLAGS, next(source) & 3, next(source) % 2 * 4 + 1), Op(CASE_FEE, (next(source) << 31 | next(source)) << 1)]
        out.append(Scenario("vector_%d" % index, ops, voters=set(present), listed=set(old), tight=bool(next(source) & 1), halt=next(source) & 1, oaw=next(source) & 1))
    return out


def describe(trace):
    parts = []
    for view, events, state in trace:
        parts.append("%#x %d+%d" % (view[0], state[0][1], state[1][1]) + (" fee=%#x halt=%d oaw=%d" % state[2:]) + (" recorder" if events else ""))
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


MUTANT_SCENARIOS = 40
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


KEY_ROWS = ((0x2355F5A, "case is the raw tag minus 0x12", "lea"), (0x2355F7D, "main jump", "jmpi"), (0x2356C56, "fee limit", "jcc"), (0x2356C5C, "first dex list", "add"), (0x2356C68, "first dex", "calli"), (0x2356C6E, "fee store, dex +0x250", "mov"), (0x2358169, "toggle map cap", "call"), (0x2358204, "next toggle", "call"), (0x2358242, "flag byte of the row", "cmp"), (0x2358267, "zero: remove", "jcc"), (0x2358293, "insert", "call"), (0x23581F9, "remove", "call"),
            (0x2359480, "list cap", "call"), (0x23594B3, "state +0x36a0", "add"), (0x23594BD, "drop the old list", "call"), (0x23594C6, "store the new length", "mov"), (0x23594CE, "store root and height", "movx"), (0x23582DA, "selector byte", "movzx"), (0x23582DF, "value byte", "movzx"), (0x235B43A, "keep one bit", "and"), (0x235B43C, "state +0x31a2", "mov"), (0x235B443, "cleared: go clear oaw", "jcc"), (0x235B455, "set: recorder 3", "calli"), (0x235B460, "keep one bit", "and"), (0x235B462, "state +0x34d8", "mov"), (0x235BD9D, "oaw cleared", "mov"),
            (0x1E802D0, "cap 10000", "cmp"), (0x1E802D6, "at or below: pass the map on", "jcc"), (0x1E802D8, "status 0x143", "mov"), (0x1E7FA80, "cap 10000", "cmp"), (0x1E7FA86, "at or below: pass the set on", "jcc"), (0x1E7FA88, "status 0x143", "mov"))


def row_at(image, va):
    return decode(lambda at, count: bytes(image.blob[image.offset(at):image.offset(at) + count]), va)


def key_rows(image):
    out = []
    for va, text, op in KEY_ROWS:
        row = row_at(image, va)
        if row.op != op:
            raise EvidenceError("row %#x is %s" % (va, row.op))
        out.append(("%#x" % image.fde(va)[0], "%#x" % va, bytes(image.blob[image.offset(va):image.offset(va) + row.size]).hex(), op, text))
    return out


def case_rows(image):
    out = []
    for case, arm in ((CASE_FEE, ARM_FEE), (CASE_TOGGLES, ARM_TOGGLES), (CASE_FLAGS, ARM_FLAGS), (CASE_LIST, ARM_LIST)):
        target = CASE_TABLE + struct.unpack_from("<i", image.blob, image.offset(CASE_TABLE + 4 * case))[0]
        if target != arm:
            raise EvidenceError("case %d moved" % case)
        out.append(("case", case, "%#x" % (CASE_BASE + case), "%#x" % (CASE_TABLE + 4 * case), "%#x" % target))
    for selector, arm in ((SELECTOR_HALT, ARM_HALT), (SELECTOR_OAW, ARM_OAW)):
        target = SELECTOR_TABLE + struct.unpack_from("<i", image.blob, image.offset(SELECTOR_TABLE + 4 * selector))[0]
        if target != arm:
            raise EvidenceError("selector %d moved" % selector)
        out.append(("selector of case 76", selector, "%#x" % selector, "%#x" % (SELECTOR_TABLE + 4 * selector), "%#x" % target))
    return out


# load of the field, load of the key, text, offset
FIELDS = ((0x370C8C5, 0x370C8CC, "bridge2_withdraw_fee", D_FEE, "per-dex record"), (0x22157E4, 0x22157EB, "oaw", 0x140, "bridge record, state +0x3398"))


def field_rows(image):
    out = []
    for field_row, key_row, text, offset, owner in FIELDS:
        field, key = row_at(image, field_row), row_at(image, key_row)
        data = bytes(image.blob[image.offset(key.b[4]):image.offset(key.b[4]) + len(text)])
        if field.b[4] != offset or data != text.encode("ascii"):
            raise EvidenceError("field row %#x moved" % field_row)
        out.append(("%#x" % field_row, "%#x" % key_row, text, "+%#x" % offset, owner))
    return out


def twin_rows(image):
    out = []
    for name, disp in (("listed set", S_LIST), ("voter set", S_VOTERS), ("halt byte", S_HALT), ("oaw byte", S_OAW)):
        for start in (VOTE, TWIN):
            low, high = image.exact_fde(start)
            data = bytes(image.blob[image.offset(low):image.offset(high)])
            hits = [low + match.start() for match in re.finditer(re.escape(struct.pack("<I", disp)), data)]
            out.append((name, "+%#x" % disp, "%#x" % start, len(hits), " ".join("%#x" % at for at in hits)))
    return out


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in (TAG_LIMIT, TAG_TOO_MANY):
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


def slot_rows(image, through):
    relative = image.relative()
    rows = []
    for slot, role in ((SLOT_DEX, "first dex, stub here"), (SLOT_RECORDER, "recorder, stub here")):
        rows.append(("%#x" % slot, role, "%#x" % relative[slot], len(through[slot])))
    return rows


def site_rows(image):
    hits = direct_sites(image, (VOTE, TWIN, CHECK_TOGGLES, CHECK_LIST, SET_REMOVE))
    return [("%#x" % target, len(hits[target]), " ".join("%#x" % site for site in hits[target]), " ".join("%#x" % image.fde(site)[0] for site in hits[target])) for target in (VOTE, TWIN, CHECK_TOGGLES, CHECK_LIST, SET_REMOVE)]


def analyse(image, mutate=True, vectors=200):
    harness = Harness(image)
    named = check_all(harness, named_scenarios())
    generated = vector_scenarios(vectors)
    check_all(harness, generated)
    seen = set(harness.machine.seen)
    table = {}
    for target in TARGETS:
        low, high = image.exact_fde(target)
        if target in PARTIAL:
            table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
            for row in table[target]:
                row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        else:
            table[target] = decode_range(image, low, high)
    unreached = {NAMES[target]: [row.va for row in rows if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target, rows in table.items()}
    through = slot_sites(image, (SLOT_DEX, SLOT_RECORDER))
    result = dict(table=table, named=named, vector_count=vectors, unreached=unreached, keys=key_rows(image), cases=case_rows(image), fields=field_rows(image), twins=twin_rows(image), statuses=status_rows(image), slots=slot_rows(image, through), sites=site_rows(image), location=("%#x" % LOCATION_HALT,) + image.location(LOCATION_HALT, image.relative()))
    if mutate:
        result["mutations"] = run_mutants(image, {target: table[target] for target in MUTATED}, seen, [scenario for scenario, _ in named] + generated[:40])
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table = result["table"]
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in TARGETS for row in table[target]])
    reach = result["unreached"]
    tsv("path.tsv", ("name", "address", "rows", "unreached_rows", "role"), [(NAMES[target], "%#x" % target, len(table[target]), len(reach[NAMES[target]]), "reached rows only, run and edited" if target in PARTIAL else "run, not edited" if target not in MUTATED else "run and edited") for target in TARGETS])
    tsv("unreached.tsv", ("function", "row"), [(name, "%#x" % va) for name in sorted(reach) for va in reach[name]])
    tsv("cases.tsv", ("table", "index", "raw_tag", "entry", "target"), result["cases"])
    tsv("fields.tsv", ("field_row", "key_row", "serde_name", "offset", "owner"), result["fields"])
    tsv("twin-rows.tsv", ("field", "offset", "function", "hits", "addresses"), result["twins"])
    tsv("node-layouts.tsv", ("map", "key_at", "key_size", "value_at", "value_size", "parent", "parent_index", "count", "leaf_size"), [(item.name, "%#x" % item.key_at, "%#x" % item.key_size, "%#x" % item.val_at, "%#x" % item.val_size, "%#x" % item.parent, "%#x" % item.index, "%#x" % item.count, "%#x" % item.size) for item in LAYOUTS])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("slots.tsv", ("slot", "role", "relative_target", "call_sites"), result["slots"])
    tsv("call-sites.tsv", ("function", "sites", "site_list", "caller_functions"), result["sites"])
    tsv("locations.tsv", ("record", "path", "line", "column"), [result["location"]])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    tsv("scenarios.tsv", ("scenario", "operations", "outcome"), [(scenario.name, len(scenario.ops), describe(trace)) for scenario, trace in result["named"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(TARGETS), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "named_operations": sum(len(scenario.ops) for scenario, _ in named), "vector_scenarios": result["vector_count"], "unreached_rows": sum(len(items) for items in reach.values())}
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
