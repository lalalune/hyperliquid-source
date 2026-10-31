#!/usr/bin/env python3
"""Pin the node #94 validator profile gate (commission bps, name and description lengths, IPv4 rule).

0x3bfcbc0 checks one CValidatorProfile: a non-global IPv4 unless the validator is in a chain set, name
1..=50, description 1..=1000, commission_bps at most 10000, and a rise above the stored value at most
100. 0x3991f70 is its only caller: it looks the validator up in the chain set, runs the gate, then scans
the profile map for another row with the same IP or signer. A walker over the real rows proves the IPv4
rule for all 2^32 addresses, the real bytes run under recording stubs over real B-tree nodes, a separately
written rule list predicts every run including all fixture bytes, and every reached conditional row is
mutated. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/validator_profile_gates.py --out <dir>
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
HEAP_SIZE = 0x20000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 20000


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


GATE = 0x3BFCBC0
SCAN = 0x3991F70
HANDLER = 0x3994F20
TARGETS = (GATE, SCAN)
NAMES = {GATE: "profile_gate", SCAN: "profile_scan"}

SLOT_GATE = 0x5776248
SLOT_CHAIN = 0x57732E8
SLOT_FREE = 0x576E010
SLOT_CMP = 0x576E488
SCAN_SLOTS = (SLOT_CHAIN, SLOT_FREE, SLOT_CMP)
STATUS_TABLE = 0x59A8D0
MARK_BASE = 0x7700000000
IP_START = 0x3BFCBD8
IP_OK = 0x3BFCC87
REFUSE = 0x3BFCD83

TAG_OK = 0x186
TAG_IP = 0x120
TAG_NAME = 0x121
TAG_DESC = 0x122
TAG_COMMISSION = 0x123
TAG_SAME_IP = 0x124
TAG_SAME_SIGNER = 0x125
NAME_MAX = 50
DESC_MAX = 1000
BPS_MAX = 10000
RISE_MAX = 100

P_NAME = 0x00
P_DESC = 0x18
P_COMMISSION = 0x30
P_SIGNER = 0x38
P_IP_TAG = 0x4C
P_IP = 0x4D
P_FLAG = 0x51
P_SIZE = 0x58
S_MAP = 0x150

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
PROFILE = HEAP_BASE + 0x300
KEY = HEAP_BASE + 0x400
NAME_TEXT = HEAP_BASE + 0x500
DESC_TEXT = HEAP_BASE + 0x600
STATE = HEAP_BASE + 0x1000
SET_TABLE = HEAP_BASE + 0x1400
SET_NODES = HEAP_BASE + 0x1800
MAP_NODES = HEAP_BASE + 0x4000
COMPARED = 0x10000
USED = 0x10000
FILL = 0xCC
SIGNER = bytes(range(0x61, 0x75))
VALIDATOR = bytes(range(0x21, 0x35))
TAIL = bytes((0xE0 + index) & 0xFF for index in range(P_SIZE - P_FLAG))

SET_STRIDE = 0x150
SET_KEY_AT, SET_SLOT_AT, SET_LEN_AT, SET_EDGE_AT = 0x8, 0xE4, 0xE6, 0xE8
MAP_STRIDE = 0x520
MAP_VAL_AT, MAP_KEY_AT, MAP_SLOT_AT, MAP_LEN_AT, MAP_EDGE_AT = 0x8, 0x3D0, 0x4AC, 0x4AE, 0x4B0
CAPACITY = 11
KEY_SIZE = 20
VAL_SIZE = 0x58


class Row:
    """One row of the profile map."""

    def __init__(self, key, signer=None, tag=0, ip=(8, 8, 4, 4)):
        self.key, self.signer, self.tag, self.ip = key, signer if signer is not None else bytes([key[0] ^ 0x5A]) * 20, tag, ip


def key_of(value):
    return bytes([value]) * KEY_SIZE


class Case:
    FIELDS = dict(ip=(8, 8, 8, 8), ip_tag=0, dl=0, cl=0, prev=0, name_len=5, desc_len=9, commission=50, name_cap=16, desc_cap=32, chain=3,
                  rows=None, height=0, members=(), set_height=0, set_root=True, fan=1)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.FIELDS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.FIELDS:
                raise EvidenceError("field " + key)
            setattr(self, key, value)


def not_global(ip):
    """The refused IPv4 set, written from the cuts and apart from the walker."""
    a, b, c, d = ip
    if a in (0, 10, 127) or (a == 172 and b & 0xF0 == 0x10) or (a == 192 and b == 168) or (a == 169 and b == 254):
        return True
    if a == 192 and b == 0 and (c == 2 or (c == 0 and d not in (9, 10))):
        return True
    if (a == 198 and b == 51 and c == 100) or (a == 203 and b == 0 and c == 113):
        return True
    return ip == (255, 255, 255, 255)


REFUSED_BLOCKS = (("0.0.0.0/8", 1 << 24), ("10.0.0.0/8", 1 << 24), ("127.0.0.0/8", 1 << 24), ("169.254.0.0/16", 1 << 16), ("172.16.0.0/12", 1 << 20), ("192.0.0.0/24 less .9 and .10", 254), ("192.0.2.0/24", 256),
                  ("192.168.0.0/16", 1 << 16), ("198.51.100.0/24", 256), ("203.0.113.0/24", 256), ("255.255.255.255/32", 1))


def gate_tag(case, bypass):
    if case.ip_tag & 1 == 0 and not bypass and not_global(tuple(case.ip)):
        return TAG_IP
    if not 1 <= case.name_len <= NAME_MAX:
        return TAG_NAME
    if not 1 <= case.desc_len <= DESC_MAX:
        return TAG_DESC
    if case.commission > BPS_MAX:
        return TAG_COMMISSION
    limit = case.prev if case.cl & 1 else BPS_MAX
    if case.commission > limit and case.commission > RISE_MAX:
        return TAG_COMMISSION
    return TAG_OK


def profile_bytes(case):
    data = bytearray((index * 3 + 0x31) & 0xFF for index in range(P_SIZE))
    data[P_NAME:P_NAME + 24] = struct.pack("<3Q", case.name_cap, NAME_TEXT, case.name_len)
    data[P_DESC:P_DESC + 24] = struct.pack("<3Q", case.desc_cap, DESC_TEXT, case.desc_len)
    data[P_COMMISSION:P_COMMISSION + 8] = struct.pack("<Q", case.commission)
    data[P_SIGNER:P_SIGNER + 20] = SIGNER
    data[P_IP_TAG] = case.ip_tag
    data[P_IP:P_IP + 4] = bytes(case.ip)
    data[P_FLAG:P_SIZE] = TAIL
    return bytes(data)


def frees(case):
    rows = []
    if case.name_cap:
        rows.append(("free", NAME_TEXT, case.name_cap, 0))
    if case.desc_cap:
        rows.append(("free", DESC_TEXT, case.desc_cap, 0))
    return rows


def blank():
    return bytes((index * 7 + 0x40) & 0xFF for index in range(OUT_SIZE))


def spec_run(case, before):
    """Predict one run from the rule list, written apart from the bytes under test."""
    image = bytearray(before)
    events = []

    def put(addr, data):
        at = addr - HEAP_BASE
        image[at:at + len(data)] = data

    def finish(tag):
        put(OUT, struct.pack("<H", tag))
        if tag == TAG_OK:
            put(OUT + 8, profile_bytes(case))
        return "done", tuple(events), bytes(image)

    if case.rows is None:
        tag = gate_tag(case, case.dl & 0xFF != 0)
        if tag != TAG_OK:
            events.extend(frees(case))
        return finish(tag)
    events.append(("chain", case.chain))
    tag = gate_tag(case, VALIDATOR in case.members and case.set_root)
    if tag != TAG_OK:
        events.extend(frees(case))
        put(OUT + 2, bytes([STACK_MARK]) * (OUT_SIZE - 2))
        return finish(tag)
    for row in sorted(case.rows, key=lambda item: item.key):
        if row.key == VALIDATOR:
            continue
        same_ip = row.tag == case.ip_tag and (bytes(row.ip) == bytes(case.ip) if case.ip_tag == 0 else row.ip[0] == case.ip[0])
        if same_ip or row.signer == SIGNER:
            events.extend(frees(case))
            return finish(TAG_SAME_IP if same_ip else TAG_SAME_SIGNER)
    return finish(TAG_OK)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((GATE,))
        statics = machine.memory.statics
        statics[SLOT_GATE] = GATE
        hooks = {SLOT_CHAIN: self.on_chain, SLOT_FREE: self.on_free, SLOT_CMP: self.on_compare}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        self.events = []
        self.case = None
        self.before = None
        self.next_map = MAP_NODES
        self.next_set = SET_NODES

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def on_chain(self, machine):
        self.expect(machine.regs[RDI] & 0xFF == self.case.chain, "chain byte")
        self.events.append(("chain", machine.regs[RDI] & 0xFF))
        machine.regs[RAX] = SET_TABLE

    def on_free(self, machine):
        regs = machine.regs
        self.events.append(("free", regs[RDI], regs[RSI], regs[RDX] & MASK[4]))

    def on_compare(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == KEY, "compare left")
        self.expect(regs[RDX] & MASK[4] == KEY_SIZE, "compare size")
        left, right = self.bytes_at(regs[RDI], KEY_SIZE), self.bytes_at(regs[RSI], KEY_SIZE)
        result = 0
        for one, two in zip(left, right):
            if one != two:
                result = one - two
                break
        regs[RAX] = result & MASK[4]

    def set_node(self, keys, children, stale):
        base = self.next_set
        self.next_set += SET_STRIDE
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * SET_STRIDE)
        for at in range(CAPACITY):
            memory.put_bytes(base + SET_KEY_AT + KEY_SIZE * at, keys[at] if at < len(keys) else stale)
        self.word(base + SET_LEN_AT, len(keys), 2)
        self.word(base + SET_SLOT_AT, 0, 2)
        self.word(base, 0)
        for at, child in enumerate(children):
            self.word(base + SET_EDGE_AT + 8 * at, child)
        return base

    def set_tree(self, keys, height, stale):
        if height == 0:
            return self.set_node(keys, (), stale)
        middle = len(keys) // 2
        if not keys:
            child = self.set_tree([], height - 1, stale)
            return self.set_node([], (child,), stale)
        left = self.set_tree(keys[:middle], height - 1, stale)
        right = self.set_tree(keys[middle + 1:], height - 1, stale)
        return self.set_node(keys[middle:middle + 1], (left, right), stale)

    def map_node(self, rows, children):
        base = self.next_map
        self.next_map += MAP_STRIDE
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * MAP_STRIDE)
        decoy = Row(key_of(0x7F), SIGNER, self.case.ip_tag, tuple(self.case.ip))
        for at in range(CAPACITY):
            row = rows[at] if at < len(rows) else decoy
            memory.put_bytes(base + MAP_KEY_AT + KEY_SIZE * at, row.key)
            value = base + MAP_VAL_AT + VAL_SIZE * at
            memory.put_bytes(value, bytes((at * 5 + 0x11 + step) & 0xFF for step in range(VAL_SIZE)))
            memory.put_bytes(value + P_SIGNER, row.signer)
            memory.write(value + P_IP_TAG, 1, row.tag)
            memory.put_bytes(value + P_IP, bytes(row.ip))
        self.word(base, 0)
        self.word(base + MAP_SLOT_AT, 0, 2)
        self.word(base + MAP_LEN_AT, len(rows), 2)
        for at, child in enumerate(children):
            self.word(base + MAP_EDGE_AT + 8 * at, child)
            self.word(child, base)
            self.word(child + MAP_SLOT_AT, at, 2)
        return base

    def spine(self, rows, height):
        if height == 0:
            return self.map_node(rows, ())
        return self.map_node([], (self.spine(rows, height - 1),))

    def map_tree(self, rows, height, fan):
        if height == 0:
            return self.map_node(rows, ())
        if fan == 1:
            middle = len(rows) // 2
            return self.map_node(rows[middle:middle + 1], (self.spine(rows[:middle], height - 1), self.spine(rows[middle + 1:], height - 1)))
        step = max(1, len(rows) // (fan + 1))
        keys, kids = [], []
        at = 0
        for _ in range(fan):
            kids.append(self.spine(rows[at:at + step - 1], height - 1))
            keys.append(rows[at + step - 1])
            at += step
        kids.append(self.spine(rows[at:], height - 1))
        return self.map_node(keys, kids)

    def build(self, case):
        keys = sorted(case.members)
        root = self.set_tree(keys, case.set_height, VALIDATOR) if case.set_root else 0
        self.word(SET_TABLE, root)
        self.word(SET_TABLE + 8, case.set_height)
        rows = sorted(case.rows, key=lambda item: item.key)
        tree = self.map_tree(rows, case.height, case.fan) if rows else 0
        self.word(STATE + S_MAP, tree)
        self.word(STATE + S_MAP + 8, case.height)
        self.word(STATE + S_MAP + 0x10, len(rows))

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE, bytes([FILL]) * COMPARED)
        memory.put_bytes(OUT, blank())
        memory.put_bytes(KEY, VALIDATOR)
        memory.put_bytes(PROFILE, profile_bytes(case))
        self.case = case
        self.next_map = MAP_NODES
        self.next_set = SET_NODES
        if case.rows is not None:
            self.build(case)
        self.events = []
        self.before = memory.bytes_at(HEAP_BASE, COMPARED)

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        if case.rows is None:
            result = self.machine.run(GATE, {RDI: OUT, RSI: PROFILE, RDX: case.dl, RCX: case.cl, R8: case.prev})
            self.expect(result == OUT, "gate result")
        else:
            memory.write(STACK_TOP - 0x100, 8, case.prev)
            self.machine.run(SCAN, {RDI: OUT, RSI: STATE, RDX: case.chain, RCX: KEY, R8: PROFILE, R9: case.cl})
        return "done", tuple(self.events), memory.bytes_at(HEAP_BASE, COMPARED)


class Sym:
    """A byte-tracked value: fn gives the number, deps[n] the address octets that byte n reads."""

    __slots__ = ("fn", "deps", "key")

    def __init__(self, fn, deps, key):
        self.fn, self.deps, self.key = fn, deps, key

    def lanes(self):
        return frozenset().union(*self.deps)


NONE_DEPS = (frozenset(),) * 8
ZERO = (0, 0, 0, 0)


def sym_const(value):
    return Sym(lambda x: value, NONE_DEPS, "%#x" % value)


def sym_word():
    return Sym(lambda x: x[0] | x[1] << 8 | x[2] << 16 | x[3] << 24, tuple(frozenset((index,)) for index in range(4)) + (frozenset(),) * 4, "ip")


def trimmed(value, width):
    mask = MASK[width]
    return Sym(lambda x: value.fn(x) & mask, value.deps[:width] + (frozenset(),) * (8 - width), "t%d(%s)" % (width, value.key))


def bitwise(left, right, op):
    if op == "and":
        return Sym(lambda x: left.fn(x) & right.fn(x), tuple(frozenset() if constant_byte_zero(right, at) or constant_byte_zero(left, at) else left.deps[at] | right.deps[at] for at in range(8)), "and(%s,%s)" % (left.key, right.key))
    if op == "or":
        return Sym(lambda x: left.fn(x) | right.fn(x), tuple(left.deps[at] | right.deps[at] for at in range(8)), "or(%s,%s)" % (left.key, right.key))
    return Sym(lambda x: left.fn(x) ^ right.fn(x), tuple(left.deps[at] | right.deps[at] for at in range(8)), "xor(%s,%s)" % (left.key, right.key))


def constant_byte_zero(value, at):
    return not value.lanes() and value.fn(ZERO) >> (8 * at) & 0xFF == 0


def added(left, right, width):
    mask = MASK[width]
    seen, deps = frozenset(), []
    for at in range(8):
        seen = seen | left.deps[at] | right.deps[at]
        deps.append(seen if at < width else frozenset())
    return Sym(lambda x: (left.fn(x) + right.fn(x)) & mask, tuple(deps), "add%d(%s,%s)" % (width, left.key, right.key))


def shifted_right(value, count):
    if count % 8:
        raise EvidenceError("walker: shift by %d" % count)
    step = count // 8
    return Sym(lambda x: value.fn(x) >> count, value.deps[step:] + (frozenset(),) * step, "shr%d(%s)" % (count, value.key))


def flag_values(flags, x):
    kind, left, right, width = flags
    one, two = left.fn(x), right.fn(x)
    if kind == "sub":
        result = (one - two) & MASK[width]
        cf, of = one < two, bool((one ^ two) & (one ^ result) & SIGN[width])
    elif kind == "add":
        total = one + two
        result = total & MASK[width]
        cf, of = total > MASK[width], bool(~(one ^ two) & (one ^ result) & SIGN[width])
    else:
        result = one
        cf = of = False
    return cf, of, result == 0, bool(result & SIGN[width])


def holds(flags, code, x):
    cf, of, zf, sf = flag_values(flags, x)
    value = {0: of, 1: cf, 2: zf, 3: cf or zf, 4: sf, 6: sf != of, 7: zf or sf != of}[code >> 1]
    return bool(value) != bool(code & 1)


class Fork:
    __slots__ = ("va", "test", "lanes", "word", "key", "yes", "no")

    def __init__(self, va, test, lanes, word, key):
        self.va, self.test, self.lanes, self.word, self.key = va, test, lanes, word, key
        self.yes = self.no = None


def walk_ip(image, bypass):
    """Walk every path of the real rows from the address load to the two exits, for all 2^32 addresses."""
    rows = {row.va: row for row in decode_range(image, *image.exact_fde(GATE))}

    def operand(regs, item, width):
        if item[0] == "i":
            return sym_const(item[1] & MASK[width])
        if item[0] == "r":
            return trimmed(regs[item[1]], width)
        if item[1] == R14 and item[4] == P_IP and width == 4:
            return sym_word()
        raise EvidenceError("walker: operand %r" % (item,))

    def store(regs, item, width, value):
        if item[0] != "r":
            raise EvidenceError("walker: store")
        register = item[1]
        if width >= 4:
            regs[register] = trimmed(value, width)
            return
        old = regs.get(register, sym_const(0))
        mask = MASK[width]
        kept = sym_const(MASK[8] ^ mask)
        regs[register] = bitwise(bitwise(old, kept, "and"), trimmed(value, width), "or")

    def walk(pc, regs, flags, steps):
        if steps > 200:
            raise EvidenceError("walker: path too long")
        if pc == IP_OK:
            return "pass"
        if pc == REFUSE:
            if trimmed(regs[RDX], 2).fn(ZERO) != TAG_IP:
                raise EvidenceError("walker: refusal with another tag")
            return "refuse"
        row = rows.get(pc)
        if row is None:
            raise EvidenceError("walker: left the function at %#x" % pc)
        regs = dict(regs)
        op, width = row.op, row.width
        if op == "mov":
            store(regs, row.a, width, operand(regs, row.b, width))
        elif op == "movzx":
            store(regs, row.a, width, operand(regs, row.b, row.cc))
        elif op in ("and", "or", "xor", "test"):
            if op == "xor" and row.a == row.b:
                value = sym_const(0)
            else:
                value = bitwise(operand(regs, row.a, width), operand(regs, row.b, width), "and" if op == "test" else op)
            flags = ("logic", value, sym_const(0), width)
            if op != "test":
                store(regs, row.a, width, value)
        elif op == "cmp":
            flags = ("sub", operand(regs, row.a, width), operand(regs, row.b, width), width)
        elif op == "add":
            left, right = operand(regs, row.a, width), operand(regs, row.b, width)
            flags = ("add", left, right, width)
            store(regs, row.a, width, added(left, right, width))
        elif op == "shr":
            value = shifted_right(operand(regs, row.a, width), row.b[1])
            flags = ("logic", value, sym_const(0), width)
            store(regs, row.a, width, value)
        elif op == "jmp":
            return walk(row.target, regs, flags, steps + 1)
        elif op in ("jcc", "set"):
            lanes = flags[1].lanes() | flags[2].lanes()
            current, code = flags, row.cc
            if not lanes:
                taken = holds(current, code, ZERO)
                if op == "jcc":
                    return walk(row.target if taken else row.next, regs, flags, steps + 1)
                store(regs, row.a, 1, sym_const(int(taken)))
                return walk(row.next, regs, flags, steps + 1)
            word = None
            if flags[0] == "sub" and len(lanes) > 2:
                if not flags[2].deps[0] == frozenset() or code not in (4, 5) or flags[3] != 4:
                    raise EvidenceError("walker: wide test at %#x" % pc)
                word = flags[2].fn(ZERO)
            elif len(lanes) > 2:
                raise EvidenceError("walker: wide test at %#x" % pc)
            fork = Fork(pc, lambda x, cur=current, cc=code: holds(cur, cc, x), lanes, word, (flags[0], flags[1].key, flags[2].key, flags[3], code))
            for outcome in (True, False):
                branch = dict(regs)
                if op == "jcc":
                    next_pc = row.target if outcome else row.next
                else:
                    store(branch, row.a, 1, sym_const(int(outcome)))
                    next_pc = row.next
                result = walk(next_pc, branch, flags, steps + 1)
                if outcome:
                    fork.yes = result
                else:
                    fork.no = result
            return fork
        else:
            raise EvidenceError("walker: unmodelled %s at %#x" % (op, pc))
        return walk(row.next, regs, flags, steps + 1)

    regs = {RDX: sym_const(bypass)}
    return walk(IP_START, regs, None, 0)


def decide(tree, x):
    while tree.__class__ is Fork:
        tree = tree.yes if tree.test(x) else tree.no
    return tree


def forks_of(tree):
    if tree.__class__ is not Fork:
        return []
    return [tree] + forks_of(tree.yes) + forks_of(tree.no)


def octet_classes(tree):
    """Group each octet's 256 values by what every test of the tree can see of them."""
    forks = list({fork.key: fork for fork in forks_of(tree)}.values())
    classes = []
    for lane in range(4):
        signatures = {}
        for value in range(256):
            cells = []
            for fork in forks:
                if lane not in fork.lanes:
                    continue
                if fork.word is not None:
                    cells.append(value == fork.word >> (8 * lane) & 0xFF)
                    continue
                others = sorted(fork.lanes - {lane})
                point = [0, 0, 0, 0]
                point[lane] = value
                if not others:
                    cells.append(fork.test(tuple(point)))
                    continue
                row = []
                for other in range(256):
                    point[others[0]] = other
                    row.append(fork.test(tuple(point)))
                cells.append(tuple(row))
            signatures.setdefault(tuple(cells), []).append(value)
        classes.append(sorted(signatures.values()))
    return classes


def path_rows(tree):
    rows = []

    def visit(node, path):
        if node.__class__ is not Fork:
            rows.append((node, " ".join(path)))
            return
        visit(node.yes, path + ["%#x:1" % node.va])
        visit(node.no, path + ["%#x:0" % node.va])
    visit(tree, [])
    return rows


def prove_ip(harness):
    """Walker tree, rule list and the real bytes agree on one point of every class product."""
    tree = walk_ip(harness.image, 0)
    classes = octet_classes(tree)
    refused = 0
    total = 0
    runs = 0
    for a in classes[0]:
        for b in classes[1]:
            for c in classes[2]:
                for d in classes[3]:
                    size = len(a) * len(b) * len(c) * len(d)
                    total += size
                    point = (a[0], b[0], c[0], d[0])
                    leaf = decide(tree, point)
                    rule = not_global(point)
                    if (leaf == "refuse") != rule:
                        raise EvidenceError("walker and rule differ at %r" % (point,))
                    case = Case("ip", ip=point)
                    if (harness.run(case) != spec_run(case, harness.before)):
                        raise EvidenceError("bytes and rule differ at %r" % (point,))
                    runs += 1
                    refused += size if rule else 0
    if total != 1 << 32:
        raise EvidenceError("class product covers %d addresses" % total)
    open_tree = walk_ip(harness.image, 1)
    if open_tree.__class__ is Fork and {row[0] for row in path_rows(open_tree)} != {"pass"}:
        raise EvidenceError("a refusal is left when the validator is in the set")
    return dict(classes=classes, refused=refused, total=total, runs=runs, paths=path_rows(tree), open_paths=len(path_rows(open_tree)) if open_tree.__class__ is Fork else 1)


def ip_cases(classes):
    rows = []
    for a in classes[0]:
        for b in classes[1]:
            for c in classes[2]:
                for d in classes[3]:
                    rows.append(Case("ip", ip=(a[0], b[0], c[0], d[0])))
    return rows


TOP = MASK[8]
HIGH = 1 << 63
GRID = (0, 1, 50, 99, 100, 101, 102, 5000, 9999, 10000, 10001, 20000, 1 << 32, HIGH, TOP)


def gate_named():
    rows = [("plain", {})]
    for value in (0, 1, 2, 49, 50, 51, 52, 100, 1 << 32, HIGH, TOP):
        rows.append(("name_%#x" % value, dict(name_len=value)))
    for value in (0, 1, 2, 999, 1000, 1001, 1002, 1 << 32, HIGH, TOP):
        rows.append(("desc_%#x" % value, dict(desc_len=value)))
    for x in GRID:
        rows.append(("register_%#x" % x, dict(commission=x)))
        for prev in GRID:
            rows.append(("change_%#x_%#x" % (x, prev), dict(commission=x, cl=1, prev=prev)))
    for cl in (2, 3, 0xFE, 0xFF, 0x100, 0x101, TOP - 1, TOP):
        rows.append(("cl_%#x" % cl, dict(commission=500, cl=cl, prev=100)))
    for dl in (0, 1, 2, 0x80, 0xFF, 0x100, 0x101):
        rows.append(("dl_%#x" % dl, dict(ip=(10, 0, 0, 1), dl=dl)))
    for tag in (0, 1, 2, 3, 0x80, 0xFE, 0xFF):
        rows.append(("tag_%#x" % tag, dict(ip=(10, 0, 0, 1), ip_tag=tag)))
    rows += [("order_ip_name", dict(ip=(10, 0, 0, 1), name_len=0)), ("order_name_desc", dict(name_len=0, desc_len=0)), ("order_desc_bps", dict(desc_len=0, commission=TOP)), ("order_ip_all", dict(ip=(10, 0, 0, 1), name_len=TOP, desc_len=TOP, commission=TOP)),
             ("order_bypass_name", dict(ip=(10, 0, 0, 1), dl=1, name_len=0)), ("order_ip_tag_name", dict(ip=(10, 0, 0, 1), ip_tag=1, name_len=0)),
             ("no_caps", dict(name_cap=0, desc_cap=0, name_len=0)), ("no_name_cap", dict(name_cap=0, name_len=0)), ("no_desc_cap", dict(desc_cap=0, name_len=0)), ("no_caps_ok", dict(name_cap=0, desc_cap=0)),
             ("cap_high", dict(name_cap=HIGH, desc_cap=TOP, name_len=0)), ("bps_refused_frees", dict(commission=10001)), ("rise_refused_frees", dict(commission=101, cl=1, prev=100)), ("bypass_ip_ok", dict(ip=(127, 0, 0, 1), dl=1))]
    for ip in ((192, 0, 0, 8), (192, 0, 0, 9), (192, 0, 0, 10), (192, 0, 0, 11), (192, 0, 0, 0), (192, 0, 0, 255), (192, 0, 1, 9), (192, 1, 0, 9), (193, 0, 0, 1), (192, 0, 2, 0), (192, 0, 2, 255), (192, 0, 3, 0), (192, 1, 2, 0), (192, 168, 0, 0), (192, 169, 0, 0), (192, 167, 0, 0),
               (198, 51, 100, 1), (198, 51, 101, 1), (198, 50, 100, 1), (203, 0, 113, 1), (203, 0, 112, 1), (203, 1, 113, 1), (172, 15, 0, 1), (172, 16, 0, 1), (172, 31, 255, 255), (172, 32, 0, 1), (169, 254, 0, 1), (169, 253, 0, 1), (170, 254, 0, 1),
               (255, 255, 255, 255), (255, 255, 255, 254), (254, 255, 255, 255), (255, 255, 254, 255), (255, 254, 255, 255), (0, 1, 2, 3), (9, 0, 0, 1), (11, 0, 0, 1), (10, 255, 255, 255), (126, 0, 0, 1), (127, 255, 255, 255), (128, 0, 0, 1), (8, 8, 8, 8)):
        rows.append(("ip_%d_%d_%d_%d" % ip, dict(ip=ip)))
    return rows


def other(value, **fields):
    return Row(key_of(value), **fields)


def scan_named():
    me = Row(VALIDATOR, SIGNER, 0, (8, 8, 8, 8))
    low, high = key_of(0x10), key_of(0x40)
    base = dict(rows=(), ip=(8, 8, 8, 8))
    rows = [("empty_map", base), ("self_only", dict(base, rows=(me,))), ("self_and_two", dict(base, rows=(me, other(0x10), other(0x40)))), ("chain_one", dict(base, chain=1)), ("chain_top", dict(base, chain=0xFF)),
            ("same_ip", dict(base, rows=(other(0x10, ip=(8, 8, 8, 8)),))), ("same_signer", dict(base, rows=(other(0x10, signer=SIGNER),))),
            ("same_both_one_row", dict(base, rows=(other(0x10, signer=SIGNER, ip=(8, 8, 8, 8)),))), ("signer_row_before_ip_row", dict(base, rows=(other(0x10, signer=SIGNER), other(0x40, ip=(8, 8, 8, 8))))), ("ip_row_before_signer_row", dict(base, rows=(other(0x10, ip=(8, 8, 8, 8)), other(0x40, signer=SIGNER)))),
            ("after_self", dict(base, rows=(me, other(0x40, ip=(8, 8, 8, 8))))), ("before_self", dict(base, rows=(other(0x10, ip=(8, 8, 8, 8)), me))),
            ("signer_last_byte", dict(base, rows=(other(0x10, signer=SIGNER[:19] + b"\x00"),))), ("signer_byte_15", dict(base, rows=(other(0x10, signer=SIGNER[:15] + b"\x00" + SIGNER[16:]),))), ("signer_byte_16", dict(base, rows=(other(0x10, signer=SIGNER[:16] + b"\x00" + SIGNER[17:]),))), ("signer_first_byte", dict(base, rows=(other(0x10, signer=b"\x00" + SIGNER[1:]),))),
            ("key_last_byte_self", dict(base, rows=(Row(VALIDATOR[:19] + b"\x00", ip=(8, 8, 8, 8)),))), ("key_byte_16_self", dict(base, rows=(Row(VALIDATOR[:16] + b"\x00" + VALIDATOR[17:], ip=(8, 8, 8, 8)),))), ("key_byte_15_self", dict(base, rows=(Row(VALIDATOR[:15] + b"\x00" + VALIDATOR[16:], ip=(8, 8, 8, 8)),))),
            ("ip_each_octet_0", dict(base, rows=(other(0x10, ip=(9, 8, 8, 8)),))), ("ip_each_octet_1", dict(base, rows=(other(0x10, ip=(8, 9, 8, 8)),))), ("ip_each_octet_2", dict(base, rows=(other(0x10, ip=(8, 8, 9, 8)),))), ("ip_each_octet_3", dict(base, rows=(other(0x10, ip=(8, 8, 8, 9)),))),
            ("tag_differs", dict(base, rows=(other(0x10, tag=1, ip=(8, 8, 8, 8)),))), ("tag_differs_other_way", dict(base, ip_tag=1, rows=(other(0x10, tag=0, ip=(8, 8, 8, 8)),))), ("tag_two_rows", dict(base, rows=(other(0x10, tag=2, ip=(8, 8, 8, 8)),))),
            ("tag_one_first_byte", dict(base, ip_tag=1, ip=(7, 1, 2, 3), rows=(other(0x10, tag=1, ip=(7, 9, 9, 9)),))), ("tag_one_first_byte_differs", dict(base, ip_tag=1, ip=(7, 1, 2, 3), rows=(other(0x10, tag=1, ip=(6, 1, 2, 3)),))), ("tag_two_profile", dict(base, ip_tag=2, ip=(7, 1, 2, 3), rows=(other(0x10, tag=2, ip=(7, 9, 9, 9)),))),
            ("gate_error_copies", dict(base, name_len=0)), ("gate_error_rows_ignored", dict(base, name_len=0, rows=(other(0x10, signer=SIGNER),))), ("gate_ip_error", dict(base, ip=(10, 0, 0, 1))),
            ("no_caps_same_ip", dict(base, name_cap=0, desc_cap=0, rows=(other(0x10, ip=(8, 8, 8, 8)),))), ("no_name_cap_same_signer", dict(base, name_cap=0, rows=(other(0x10, signer=SIGNER),))), ("no_desc_cap_same_ip", dict(base, desc_cap=0, rows=(other(0x10, ip=(8, 8, 8, 8)),))),
            ("register_above_rise", dict(base, commission=10000)), ("change_rise_refused", dict(base, commission=101, cl=1, prev=100)), ("change_rise_ok", dict(base, commission=100, cl=1, prev=0)), ("change_fall_ok", dict(base, commission=9000, cl=1, prev=10000)), ("change_same_ok", dict(base, commission=9000, cl=1, prev=9000)),
            ("change_flag_two", dict(base, commission=500, cl=2, prev=100)), ("change_flag_three", dict(base, commission=500, cl=3, prev=100))]
    private = dict(base, ip=(10, 0, 0, 1))
    rows += [("set_absent_root", dict(private, set_root=False)), ("set_member_only", dict(private, members=(VALIDATOR,))), ("set_empty_leaf", dict(private, members=())), ("set_miss_low", dict(private, members=(low,))), ("set_miss_high", dict(private, members=(high,))),
             ("set_first", dict(private, members=(VALIDATOR, high))), ("set_last", dict(private, members=(low, VALIDATOR))), ("set_full_leaf", dict(private, members=tuple(key_of(0x10 + at) for at in range(10)) + (VALIDATOR,))), ("set_full_miss", dict(private, members=tuple(key_of(0x40 + at) for at in range(11)))),
             ("set_deep_left", dict(private, set_height=1, members=(VALIDATOR, high, key_of(0x50)))), ("set_deep_mid", dict(private, set_height=1, members=(low, VALIDATOR, high))), ("set_deep_right", dict(private, set_height=1, members=(low, key_of(0x18), VALIDATOR))), ("set_deep_miss", dict(private, set_height=1, members=(low, key_of(0x18), high))),
             ("set_tall", dict(private, set_height=3, members=(low, VALIDATOR, high, key_of(0x50), key_of(0x51), key_of(0x52), key_of(0x53)))), ("set_tall_miss", dict(private, set_height=3, members=(low, key_of(0x18), high, key_of(0x50), key_of(0x51), key_of(0x52), key_of(0x53)))),
             ("set_public_member", dict(base, members=(VALIDATOR,)))]
    rows += [("left_leaf_empty", dict(base, height=1, rows=(other(0x10, signer=SIGNER),))), ("left_leaf_empty_clean", dict(base, height=1, rows=(other(0x10),)))]
    many = tuple(other(0x40 + at) for at in range(11))
    rows += [("full_leaf_clean", dict(base, rows=many)), ("full_leaf_last_hit", dict(base, rows=many[:10] + (other(0x60, ip=(8, 8, 8, 8)),))), ("full_leaf_last_signer", dict(base, rows=many[:10] + (other(0x60, signer=SIGNER),)))]
    wide = tuple(other(0x40 + at) for at in range(9))
    rows += [("fan_two_clean", dict(base, height=1, fan=2, rows=wide)), ("fan_two_last", dict(base, height=1, fan=2, rows=wide[:8] + (other(0x60, ip=(8, 8, 8, 8)),))), ("fan_two_first", dict(base, height=1, fan=2, rows=(other(0x10, signer=SIGNER),) + wide[1:]))]
    for height in (1, 2, 3, 7, 8, 9, 10, 15, 16, 17):
        chain = tuple(other(0x40 + at) for at in range(7))
        rows.append(("tall_%d_clean" % height, dict(base, height=height, rows=chain)))
        rows.append(("tall_%d_last" % height, dict(base, height=height, rows=chain[:-1] + (other(0x70, ip=(8, 8, 8, 8)),))))
        rows.append(("tall_%d_first" % height, dict(base, height=height, rows=(other(0x10, signer=SIGNER),) + chain[1:])))
    return rows


def named_cases():
    return [Case("gate_" + name, **fields) for name, fields in gate_named()] + [Case("scan_" + name, **fields) for name, fields in scan_named()]


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11 ^ state


def vector_cases(count):
    source = lcg(0x3BFC)
    rows = []
    for index in range(count):
        word = next(source)
        prev = next(source) >> (word & 63)
        commission = (prev + (word >> 6 & 3) - 1) & MASK[8] if word >> 8 & 1 else next(source) >> (word >> 9 & 63)
        fields = dict(commission=commission, prev=prev, cl=word >> 15 & 3, dl=word >> 17 & 1, ip_tag=word >> 18 & 1, ip=tuple(next(source).to_bytes(8, "little")[:4]), name_len=word >> 19 & 63, desc_len=word >> 25 & 0x7FF, name_cap=word >> 36 & 3, desc_cap=word >> 38 & 3)
        if word >> 40 & 1:
            shared = fields["ip"]
            mates = [Row(key_of(0x10 + at), ip=shared if word >> (41 + at) & 7 == 0 else (1, 2, 3, at), signer=SIGNER if word >> (44 + at) & 7 == 0 else None) for at in range(word >> 56 & 7)]
            fields.update(rows=tuple(mates), members=(VALIDATOR,) if word >> 59 & 1 else (), height=0)
            fields["dl"] = 0
        rows.append(Case("v%d" % index, **fields))
    return rows


def piece_rows(harness):
    """Both ends of each length piece: same status and same reached rows."""
    rows = []
    machine = harness.machine
    for field, pieces in (("name_len", ((0, 0), (1, 50), (51, TOP))), ("desc_len", ((0, 0), (1, 1000), (1001, TOP)))):
        for low, high in pieces:
            walked, results = [], []
            for value in (low, high):
                case = Case("%s_%#x" % (field, value), **{field: value})
                saved = machine.seen
                machine.seen = set()
                got = harness.run(case)
                walked.append(machine.seen)
                machine.seen = saved | walked[-1]
                if got != spec_run(case, harness.before):
                    raise EvidenceError("piece end %#x" % value)
                results.append(struct.unpack_from("<H", got[2], OUT - HEAP_BASE)[0])
            if results[0] != results[1] or walked[0] != walked[1]:
                raise EvidenceError("piece %#x..%#x splits" % (low, high))
            rows.append((field, low, high, "%#x" % results[0]))
    return rows


def compare_only(rows):
    """Between the address test and the success copy the lengths and bps only meet add and compare rows."""
    window = [row for row in rows if IP_OK <= row.va < 0x3BFCCEA]
    allowed = {"mov", "add", "cmp", "jcc", "test", "cmov", "set"}
    other_ops = sorted({row.op for row in window} - allowed)
    if other_ops:
        raise EvidenceError("window has %r" % other_ops)
    return [("%#x" % row.va, row.op, row.data.hex()) for row in window]


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


def slot_rows(image):
    if image.relative().get(SLOT_GATE) != GATE:
        raise EvidenceError("gate slot")
    sites = slot_sites(image, SLOT_GATE)
    if sites != [0x39920CE]:
        raise EvidenceError("gate sites %r" % sites)
    return [("%#x" % SLOT_GATE, "%#x" % GATE, "%#x" % sites[0])]


PINS = (
    (0x399536F, "45 31 c9", "register path: r9d = 0, so no previous commission is passed"),
    (0x3995372, "e8", "register path calls the scan"),
    (0x3995A1E, "49 8b 4f e0", "change path: rcx = stored commission at record +0x30"),
    (0x3995A22, "80 7c 24 17 00", "change path: test the patch tag"),
    (0x3995A27, "4c 0f 44 f1", "change path: no patch keeps the stored commission"),
    (0x3995AE1, "48 89 0c 24", "change path: stored commission is the stack argument"),
    (0x3995AFA, "41 b9 01 00 00 00", "change path: r9d = 1, previous commission present"),
    (0x3995B19, "e8", "change path calls the scan"),
    (0x3994FC2, "48 b8 cb cc cc cc cc cc cc 0c", "change path: commission patch bound 0x0ccccccccccccccb"),
    (0x399560B, "49 83 fd 65", "change path: name patch length below 101 else tag 0x143"),
    (0x39958CA, "49 81 f8 e9 03 00 00", "change path: description patch length below 1001 else tag 0x143"),
    (0x3995B26, "3d 86 01 00 00", "both paths test the ok tag"),
)


def pin_rows(image):
    rows = []
    for va, text, note in PINS:
        want = bytes.fromhex(text)
        got = bytes(image.blob[image.offset(va):image.offset(va) + len(want)])
        if got != want:
            raise EvidenceError("pin %#x: %s" % (va, got.hex()))
        if image.fde(va)[0] != HANDLER:
            raise EvidenceError("pin outside the handler %#x" % va)
        rows.append(("%#x" % va, got.hex(), note))
    for site in (0x3995372, 0x3995B19):
        if site not in direct_to(image, SCAN):
            raise EvidenceError("scan call %#x" % site)
    if sorted(direct_to(image, SCAN)) != [0x3995372, 0x3995B19]:
        raise EvidenceError("scan has other callers")
    return rows


TEXT_TAGS = (TAG_IP, TAG_COMMISSION, TAG_SAME_IP, TAG_SAME_SIGNER)
FORMAT_TAGS = ((TAG_NAME, 0x20B0F8, 0x200F12, NAME_MAX), (TAG_DESC, 0x20B0D8, 0x1E5786, DESC_MAX))


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in TEXT_TAGS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
        at = data.find(b"\x48\x8d\x35")
        if at < 0 or data[at + 7] != 0xBA:
            raise EvidenceError("status arm %#x has another shape" % tag)
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0]
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
    for tag, literal, piece, want in FORMAT_TAGS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
        if data[:3] != b"\x48\x8d\x05" or arm + 7 + struct.unpack_from("<i", data, 3)[0] != literal or data[0x1F:0x22] != b"\x48\x8d\x15" or arm + 0x26 + struct.unpack_from("<i", data, 0x22)[0] != piece:
            raise EvidenceError("format arm %#x" % tag)
        value = struct.unpack_from("<Q", image.blob, image.offset(literal))[0]
        if value != want:
            raise EvidenceError("format literal %#x" % tag)
        size = image.blob[image.offset(piece)]
        text = bytes(image.blob[image.offset(piece) + 1:image.offset(piece) + 1 + size]).decode("ascii")
        rows.append(("%#x" % tag, "%#x" % arm, text + "{" + str(value) + "}"))
    return rows


def text_rows(image):
    rows = []
    blob = bytes(image.blob)
    for text in (b"node_ipdelegations_disabledcommission_bpssigner", b"struct CValidatorProfile with 6 elements", b"validator_to_profile"):
        hits = [match.start() for match in re.finditer(re.escape(text), blob)]
        if not hits:
            raise EvidenceError("text %r" % text)
        rows.append((text.decode("ascii"), len(hits), "%#x" % hits[0]))
    return rows


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case, harness.before)
        if got != want:
            diff = [hex(HEAP_BASE + at) for at in range(COMPARED) if got[2][at] != want[2][at]][:12]
            raise EvidenceError("case %s: events %r != %r diff %s" % (case.name, got[1], want[1], diff))
        outcomes.append(got)
    return outcomes


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
            if harness.run(case) != spec_run(case, harness.before):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error):
            return case
    return None


CHAIN_STEP = "the same test runs on a path where the height is not a multiple of 8, so 8 and 9 both split the heights the same way"
EXPECTED_SURVIVORS = {
    (0x3BFCC0D, "immediate"): "the low byte is the first octet, fixed at 172 (even) on this path, so bit 0 of the mask reads 0 either way",
    (0x3BFCCCC, "immediate"): "with no previous value a limit of 10000 can never refuse, the cap row above already holds x <= 10000",
    (0x3992215, "immediate"): CHAIN_STEP, (0x39922F8, "immediate"): CHAIN_STEP,
}


def run_mutants(image, table, seen, lists):
    results = []
    for target in TARGETS:
        cases = lists[target]
        control = Harness(image)
        control.machine.step_limit = MUTANT_STEP_LIMIT
        if first_failure(control, cases) is not None:
            raise EvidenceError("an unedited image fails under the mutant step limit")
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            failed = first_failure(harness, cases)
            if failed is not None:
                results.append((va, kind, "killed", "whole run"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def mutant_lists(cases, ip):
    gate = [case for case in cases if case.rows is None]
    scan = [case for case in cases if case.rows is not None]
    return {GATE: gate + ip_cases(ip["classes"]), SCAN: scan}


def analyse(image, mutate=True, vectors=400):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    check_cases(harness, vector_cases(vectors))
    ip = prove_ip(harness)
    pieces = piece_rows(harness)
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, ip=ip, pieces=pieces, window=compare_only(table[GATE]), slots=slot_rows(image), pins=pin_rows(image), statuses=status_rows(image), texts=text_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, mutant_lists(cases, ip))
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    data = outcome[2]
    at = OUT - HEAP_BASE
    tag = struct.unpack_from("<H", data, at)[0]
    return "%#x" % tag, ",".join(str(event[0]) for event in outcome[1]), hashlib.sha256(data).hexdigest()[:16]


def spans(values):
    rows, first = [], values[0]
    for one, two in zip(values, values[1:] + [None]):
        if two != one + 1:
            rows.append(str(first) if first == one else "%d-%d" % (first, one))
            first = two
    return " ".join(rows)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    ip = result["ip"]
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("gate-slot.tsv", ("slot", "relative_target", "only_call_site"), result["slots"])
    tsv("handler-pins.tsv", ("address", "bytes", "meaning"), result["pins"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("rodata-text.tsv", ("text", "hits", "first_offset"), result["texts"])
    tsv("ip-octet-classes.tsv", ("octet", "class_values", "class_size"), [(lane, spans(group), len(group)) for lane, groups in enumerate(ip["classes"]) for group in groups])
    tsv("ip-paths.tsv", ("outcome", "branch_rows"), ip["paths"])
    tsv("ip-refused-blocks.tsv", ("block", "addresses"), REFUSED_BLOCKS)
    tsv("length-pieces.tsv", ("field", "low", "high", "status"), result["pieces"])
    tsv("limit-window.tsv", ("address", "operation", "bytes"), result["window"])
    tsv("outcomes.tsv", ("case", "status", "events", "state_digest"), [(case.name,) + describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"], "ip_class_runs": ip["runs"], "ip_paths": len(ip["paths"]), "ip_paths_in_set": ip["open_paths"], "ip_refused_addresses": ip["refused"], "ip_total_addresses": ip["total"],
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
