#!/usr/bin/env python3
"""Pin the node #94 voteL1Hash path from ELF bytes.

Arm 87 recovers a signer from a digest over a MessagePack pair of height and hex hash, checks it against the
sender, finds the sender as a voter key, as a linked listed address, or both, and hands the vote to a tracker.
A quorum result raises `highest_quorum_height`, pushes one row on `quorum_l1_hashes` with signatures keyed by
hot user, and prunes tracker heights below the vote height minus 50,000. Real bytes run under recording stubs,
a separately written rule list predicts every status, stub event and tree state, and reached conditional rows
are mutated. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/l1_hash_vote_path.py --out <dir>
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
SHIFTS = {0: "rol", 4: "shl", 5: "shr", 7: "sar"}


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
        elif op == "rol":
            count = row.b[1] & (8 * width - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, value << count | value >> (8 * width - count))
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



WRAP = 0x1E5F010
KEY_HASH = 0x37E5620
ENCODE = 0x32478A0
PUT_LEN = 0x3598E20
PUT_U64 = 0x31FBEA0
PUT_BYTE = 0x359B320
PUT_STR = 0x3599A40
FINISH = 0x31FFE10
CORE = 0x394AC70
SCAN = 0x3B45C80
SCAN_NEXT = 0x330E890
COLLECT = 0x3315A60
TAKE = 0x3BD7AF0
TAKE_NEXT = 0x33B16E0
SORT = 0x3386340
BULK = 0x2FC0390
PRUNE = 0x3942C90
SPLIT = 0x2FB4520
SPLIT_COUNT = 0x2FB27F0
GATHER = 0x3BCDCA0
GATHER_LOOP = 0x3BE4C90
GATHER_NEXT = 0x33B4700
FILTER = 0x3BC3150
MARKER = 0x359BE70
WRITE_A = 0x359BAA0
WRITE_B = 0x359B870
WRITE_C = 0x359BCD0
HEX = 0x29ED380
NAMES = {WRAP: "arm_87_wrapper", KEY_HASH: "signed_digest", ENCODE: "signed_encoding", PUT_LEN: "rmp_array_header", PUT_U64: "rmp_first_field", PUT_BYTE: "rmp_uint", PUT_STR: "rmp_str", FINISH: "encoding_finish", CORE: "vote_core", SCAN: "height_hash_scan", SCAN_NEXT: "scan_key_next",
         COLLECT: "hot_map_collect", TAKE: "hot_rows_take", TAKE_NEXT: "voter_map_next", SORT: "hot_rows_sort", BULK: "hot_map_build", PRUNE: "height_prune", SPLIT: "height_split", SPLIT_COUNT: "split_counts", GATHER: "removed_gather", GATHER_LOOP: "removed_loop", GATHER_NEXT: "removed_next", FILTER: "quorum_row_filter", MARKER: "rmp_marker", WRITE_A: "rmp_data_write_a", WRITE_B: "rmp_data_write_b", WRITE_C: "rmp_data_write_c", HEX: "prefixed_hex"}
TARGETS = tuple(sorted(NAMES))
MUTATED = (WRAP, KEY_HASH, ENCODE, PUT_LEN, PUT_BYTE, PUT_STR, HEX, CORE, SCAN, COLLECT, TAKE, SORT, PRUNE, GATHER_LOOP, FILTER)

SLOT_RECOVER = 0x576FE58
SLOT_NEW = 0x57700C0
SLOT_UPDATE = 0x57700C8
SLOT_FINAL = 0x57700D0
SLOT_HEX = 0x5773120
SLOT_CORE = 0x5773128
SLOT_VOTER = 0x5773148
SLOT_HOT = 0x5775C88
SLOT_VEC_GROW = 0x5774488
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_ALLOC_ERROR = 0x576E020
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_NONE = 0x576E470
SLOT_OVERFLOW = 0x576E118
SLOT_ONCE = 0x576E8B8
SLOT_LONG_SORT = 0x57758E0
ONCE_STATE = 0x577AB98
VOTER = 0x33690C0
TRACK = 0x39438E0
STATUS_DROP = 0x3999770
ROW_REMOVED = 0x3941930
ROW_DROP = 0x3BBE8A0
MAP_DROP = 0x33F94F0
RAW_GROW = 0x32D6A00
FINISH_GROW = 0x32D6740
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_LIMIT = 0x13F
TAG_BAD_SIGNATURE = 0x7A
TAG_SIGNER = 0x11F
TAG_NOT_VOTER = 0x91
TAG_NOT_VALIDATOR = 0x2A
TAG_NO_KEY = 0x94
OUTCOME_DONE = 0x9
OUTCOME_ERROR = 0xE
STATUS_TABLE = 0x59A8D0
STATUS_TAGS = (TAG_LIMIT, TAG_BAD_SIGNATURE, TAG_SIGNER, TAG_NOT_VOTER)
HEIGHT_LIMIT = 0x0CCCCCCCCCCCCCCC
WINDOW = 50000
ROW_SIZE = 0x58

S_TRACKER = 0x35B0
S_CTX = 0x3840
S_LISTED = 0x36A0
S_USERS = 0x8F8
U_MAP = 0x150
C_EPOCH = 0x48
T_ROWS = 0x28
T_QUORUM = 0x40
T_HIGHEST = 0x58
Q_CAP, Q_PTR, Q_LEN = 0, 8, 0x10

Layout = collections.namedtuple("Layout", "name key_at key_size val_at val_size parent index count size")
HEIGHTS = Layout("heights", 0x2C8, 8, 0, 0x40, 0x2C0, 0x320, 0x322, 0x328)
HASHES = Layout("hashes of one height", 0, 0x20, 0x160, 0x30, 0x370, 0x378, 0x37A, 0x380)
VOTERS = Layout("voter key to signature", 0, 0x20, 0x168, 0x48, 0x160, 0x480, 0x482, 0x488)
LISTED = Layout("20-byte set", 8, 0x14, 0, 0, 0, 0xE4, 0xE6, 0xE8)
USERS = Layout("linked users", 8, 0x58, 0x3D0, 0x14, 0, 0x4AC, 0x4AE, 0x4B0)
HOT = Layout("hot_user_to_signature", 0x320, 0x14, 8, 0x48, 0, 0x3FC, 0x3FE, 0x400)
LAYOUTS = (HEIGHTS, HASHES, VOTERS, LISTED, USERS, HOT)

ARENA = HEAP_BASE + 0x1000
USED = 0x80000
ARENA_END = HEAP_BASE + 0x70000
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x300
SIGNER = HEAP_BASE + 0x600
HOLDER = HEAP_BASE + 0x640
VEC_AT = HEAP_BASE + 0x680
EPOCH = 7


def address(tag):
    return blob(tag, 20)


def blob(tag, size):
    """Distinct bytes, so that a shifted copy never matches by accident."""
    return bytes((tag + index) & 0xFF for index in range(size))


def user_key(link):
    return blob(0x70, 0x38) + link + blob(0x20, 0x0C)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        statics[ONCE_STATE] = 0
        statics[SLOT_CORE] = CORE
        statics[SLOT_HEX] = HEX
        table = {SLOT_RECOVER: self.on_recover, SLOT_NEW: self.on_new, SLOT_UPDATE: self.on_update, SLOT_FINAL: self.on_final, SLOT_VOTER: self.on_voter, SLOT_HOT: self.on_hot, SLOT_VEC_GROW: self.on_vec_grow,
                 SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_FAIL: self.on_stop, SLOT_ALLOC_ERROR: self.on_stop, SLOT_FREE: self.on_nothing, SLOT_MEMCPY: self.on_memcpy, SLOT_MEMMOVE: self.on_memcpy, SLOT_MEMCMP: self.on_memcmp, SLOT_NONE: self.on_none,
                 SLOT_OVERFLOW: self.on_overflow, SLOT_ONCE: self.on_once, SLOT_LONG_SORT: self.on_long_sort}
        for slot, hook in table.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        machine.calls = {TRACK: self.on_track, STATUS_DROP: self.on_nothing, ROW_REMOVED: self.on_removed, ROW_DROP: self.on_nothing, MAP_DROP: self.on_nothing, RAW_GROW: self.on_raw_grow, FINISH_GROW: self.on_finish_grow}
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

    def on_memcmp(self, machine):
        size = machine.regs[RDX]
        left, right = self.data(machine.regs[RDI], size), self.data(machine.regs[RSI], size)
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_none(self, machine):
        raise Panicked("option none")

    def on_overflow(self, machine):
        raise Panicked("add overflow")

    def on_once(self, machine):
        self.events.append(("once",))

    def on_new(self, machine):
        self.message = b""
        machine.regs[RAX] = 1

    def on_update(self, machine):
        self.message += self.data(machine.regs[RSI], machine.regs[RDX])

    def on_final(self, machine):
        self.put(machine.regs[RDI], stand_in_digest(self.message))
        self.events.append(("signed_bytes", self.message))

    def on_recover(self, machine):
        out, signature, digest = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.expect(self.data(digest, 32) == stand_in_digest(self.message), "digest handed to recovery")
        self.events.append(("recover", self.data(signature, 0x10)))
        if self.op.recovered is None:
            self.write(out, 1, 1)
            self.write(out + 8, RECOVER_ERROR)
        else:
            self.write(out, 0, 1)
            self.put(out + 1, self.op.recovered)

    def on_voter(self, machine):
        out, signer = machine.regs[RDI], self.data(machine.regs[RDX], 20)
        self.expect(machine.regs[RSI] == self.ctx and machine.regs[RCX] == EPOCH, "voter lookup arguments")
        hits = [key for key, who in self.scenario.validators if who == signer]
        if hits:
            self.write(out, TAG_OK, 2)
            self.put(out + 2, hits[0])
        else:
            self.write(out, TAG_NOT_VALIDATOR, 2)

    def on_hot(self, machine):
        out, key = machine.regs[RDI], self.data(machine.regs[RDX], 32)
        self.expect(machine.regs[RSI] == self.ctx and machine.regs[RCX] == EPOCH, "hot user lookup arguments")
        if key in self.scenario.hot:
            self.write(out, TAG_OK, 2)
            self.put(out + 2, self.scenario.hot[key])
        else:
            self.write(out, TAG_NO_KEY, 2)

    def on_vec_grow(self, machine):
        vec = machine.regs[RDI]
        cap, old = self.read(vec), self.read(vec + 8)
        wider = max(4, cap * 2)
        at = self.alloc(wider * ROW_SIZE)
        if cap:
            self.put(at, self.data(old, cap * ROW_SIZE))
        self.write(vec, wider)
        self.write(vec + 8, at)

    def on_raw_grow(self, machine):
        vec, have, extra, align, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX], machine.regs[R8]
        cap, old = self.read(vec), self.read(vec + 8)
        wider = max(cap * 2, have + extra, 8 if size == 1 else 4)
        at = self.alloc(wider * size)
        if have:
            self.put(at, self.data(old, have * size))
        self.write(vec, wider)
        self.write(vec + 8, at)

    def on_finish_grow(self, machine):
        out, have, old, wider = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX]
        self.expect(machine.regs[R8] == 1 and machine.regs[R9] == 1, "byte buffer growth")
        at = self.alloc(wider)
        if have:
            self.put(at, self.data(old, have))
        self.write(out, 0, 4)
        self.write(out + 8, at)
        self.write(out + 0x10, wider)

    def on_long_sort(self, machine):
        base, count = machine.regs[RDI], machine.regs[RSI]
        rows = sorted((self.data(base + index * 0x60, 0x60) for index in range(count)), key=lambda row: row[:20])
        for index, row in enumerate(rows):
            self.put(base + index * 0x60, row)

    def on_removed(self, machine):
        self.expect(machine.regs[RDI] == self.tracker, "removed row tracker")
        self.events.append(("removed", machine.regs[RSI]))

    def on_track(self, machine):
        out, tracker, height, digest, votes, signature = (machine.regs[reg] for reg in (RDI, RSI, RDX, RCX, R8, R9))
        top = machine.regs[RSP]
        self.expect(tracker == self.tracker and self.read(top + 8) == self.ctx, "tracker arguments")
        self.expect(self.read(self.read(top + 16)) == self.holder, "listed set argument")
        voter = self.data(votes + 1, 32) if self.read(votes, 1) else None
        hard = self.data(votes + 0x22, 20) if self.read(votes + 0x21, 1) else None
        self.events.append(("track", height, self.data(digest, 32), voter, hard, self.data(signature, 0x10)))
        won = self.op.quorum
        if won is None:
            self.write(out, 0, 4)
            return
        self.write(out, 1, 4)
        self.put(out + 8, won[0])
        self.tree(out + 0x28, VOTERS, [(key, value) for key, value in sorted(won[1].items())])
        self.write(out + 0x40, HARD_ROOT)
        self.write(out + 0x48, HARD_HEIGHT)
        self.write(out + 0x50, len(won[1]) + 1)

    def build(self, layout, items):
        """Build a tree of height 0 or 1 in the fixture arena; items are sorted (key bytes, value bytes)."""
        def node(entries, edges=()):
            size = layout.size + 12 * 8 if edges else layout.size
            at = self.alloc(size)
            self.put(at, bytes([0xDD]) * size)
            self.write(at + layout.parent, 0)
            self.write(at + layout.count, len(entries), 2)
            for index, (key, value) in enumerate(entries):
                if layout.key_size:
                    self.put(at + layout.key_at + index * layout.key_size, key)
                if layout.val_size:
                    self.put(at + layout.val_at + index * layout.val_size, value)
            for index, child in enumerate(edges):
                self.write(at + layout.size + 8 * index, child)
                self.write(child + layout.parent, at)
                self.write(child + layout.index, index, 2)
            return at
        if len(items) <= 11:
            return node(items)
        children, separators = [], []
        at = 0
        while at < len(items):
            take = 11 if len(items) - at == 11 else 10
            children.append(node(items[at:at + take]))
            if at + take < len(items):
                separators.append(items[at + take])
            at += take + 1
        self.expect(len(separators) <= 11, "fixture tree too wide")
        return node(separators, children)

    def height(self, items):
        return 0 if len(items) <= 11 else 1

    def positions(self, layout, root, height):
        if not root:
            return []
        count = self.read(root + layout.count, 2)
        if height == 0:
            return [(root, index) for index in range(count)]
        out = []
        for index in range(count + 1):
            out += self.positions(layout, self.read(root + layout.size + 8 * index), height - 1)
            if index < count:
                out.append((root, index))
        return out

    def walk(self, layout, root, height):
        rows = []
        for node, index in self.positions(layout, root, height):
            value = node + layout.val_at + index * layout.val_size
            rows.append((self.data(node + layout.key_at + index * layout.key_size, layout.key_size), value))
        return rows

    def tree(self, at, layout, items):
        tree = self.build(layout, items) if items else 0
        self.write(at, tree)
        self.write(at + 8, self.height(items))
        self.write(at + 0x10, len(items))

    def fresh(self, scenario):
        memory = self.machine.memory
        memory.reset(USED)
        memory.statics[ONCE_STATE] = 0
        self.top = ARENA
        self.events = []
        self.scenario = scenario
        self.message = b""
        self.state = HEAP_BASE + 0x70000
        memory.put_bytes(self.state, bytes(0x4000))
        self.tracker = self.state + S_TRACKER
        self.ctx = self.state + S_CTX
        self.holder = self.state + S_LISTED
        self.write(self.ctx + C_EPOCH, EPOCH)
        self.write(self.tracker + T_QUORUM + Q_PTR, 8)
        self.write(self.tracker + T_HIGHEST, scenario.highest)
        self.tree(self.holder, LISTED, [(item, b"") for item in sorted(scenario.listed)])
        self.write(HOLDER, self.holder)
        self.tree(self.state + S_USERS + U_MAP, USERS, [(user_key(link), value) for link, value in sorted(scenario.users)])
        items = []
        for height, hashes in sorted(scenario.rows.items()):
            inner = sorted((digest, bytes(0x30)) for digest in hashes)
            value = self.build(HASHES, inner) if inner else 0
            items.append((struct.pack("<Q", height), struct.pack("<QQQ", value, self.height(inner), len(inner)) + b"\x01" + blob(0x10, 0x20) + b"\x00" + bytes(6)))
        self.tree(self.tracker + T_ROWS, HEIGHTS, items)

    def quorum_rows(self):
        rows = []
        vec = self.tracker + T_QUORUM
        base = self.read(vec + Q_PTR)
        for index in range(self.read(vec + Q_LEN)):
            at = base + index * ROW_SIZE
            hot = {}
            if self.read(at + 0x38):
                for key, value in self.walk(HOT, self.read(at + 0x28), self.read(at + 0x30)):
                    hot[key] = self.data(value, 0x48)
            rows.append((self.read(at), self.data(at + 8, 32), hot, self.read(at + 0x40), self.read(at + 0x48), self.read(at + 0x50)))
        return rows

    def dump(self):
        at = self.tracker + T_ROWS
        heights = [struct.unpack("<Q", key)[0] for key, _ in self.walk(HEIGHTS, self.read(at), self.read(at + 8))] if self.read(at + 0x10) else []
        self.expect(len(heights) == self.read(at + 0x10), "height map length")
        return heights, self.read(self.tracker + T_HIGHEST), self.quorum_rows()

    def perform(self, op):
        memory = self.machine.memory
        memory.put_bytes(OUT, bytes([0xEE]) * 0x70)
        self.events = []
        self.op = op
        memory.statics[ONCE_STATE] = 1 if op.once else 0
        self.put(ACTION, op.l1 + struct.pack("<Q", op.height) + SIGNATURE)
        self.put(SIGNER, op.signer)
        if op.kind == "core":
            self.machine.run(CORE, {RDI: OUT, RSI: self.tracker, RDX: ACTION, RCX: SIGNER, R8: self.ctx, R9: self.state + S_USERS}, (self.holder,))
            tag = self.read(OUT, 2)
            view = (tag,)
            if tag == TAG_LIMIT:
                view = (tag, self.read(OUT + 8))
            elif tag == TAG_OK:
                view = (tag, self.read(OUT + 2, 1))
            return view, tuple(self.events)
        if op.kind == "scan":
            self.machine.run(SCAN, {RDI: OUT, RSI: self.tracker, RDX: op.height, RCX: ACTION})
            size = self.read(OUT)
            if size == 1 << 63:
                return (None,), ()
            base = self.read(OUT + 8)
            return (tuple(self.data(base + index * 32, 32) for index in range(self.read(OUT + 0x10))),), ()
        if op.kind == "filter":
            self.put(VEC_AT, struct.pack("<QQQ", 0, 8, 0))
            rows = op.vec_rows
            at = self.alloc(len(rows) * ROW_SIZE + ROW_SIZE)
            for index, row in enumerate(rows):
                self.put(at + index * ROW_SIZE, row)
            self.put(VEC_AT, struct.pack("<QQQ", len(rows), at, len(rows)))
            self.machine.run(FILTER, {RDI: VEC_AT})
            size = self.read(VEC_AT + 0x10)
            return (tuple(self.data(at + index * ROW_SIZE, ROW_SIZE) for index in range(size)),), ()
        self.machine.run(WRAP, {RDI: OUT, RSI: ACTION, RDX: SIGNER, RCX: self.state})
        tag = self.read(OUT, 1)
        if tag == OUTCOME_DONE:
            return (tag, self.read(OUT + 1, 1)), tuple(self.events)
        status = self.read(OUT + 8, 2)
        return ((tag, status, self.read(OUT + 0x10)) if status in (TAG_LIMIT, TAG_BAD_SIGNATURE, TAG_SIGNER) else (tag, status)), tuple(self.events)

    def run(self, scenario):
        self.fresh(scenario)
        trace = []
        for op in scenario.ops:
            try:
                view, events = self.perform(op)
            except Panicked as stop:
                trace.append(("panic", stop.args[0], ()))
                break
            trace.append((view, events, self.dump()))
        return trace


HEIGHT = 900000
L1 = blob(0x51, 32)
L1B = blob(0x61, 32)
SIGNATURE = blob(0xC1, 0x48)
RECOVER_ERROR = 0x1122334455667788
HARD_ROOT = 0x600000123450
HARD_HEIGHT = 0x77


def stand_in_digest(message):
    """Not BLAKE3: a value that depends on every hashed byte, so a wrong input to recovery fails the stub check."""
    return hashlib.sha256(message).digest()


def validator(tag):
    return (blob(tag, 32), address(tag))


V1, V2, V3, V4 = validator(0x11), validator(0x22), validator(0x33), validator(0x44)
EQUAL = (V1, V2, V3, V4)
OUTSIDER = address(0xF0)
LINK1, LINK2, LINK3 = address(0xA1), address(0xB2), address(0xC3)
HOT1, HOT2, HOT3, HOT4 = address(0xD1), address(0x09), address(0x75), address(0x3C)
HOTS = {V1[0]: HOT1, V2[0]: HOT2, V3[0]: HOT3, V4[0]: HOT4}


def sig(tag):
    return blob(tag, 0x48)


class Op:
    def __init__(self, kind, **fields):
        self.kind = kind
        defaults = dict(l1=L1, height=HEIGHT, signer=V1[1], recovered="same", quorum=None, once=False, vec_rows=())
        defaults.update(fields)
        self.__dict__.update(defaults)
        if self.recovered == "same":
            self.recovered = self.signer

    def __repr__(self):
        return self.kind


class Scenario:
    def __init__(self, name, ops, validators=EQUAL, hot=HOTS, listed=(), users=(), rows=None, highest=0):
        self.name = name
        self.ops = ops
        self.validators = validators
        self.hot = hot
        self.listed = tuple(listed)
        self.users = tuple(users)
        self.rows = rows or {}
        self.highest = highest


# ---- the rule list; it is written from the path description, never from fixture reads ----

def rmp_uint(value):
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return b"\xcc" + bytes([value])
    if value <= 0xFFFF:
        return b"\xcd" + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return b"\xce" + struct.pack(">I", value)
    return b"\xcf" + struct.pack(">Q", value)


def signed_bytes(height, l1):
    return b"\x92" + rmp_uint(height) + b"\xd9\x42" + b"0x" + l1.hex().encode()


def equal_mask(left, right):
    """The leftover pmovmskb word: lanes 0-3 also need bytes 16-19 equal."""
    mask = 0
    for lane in range(16):
        same = left[lane] == right[lane]
        if lane < 4:
            same = same and left[16 + lane] == right[16 + lane]
        mask |= int(same) << lane
    return mask


class Model:
    def __init__(self, scenario):
        self.scenario = scenario
        self.rows = {height: sorted(hashes) for height, hashes in scenario.rows.items()}
        self.highest = scenario.highest
        self.quorum = []

    def scan(self, height, l1):
        hashes = self.rows.get(height)
        if not hashes or hashes == [l1]:
            return None
        return tuple(hashes)

    def hot_map(self, voters):
        out = {}
        for key in sorted(voters):
            if key in self.scenario.hot:
                out[self.scenario.hot[key]] = voters[key]
        return out

    def core(self, op):
        if op.height >= HEIGHT_LIMIT:
            return (TAG_LIMIT, op.height), ()
        links = [value for link, value in sorted(self.scenario.users) if user_key(link)[0x38:0x4C] == op.signer]
        hard = links[0] if links and links[0] in self.scenario.listed else None
        hits = [key for key, who in self.scenario.validators if who == op.signer]
        voter = hits[0] if hits else None
        if voter is None and hard is None:
            return (TAG_NOT_VOTER,), ()
        events = [("track", op.height, op.l1, voter, hard, SIGNATURE[:0x10])]
        if op.quorum is None:
            return (TAG_OK, 0), tuple(events)
        winner, voters = op.quorum
        self.highest = max(self.highest, op.height)
        self.quorum.append((op.height, winner, self.hot_map(voters), HARD_ROOT, HARD_HEIGHT, len(voters) + 1))
        if op.once:
            events.append(("once",))
        floor = max(op.height - WINDOW, 0)
        for height in sorted(self.rows):
            if height < floor:
                events.append(("removed", height))
                del self.rows[height]
        return (TAG_OK, 1), tuple(events)

    def apply(self, op):
        if op.kind == "core":
            return self.core(op)
        if op.kind == "scan":
            return (self.scan(op.height, op.l1),), ()
        if op.kind == "filter":
            return (tuple(row for row in op.vec_rows if struct.unpack_from("<Q", row, 0x38)[0]),), ()
        if op.height >= HEIGHT_LIMIT:
            return (OUTCOME_ERROR, TAG_LIMIT, op.height), ()
        events = [("signed_bytes", signed_bytes(op.height, op.l1)), ("recover", SIGNATURE[:0x10])]
        if op.recovered is None:
            return (OUTCOME_ERROR, TAG_BAD_SIGNATURE, RECOVER_ERROR), tuple(events)
        if op.recovered != op.signer:
            return (OUTCOME_ERROR, TAG_SIGNER, equal_mask(op.recovered, op.signer)), tuple(events)
        view, more = self.core(op)
        events += more
        if view[0] == TAG_OK:
            return (OUTCOME_DONE, view[1]), tuple(events)
        return (OUTCOME_ERROR, view[0]), tuple(events)

    def snapshot(self):
        return sorted(self.rows), self.highest, list(self.quorum)


def spec_run(scenario):
    model = Model(scenario)
    trace = []
    for op in scenario.ops:
        view, events = model.apply(op)
        trace.append((view, events, model.snapshot()))
    return trace


def core(who=V1, **fields):
    return Op("core", signer=who[1] if isinstance(who, tuple) else who, **fields)


def arm(who=V1, **fields):
    return Op("arm_87", signer=who[1] if isinstance(who, tuple) else who, **fields)


def won(*voters, digest=L1):
    return (digest, {voter[0]: sig(0x40 + index) for index, voter in enumerate(voters)})


def many_validators(count):
    return tuple(validator(0x03 + 2 * index) for index in range(count))


WIDE = many_validators(30)
WIDE_HOT = {key: address(0xE0 - 3 * index) for index, (key, _) in enumerate(WIDE)}


def quorum_row(height, tag, hot_size):
    return struct.pack("<Q", height) + blob(tag, 0x30) + struct.pack("<Q", hot_size) + blob(tag + 0x40, 0x18)


def named_scenarios():
    limit = HEIGHT_LIMIT
    users = ((V3[1], LINK1), (OUTSIDER, LINK2))
    pair = (V1, V2)
    return [Scenario("arm_87_first_vote", [arm()]),
            Scenario("arm_87_quorum", [arm(quorum=won(*pair))]),
            Scenario("arm_87_height_zero", [arm(height=0)]),
            Scenario("arm_87_height_small_uint", [arm(height=0x7F), arm(height=0x80), arm(height=0xFF), arm(height=0x100), arm(height=0xFFFF), arm(height=0x10000), arm(height=0xFFFFFFFF), arm(height=0x100000000)]),
            Scenario("arm_87_limit", [arm(height=limit)]),
            Scenario("arm_87_limit_minus_one", [arm(height=limit - 1)]),
            Scenario("arm_87_limit_plus_one", [arm(height=limit + 1)]),
            Scenario("arm_87_bad_signature", [arm(recovered=None)]),
            Scenario("arm_87_other_signer", [arm(recovered=OUTSIDER)]),
            Scenario("arm_87_signer_differs_low_byte", [arm(recovered=V1[1][:19] + b"\x00")]),
            Scenario("arm_87_signer_differs_first_byte", [arm(recovered=b"\x00" + V1[1][1:])]),
            Scenario("arm_87_not_voter", [arm(OUTSIDER)]),
            Scenario("arm_87_hard_only", [arm(OUTSIDER)], users=((OUTSIDER, LINK1),), listed=(LINK1,)),
            Scenario("arm_87_other_hash", [arm(l1=L1B)]),
            Scenario("core_limit", [core(height=limit)]),
            Scenario("core_limit_minus_one", [core(height=limit - 1)]),
            Scenario("core_validator_no_link", [core()]),
            Scenario("core_validator_and_link", [core(V3)], users=users, listed=(LINK1,)),
            Scenario("core_link_not_listed", [core(V3)], users=users, listed=(LINK2,)),
            Scenario("core_link_only", [core(OUTSIDER)], users=users, listed=(LINK2,)),
            Scenario("core_link_only_not_listed", [core(OUTSIDER)], users=users, listed=(LINK1,)),
            Scenario("core_nobody", [core(address(0x66))], users=users, listed=(LINK1, LINK2)),
            Scenario("core_two_links_first_in_key_order", [core(V3)], users=((V3[1], LINK3), (V3[1], LINK1)), listed=(LINK1,)),
            Scenario("core_two_links_second_listed_only", [core(V3)], users=((V3[1], LINK3), (V3[1], LINK1)), listed=(LINK3,)),
            Scenario("core_wide_links", [core(WIDE[20])], validators=WIDE, hot=WIDE_HOT, users=tuple((item[1], address(0x20 + index)) for index, item in enumerate(WIDE)), listed=(address(0x34),)),
            Scenario("core_wide_links_last", [core(WIDE[29])], validators=WIDE, hot=WIDE_HOT, users=tuple((item[1], address(0x20 + index)) for index, item in enumerate(WIDE)), listed=(address(0x3D),)),
            Scenario("core_wide_listed", [core(V3)], users=((V3[1], address(0x40)),), listed=[address(0x30 + 2 * index) for index in range(30)]),
            Scenario("core_wide_listed_miss", [core(V3)], users=((V3[1], address(0x41)),), listed=[address(0x30 + 2 * index) for index in range(30)]),
            Scenario("core_empty_listed_set", [core(V3)], users=users),
            Scenario("core_tracker_no_result", [core()], rows={HEIGHT: [L1]}),
            Scenario("core_quorum_row", [core(quorum=won(V1, V2, V3))]),
            Scenario("core_quorum_winner_hash_differs", [core(quorum=won(V1, V2, digest=L1B))]),
            Scenario("core_quorum_keeps_higher_highest", [core(quorum=won(V1))], highest=HEIGHT + 9),
            Scenario("core_quorum_equal_highest", [core(quorum=won(V1))], highest=HEIGHT),
            Scenario("core_quorum_raises_highest", [core(quorum=won(V1))], highest=HEIGHT - 1),
            Scenario("core_two_quorums", [core(quorum=won(V1)), core(height=HEIGHT + 1, quorum=won(V2)), core(height=HEIGHT - 1, quorum=won(V3))]),
            Scenario("core_many_quorums_grow_list", [core(height=HEIGHT + index, quorum=won(V1)) for index in range(6)]),
            Scenario("core_once_cold_path", [core(once=True, quorum=won(V1))], rows={1: [L1]}),
            Scenario("hot_voter_without_user_dropped", [core(quorum=won(V1, V2, V3))], hot={V1[0]: HOT1, V3[0]: HOT3}),
            Scenario("hot_no_voter_resolves", [core(quorum=won(V1, V2))], hot={}),
            Scenario("hot_first_voter_dropped_only", [core(quorum=won(V1, V2))], hot={V2[0]: HOT2}),
            Scenario("hot_last_voter_dropped_only", [core(quorum=won(V1, V2))], hot={V1[0]: HOT1}),
            Scenario("hot_empty_voter_map", [core(quorum=won())]),
            Scenario("hot_one_voter", [core(quorum=won(V4))]),
            Scenario("hot_two_voters_same_user", [core(quorum=won(V1, V2))], hot={V1[0]: HOT1, V2[0]: HOT1}),
            Scenario("hot_order_reversed_by_user", [core(quorum=won(V1, V2, V3, V4))]),
            Scenario("hot_thirty_voters", [core(quorum=won(*WIDE))], validators=WIDE, hot=WIDE_HOT),
            Scenario("hot_twelve_voters", [core(quorum=won(*WIDE[:12]))], validators=WIDE, hot=WIDE_HOT),
            Scenario("prune_window_edge_stays", [core(quorum=won(V1))], rows={HEIGHT - WINDOW: [L1]}),
            Scenario("prune_one_below_window", [core(quorum=won(V1))], rows={HEIGHT - WINDOW - 1: [L1]}),
            Scenario("prune_keeps_above", [core(quorum=won(V1))], rows={HEIGHT - WINDOW - 2: [L1], HEIGHT - WINDOW - 1: [L1B], HEIGHT - 3: [L1], HEIGHT: [L1], HEIGHT + 4: [L1B]}),
            Scenario("prune_no_quorum_no_prune", [core()], rows={1: [L1]}),
            Scenario("prune_low_height_saturates", [core(height=WINDOW - 1, quorum=won(V1))], rows={0: [L1], 1: [L1]}),
            Scenario("prune_height_equal_window", [core(height=WINDOW, quorum=won(V1))], rows={0: [L1], 1: [L1]}),
            Scenario("prune_all_below", [core(quorum=won(V1))], rows={1: [L1], 2: [L1], 3: [L1]}),
            Scenario("prune_wide_map", [core(quorum=won(V1))], rows={HEIGHT - WINDOW - 15 + index: [L1] for index in range(30)}),
            Scenario("prune_wide_map_all", [core(quorum=won(V1))], rows={1000 + index: [L1] for index in range(30)}),
            Scenario("prune_wide_map_none", [core(quorum=won(V1))], rows={HEIGHT + index: [L1] for index in range(30)}),
            Scenario("prune_uses_vote_height", [core(height=HEIGHT - WINDOW, quorum=won(V1))], rows={HEIGHT - 2 * WINDOW - 1: [L1], HEIGHT - WINDOW - 1: [L1]}, highest=HEIGHT),
            Scenario("prune_empty_map", [core(quorum=won(V1))]),
            Scenario("scan_empty", [Op("scan")]),
            Scenario("scan_other_height", [Op("scan")], rows={HEIGHT + 1: [L1B], HEIGHT - 1: [L1B]}),
            Scenario("scan_only_this_hash", [Op("scan")], rows={HEIGHT: [L1]}),
            Scenario("scan_only_other_hash", [Op("scan")], rows={HEIGHT: [L1B]}),
            Scenario("scan_two_hashes", [Op("scan")], rows={HEIGHT: [L1, L1B]}),
            Scenario("scan_three_hashes_order", [Op("scan")], rows={HEIGHT: [L1B, blob(0x05, 32), L1]}),
            Scenario("scan_wide_height_map", [Op("scan", height=1000 + 17), Op("scan", height=1000 + 21)], rows={1000 + index: [L1B] for index in range(30)}),
            Scenario("scan_wide_hash_map", [Op("scan")], rows={HEIGHT: [blob(0x02 + 3 * index, 32) for index in range(30)]}),
            Scenario("scan_wide_hash_map_only_hit_is_not_sole", [Op("scan", l1=blob(0x02 + 3 * 7, 32))], rows={HEIGHT: [blob(0x02 + 3 * index, 32) for index in range(30)]}),
            Scenario("filter_empty", [Op("filter")]),
            Scenario("filter_keeps_nonempty", [Op("filter", vec_rows=(quorum_row(1, 0x11, 1), quorum_row(2, 0x22, 5)))]),
            Scenario("filter_drops_empty_first", [Op("filter", vec_rows=(quorum_row(1, 0x11, 0), quorum_row(2, 0x22, 5), quorum_row(3, 0x33, 2)))]),
            Scenario("filter_drops_middle", [Op("filter", vec_rows=(quorum_row(1, 0x11, 1), quorum_row(2, 0x22, 0), quorum_row(3, 0x33, 2)))]),
            Scenario("filter_drops_last", [Op("filter", vec_rows=(quorum_row(1, 0x11, 1), quorum_row(2, 0x22, 2), quorum_row(3, 0x33, 0)))]),
            Scenario("filter_drops_all", [Op("filter", vec_rows=(quorum_row(1, 0x11, 0), quorum_row(2, 0x22, 0)))]),
            Scenario("filter_two_runs", [Op("filter", vec_rows=(quorum_row(1, 0x11, 1), quorum_row(2, 0x22, 0), quorum_row(3, 0x33, 0), quorum_row(4, 0x44, 3), quorum_row(5, 0x55, 0), quorum_row(6, 0x66, 4)))])]


def lcg(seed):
    value = seed
    while True:
        value = (value * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield value >> 33


def vector_scenarios(count):
    source = lcg(0x1522)
    out = []
    for index in range(count):
        size = 3 + next(source) % 12
        people = many_validators(30)[:size]
        hot = {key: address(0xE0 - 3 * (next(source) % 40)) for key, _ in people if next(source) % 5}
        heights = sorted({HEIGHT - WINDOW - 5 + next(source) % 12 for _ in range(next(source) % 9)})
        rows = {height: [L1] for height in heights}
        ops = []
        at = HEIGHT
        for step in range(5):
            voters = tuple(person for person in people if next(source) % 2)
            who = people[next(source) % size]
            ops.append(core(who, height=at, quorum=won(*voters) if next(source) % 3 else None))
            at += next(source) % 4
        out.append(Scenario("vector_%d" % index, ops, validators=people, hot=hot, rows=rows))
    return out


def describe(trace):
    """One short line per operation: status, result byte, and the marks that followed."""
    parts = []
    for step in trace:
        view, events, state = step
        if view[0] is None or isinstance(view[0], tuple):
            parts.append("none" if view[0] is None else "%d rows" % len(view[0]))
            continue
        text = "%#x" % (view[1] if view[0] == OUTCOME_ERROR and len(view) > 1 else view[0])
        if view[0] in (TAG_OK, OUTCOME_DONE) and len(view) > 1:
            text += "/%d" % view[1]
        removed = sum(1 for event in events if event[0] == "removed")
        parts.append(text + ("(removed %d)" % removed if removed else ""))
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


SLOT_ROWS = ((SLOT_CORE, "vote core", CORE), (SLOT_VOTER, "signer to voter key", VOTER), (SLOT_HOT, "voter key to hot user", 0x3369500), (SLOT_RECOVER, "signature recovery", 0x14C6F50), (SLOT_NEW, "digest state platform byte", 0x14FA220), (SLOT_UPDATE, "digest update", 0x14F93E0),
             (SLOT_FINAL, "digest finish", 0x14FA010), (SLOT_HEX, "prefixed hex", HEX), (SLOT_VEC_GROW, "row list growth", 0x32D6270), (SLOT_LONG_SORT, "sort of 21 rows or more", 0x3BBF960))


def slot_rows(image, through):
    relative = image.relative()
    rows = []
    for slot, role, target in SLOT_ROWS:
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target, len(through[slot])))
    return rows


def site_rows(image, through):
    direct = direct_sites(image, TARGETS + (TRACK,))
    rows = []
    for target in TARGETS + (TRACK,):
        sites = through[SLOT_CORE] if target == CORE else direct[target]
        owners = sorted({image.fde(site)[0] for site in sites})
        rows.append(("%#x" % target, NAMES.get(target, "tracker_stub"), len(sites), len(owners), " ".join("%#x" % owner for owner in owners[:6])))
    return rows


BLAKE3_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
IV_AT = 0x20C020
TABLE_AT = 0x3EDE28
ARM_INDEX = 87
ARM_AT = 0x275A259
ARM_CALL = 0x275A27C


def constant_rows(image, table):
    """Limits, the window and the digest words, read as bytes at their rows."""
    rows = []
    wrap = next(row for row in table[WRAP] if row.va == 0x1E5F02F)
    limit = next(row for row in table[CORE] if row.va == 0x394AC88)
    window = next(row for row in table[CORE] if row.va == 0x394B30F)
    size = next(row for row in table[ENCODE] if row.va == 0x3247A04)
    values = (struct.unpack_from("<Q", wrap.data, 2)[0], struct.unpack_from("<Q", limit.data, 2)[0], struct.unpack_from("<I", window.data, len(window.data) - 4)[0], struct.unpack_from("<I", size.data, 1)[0])
    if values != (HEIGHT_LIMIT - 1, HEIGHT_LIMIT, WINDOW, 0x42):
        raise EvidenceError("constants moved: %r" % (values,))
    for row, role, value in ((wrap, "wrapper: height above this is refused", values[0]), (limit, "core: height at or above this is refused", values[1]), (window, "height window of the prune", values[2]), (size, "hex text length", values[3])):
        rows.append(("%#x" % row.va, row.data.hex(), role, "%#x" % value, value))
    words = struct.unpack("<8I", bytes(image.blob[image.offset(IV_AT):image.offset(IV_AT) + 32]))
    if words != BLAKE3_IV:
        raise EvidenceError("digest words changed")
    rows.append(("%#x" % IV_AT, struct.pack("<8I", *words).hex(), "first eight digest state words", "%#x" % words[0], words[0]))
    return rows


def dispatch_rows(image):
    base = image.offset(TABLE_AT)
    arm = TABLE_AT + struct.unpack_from("<i", image.blob, base + 4 * ARM_INDEX)[0]
    at = image.offset(ARM_CALL)
    if arm != ARM_AT or image.blob[at] != 0xE8 or ARM_CALL + 5 + struct.unpack_from("<i", image.blob, at + 1)[0] != WRAP:
        raise EvidenceError("dispatch row changed")
    return [(ARM_INDEX, "%#x" % TABLE_AT, "%#x" % arm, "%#x" % ARM_CALL, "%#x" % WRAP)]


def note_rows(image, table):
    """The scan result reaches only a free, and the block step empties the row list."""
    rows = table[CORE]
    start = next(at for at, row in enumerate(rows) if row.va == 0x394B10F)
    stop = next(at for at, row in enumerate(rows) if row.va == 0x394B165)
    between = rows[start + 1:stop]
    calls = [row for row in between if row.op in ("call", "calli")]
    if rows[start].target != SCAN or rows[stop].target != TRACK or len(calls) != 1 or calls[0].a[4] != SLOT_FREE:
        raise EvidenceError("scan tail changed")
    out = [("scan_then_tracker", "%#x" % rows[start].va, "%#x" % rows[stop].va, " ".join(row.op for row in between))]
    site = 0x276451D
    want = bytes.fromhex("48c783f035000000000000")
    at = image.offset(site)
    if bytes(image.blob[at:at + len(want)]) != want:
        raise EvidenceError("block step list reset moved")
    call = 0x2764546
    at = image.offset(call)
    if image.blob[at] != 0xE8 or call + 5 + struct.unpack_from("<i", image.blob, at + 1)[0] != FILTER:
        raise EvidenceError("block step filter call moved")
    out.append(("block_step_takes_list", "%#x" % site, "%#x" % call, want.hex()))
    return out


def text_at(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def lea_text(image, site, size):
    at = image.offset(site)
    if bytes(image.blob[at:at + 3]) != bytes.fromhex("488d35"):
        raise EvidenceError("key load moved %#x" % site)
    return text_at(image, site + 7 + struct.unpack_from("<i", image.blob, at + 3)[0], size)


FIELD_ROWS = ((0x394AA14, 7, "tracker", "L1HashSignatureTracker +0x0", 0x394AA60), (0x394AA7D, 16, "quorum_l1_hashes", "L1HashSignatureTracker +0x40, the row list", 0x394AA79), (0x394AAA8, 21, "highest_quorum_height", "L1HashSignatureTracker +0x58", 0x394AAA4),
              (0x394A494, 7, "l1_hash", "HardQuorumL1Hash +0x0, row +0x8", 0x394A50D), (0x394A526, 21, "hot_user_to_signature", "HardQuorumL1Hash +0x20, row +0x28", 0x394A544), (0x394A58C, 23, "hard_voter_to_signature", "HardQuorumL1Hash +0x38, row +0x40", 0x394A5AA),
              (0x3792304, 4, "lhvt", "state key whose writer 0x37922f0 calls the tracker serializer 0x394a9c0", 0x379234A))
TEXT_ROWS = ((0x3D2835, "heightl1Hashsignaturestruct VoteL1HashAction with 3 elements", "action fields, then the struct name"), (0x3F4070, "L1Hashvariant index 0 <= i < 88", "last name of the action variant list"), (0x207690, "VoteL1HashAction", "action name"),
             (0x3B05E9, "HardQuorumL1Hash with 3 elements", "row name"), (0x3B0915, "L1HashSignatureTracker with 3 elements", "tracker name"))


def field_rows(image):
    rows = []
    for site, size, key, field, reader in FIELD_ROWS:
        if lea_text(image, site, size) != key:
            raise EvidenceError("key text %#x" % site)
        rows.append(("%#x" % site, "%#x" % reader, key, field))
    for at, text, role in TEXT_ROWS:
        if text_at(image, at, len(text)) != text:
            raise EvidenceError("text %#x" % at)
        rows.append(("%#x" % at, "-", text, role))
    return rows


KEY_ROWS = ((WRAP, 0x1E5F03C, "height limit", "jcc"), (WRAP, 0x1E5F076, "digest of height and hash", "call"), (WRAP, 0x1E5F086, "signature recovery", "calli"), (WRAP, 0x1E5F098, "recovery failed: 0x7a", "mov"), (WRAP, 0x1E5F0F3, "recovered address against signer", "cmp"), (WRAP, 0x1E5F0FA, "other address: 0x11f", "mov"), (WRAP, 0x1E5F149, "core", "calli"), (WRAP, 0x1E5F161, "outcome 9", "mov"),
            (CORE, 0x394AC95, "height limit", "jcc"), (CORE, 0x394ACC4, "linked user map root", "mov"), (CORE, 0x394AD37, "linked user address compare", "cmp"), (CORE, 0x394B058, "signer to voter key", "calli"), (CORE, 0x394B092, "no voter and no link: 0x91", "jcc"), (CORE, 0x394B10F, "scan at height", "call"), (CORE, 0x394B165, "tracker", "call"), (CORE, 0x394B176, "no quorum result", "jcc"),
            (CORE, 0x394B183, "highest_quorum_height is a maximum", "cmov"), (CORE, 0x394B20C, "hot_user_to_signature collect", "call"), (CORE, 0x394B2AE, "row list growth", "calli"), (CORE, 0x394B30F, "height minus the window", "sub"), (CORE, 0x394B316, "floor of 0", "cmov"), (CORE, 0x394B328, "prune", "call"), (CORE, 0x394B359, "status 0x91", "mov"),
            (KEY_HASH, 0x37E564F, "digest words", "movx"), (KEY_HASH, 0x37E56F8, "encoder", "call"), (KEY_HASH, 0x37E572B, "digest update", "calli"), (ENCODE, 0x3247A14, "prefixed hex of the hash", "calli"), (ENCODE, 0x32478EB, "array of two", "call"), (ENCODE, 0x3247930, "height", "call"),
            (SCAN, 0x3B45D15, "one hash at this height", "cmp"), (TAKE, 0x3BD7BC6, "voter key to hot user", "calli"), (TAKE, 0x3BD7BD2, "unresolved voter skipped", "jcc"), (FILTER, 0x3BC3180, "row hot map length", "cmp"), (PRUNE, 0x3942CCF, "split at the floor", "call"))


def key_rows(image, table):
    rows = []
    for target, va, text, op in KEY_ROWS:
        row = next((item for item in table[target] if item.va == va), None)
        if row is None or row.op != op:
            raise EvidenceError("row %#x is %s" % (va, row.op if row else None))
        rows.append(("%#x" % target, "%#x" % va, row.data.hex(), op, text))
    return rows


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


def layout_rows():
    return [(row.name, "%#x" % row.key_at, "%#x" % row.key_size, "%#x" % row.val_at, "%#x" % row.val_size, "%#x" % row.parent, "%#x" % row.index, "%#x" % row.count, "%#x" % row.size) for row in LAYOUTS]


def signed_rows():
    """The exact bytes given to the digest, for heights that take each integer form."""
    rows = []
    for height in (0, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000, HEIGHT):
        rows.append((height, signed_bytes(height, L1).hex()))
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


# Scenario name prefixes run against the edits of each function; the generated runs stay out to bound the time.
FOCUS = {WRAP: ("arm_87",), KEY_HASH: ("arm_87_first", "arm_87_other_hash"), ENCODE: ("arm_87_first", "arm_87_other_hash", "arm_87_height_small"), PUT_LEN: ("arm_87_first",), PUT_BYTE: ("arm_87_height",), PUT_STR: ("arm_87_first", "arm_87_other_hash"), HEX: ("arm_87_first", "arm_87_other_hash"),
         CORE: ("core_", "arm_87_hard", "prune_", "hot_one"), SCAN: ("scan_",), COLLECT: ("hot_",), TAKE: ("hot_",), SORT: ("hot_",), PRUNE: ("prune_",), GATHER_LOOP: ("prune_",), FILTER: ("filter_",)}
FULL = (WRAP, CORE, SCAN, FILTER)


def run_mutants(image, table, seen, scenarios):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, scenarios, [spec_run(scenario) for scenario in scenarios]) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    results = []
    IMAGE_FDE.update({target: image.exact_fde(target) for target in MUTATED})
    for target in MUTATED:
        chosen = [scenario for scenario in scenarios if scenario.name.startswith(FOCUS[target])]
        wants = [spec_run(scenario) for scenario in chosen]
        for va, kind, patch in edits_for(image, table[target], seen, target in FULL):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            hit = first_failure(harness, chosen, wants)
            results.append((va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else survivor_reason(va)))
    return results


def survivor_reason(va):
    for target, text in SURVIVORS:
        start, stop = IMAGE_FDE[target]
        if start <= va < stop:
            return text
    return "UNEXPLAINED"


IMAGE_FDE = {}
LOOP = "class: search loop step for a deeper tree, allocation size, free test, tail of a copied status record, or a stub argument; not visible in the compared state"
SURVIVORS = tuple((target, LOOP) for target in MUTATED)


def analyse(image, mutate=True, vectors=200):
    harness = Harness(image)
    scenarios = named_scenarios()
    named = check_all(harness, scenarios)
    check_all(harness, vector_scenarios(vectors))
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target in TARGETS}
    through = slot_sites(image, tuple(row[0] for row in SLOT_ROWS))
    result = dict(table=table, named=named, scenarios=scenarios, vector_count=vectors, unreached=unreached, slots=slot_rows(image, through), sites=site_rows(image, through), constants=constant_rows(image, table), notes=note_rows(image, table),
                  fields=field_rows(image), statuses=status_rows(image), layouts=layout_rows(), keys=key_rows(image, table), dispatch=dispatch_rows(image), signed=signed_rows())
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, scenarios)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("path.tsv", ("function", "name", "bytes", "instructions", "unreached_rows"),
        [("%#x" % target, NAMES[target], sum(row.size for row in result["table"][target]), len(result["table"][target]), len(result["unreached"][target])) for target in TARGETS])
    tsv("unreached.tsv", ("function", "row"), [("%#x" % target, "%#x" % va) for target in TARGETS for va in result["unreached"][target]])
    tsv("slots.tsv", ("slot", "role", "relative_target", "call_or_load_sites"), result["slots"])
    tsv("call-sites.tsv", ("function", "name", "sites", "caller_functions", "first_callers"), result["sites"])
    tsv("constants.tsv", ("at", "bytes", "role", "hex", "value"), result["constants"])
    tsv("dispatch.tsv", ("arm_index", "table", "arm", "call_site", "wrapper"), result["dispatch"])
    tsv("notes.tsv", ("note", "first_row", "second_row", "detail"), result["notes"])
    tsv("fields.tsv", ("key_at", "field_at", "text", "field"), result["fields"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("node-layouts.tsv", ("tree", "key_at", "key_size", "value_at", "value_size", "parent_at", "parent_index_at", "count_at", "leaf_size"), result["layouts"])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    tsv("signed-bytes.tsv", ("height", "bytes_for_hash_515253"), result["signed"])
    tsv("scenarios.tsv", ("scenario", "operations", "outcome"), [(scenario.name, " ".join(op.kind for op in scenario.ops), describe(trace)) for scenario, trace in result["named"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(TARGETS), "instructions": sum(len(result["table"][target]) for target in TARGETS),
        "named_scenarios": len(result["scenarios"]), "named_operations": sum(len(scenario.ops) for scenario in result["scenarios"]), "vector_scenarios": result["vector_count"],
        "unreached_rows": sum(len(rows) for rows in result["unreached"].values()),
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
