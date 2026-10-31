#!/usr/bin/env python3
"""Pin node #94 forceIncreaseEpoch and the epoch roll: gate order, signed tuple, 2/3 stake quorum, snapshot, prune.

0x3368380 is the handler body, 0x33696b0 freezes cur_epoch_state into epoch_states and prunes, 0x3366b60 is the
stake quorum, 0x3369500 reads a validator row, 0x33676a0 reads the last epoch key, 0x3941e70 opens a signature
tracker row and 0x3c97a70 builds the signed tuple. The real bytes run under recording stubs over real B-tree nodes,
a separately written rule list predicts every run including all fixture bytes, and every reached conditional row,
immediate and field offset is mutated. No objdump or readelf output is parsed and the binary is never executed.
Standard library only.

    python3 tools/force_increase_epoch.py --out <dir>
"""

import argparse
import bisect
import datetime
import hashlib
import json
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


FORCE = 0x3368380
ROLL = 0x33696B0
QUORUM = 0x3366B60
LOOKUP = 0x3369500
LAST = 0x33676A0
TRACK = 0x3941E70
ENCODE_TUPLE = 0x3C97A70
TARGETS = (FORCE, ROLL, QUORUM, LOOKUP, LAST, TRACK, ENCODE_TUPLE)
NAMES = {FORCE: "force_increase_epoch", ROLL: "advance_epoch", QUORUM: "stake_quorum", LOOKUP: "validator_user", LAST: "last_epoch_key", TRACK: "signature_tracker_slot", ENCODE_TUPLE: "signed_tuple_encode"}

SLOT_FORCE = 0x5773940
SLOT_LAST = 0x5773948
SLOT_LOOKUP = 0x5775C88
SLOT_COMPARE = 0x576E488
SLOT_TIME = 0x576EFB8
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_ABI = 0x576ED20
SLOT_ABSORB = 0x576E1D8
SLOT_SQUEEZE = 0x576E1E0
SLOT_MEMCPY = 0x576DFE0
SLOT_RECOVER = 0x576FE58
SLOT_CROSSROADS = 0x576F488
SLOT_ONCE = 0x576E8B8
SLOT_UNWRAP = 0x576E470
SLOT_EXPECT = 0x576E108
SLOT_ADD = 0x576E118
SLOT_ALLOC_FAIL = 0x576DFB8
ONCE_CELL = 0x577AB98
DROP_STATUS = 0x3379490
NEXT_SIGNATURE = 0x33B16E0
SET_INSERT = 0x33A0950
DROP_SET = 0x33F3FC0
AGENT_DIGEST = 0x37F2940
REPORT_ERROR = 0x365EB00
STAKE_TOTALS = 0x3364ED0
NEXT_STAKE = 0x33AE9E0
CLONE_VALIDATORS = 0x33E71C0
INSERT_EPOCH = 0x33A7690
NEXT_OLD = 0x33B64D0
DROP_OLD = 0x33F0DA0
POP_FIRST = 0x2FD8BC0
DROP_TOKEN = 0x3BBC830
BUILD_EMPTY = 0x33C1E70
VACANT_INSERT = 0x33C1260
STATUS_TABLE = 0x59A8D0
MARK_BASE = 0x7700000000
PANIC_FIRST = "first_key_absent"

TAG_OK = 0x186
TAG_INVALID_VALIDATOR = 0x94
TAG_EPOCH_MISSING = 0x97
TAG_FORCE_FAILED = 0x98
TAG_QUORUM = 0x99
TAG_TRACKER = 0x9A
TAG_SIGNER = 0x11F
TAG_RECOVER = 0x7A
TAG_LENGTH = 0x143
TAG_NUMBER = 0x13F
TEXT_TAGS = (TAG_RECOVER, TAG_INVALID_VALIDATOR, TAG_EPOCH_MISSING, TAG_FORCE_FAILED, TAG_QUORUM, TAG_TRACKER, TAG_SIGNER, TAG_LENGTH, TAG_NUMBER)
MAX_SIGNATURES = 10000
NUMBER_CAP = 0x0CCCCCCCCCCCCCCC
PRUNE_ABOVE = 1000
RATE = 0x88
CHAIN = 1337
TOP = MASK[8]

S_DURATION = 0
S_VALIDATORS = 8
S_START = 0x20
S_EPOCHS = 0x30
S_ACTIVE = 0x48
S_CUR = 0x50

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
ACTION = HEAP_BASE + 0x300
KEY_AT = HEAP_BASE + 0x400
NOW_AT = HEAP_BASE + 0x440
SET_AT = HEAP_BASE + 0x480
TRACKER = HEAP_BASE + 0x500
NODES = HEAP_BASE + 0x1000
NODE_STRIDE = 0x900
STATE = HEAP_BASE + 0x14000
COMPARED = 0x14800
SET_AREA = HEAP_BASE + 0x17000
TOKENS = HEAP_BASE + 0x18000
TEXT_BUF = HEAP_BASE + 0x18100
SOURCE_BUF = HEAP_BASE + 0x18140
ENCODED = HEAP_BASE + 0x18180
USED = 0x1A000
FILL = 0xCC
BASE_DATE = (2026 << 13) | (304 << 4) | 5
CLONE_ROOT = 0x4000
CLONE_HEIGHT = 2
ROW_DROP = HEAP_BASE + 0x19000
ERROR_WORDS = bytes(range(0x50, 0x68))
HEIGHT_TEXT = 0x57AE54


class Layout:
    def __init__(self, key_size, val_size, val_at, key_at, len_at, edge_at, parent_at, slot_at, stride=NODE_STRIDE):
        self.key_size, self.val_size, self.val_at, self.key_at = key_size, val_size, val_at, key_at
        self.len_at, self.edge_at, self.parent_at, self.slot_at, self.stride = len_at, edge_at, parent_at, slot_at, stride


EPOCH_MAP = Layout(8, 0x28, 0x60, 8, 0x21A, 0x220, 0, 0x218)
VALIDATOR_MAP = Layout(0x20, 0x40, 0, 0x2C0, 0x42A, 0x430, 0x420, 0x428)
STAKE_MAP = Layout(0x20, 8, 0x168, 0, 0x1C2, 0x1C8, 0x160, 0x1C0)
SET_MAP = Layout(0x20, 0, 0x160, 0, 0x16A, 0x170, 0x160, 0x168, 0x200)
TRACKER_MAP = Layout(8, 0x20, 0, 0x168, 0x1C2, 0x1C8, 0x160, 0x1C0)


def bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def key_of(index):
    return bytes([0x40 + index]) * 31 + bytes([index])


def user_of(index):
    return bytes((0x70 + index + at * 3) & 0xFF for at in range(20))


def signer_of(index):
    return bytes((0xA0 + index + at * 5) & 0xFF for at in range(20))


def signature_of(index):
    return bytes((0x10 + index + at * 7) & 0xFF for at in range(0x47)) + bytes([index])


def pack_time(value):
    return struct.pack("<iII", *value)


def wrap32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


def trunc_div(left, right):
    quotient = abs(left) // right
    return -quotient if left < 0 else quotient


def unix_seconds(date, seconds):
    """Packed chrono date to whole seconds, zero below 1970; written from the calendar rule and held by vectors."""
    year = date >> 13
    shifted = wrap32(year - 1)
    adjust = 0
    if year <= 0:
        cycles = (1 - year) // 400 + 1
        shifted = wrap32(shifted + 400 * cycles)
        adjust = wrap32(cycles * -146097)
    ordinal = (date >> 4) & 0x1FF
    centuries = trunc_div(shifted, 100)
    days = wrap32(ordinal + adjust - centuries + (wrap32(shifted * 1461) >> 2) + (centuries >> 2) - 719163)
    return max(days * 86400 + seconds, 0)


class Case:
    FIELDS = dict(chain=3, epoch=7, nonce=0x1122334455667788, duration=86400, start=(BASE_DATE, 3600, 9), added=None, active=5, cur=7, epochs=((3, 19000), (5, 19000), (6, 19000)), e_shape="leaf", len_word=None, v_len=4, v_root=True,
                  validators=(1, 2, 3, 4), v_shape="leaf", v_null=False, signatures=((1, "ok"), (2, "ok"), (3, "ok")), n_word=None, a_null=False, digest_fail=None, stakes=None, stake_shape="leaf", once=0, extra_high=0, old=None, shrink=(),
                  force=0, now=(BASE_DATE, 3600, 9), target=7, set_keys=(1, 2, 3), lookup=1, tracked=(), t_shape="leaf", t_null=False, last_key=None, l_shape="leaf", l_null=False, l_zero=False, stake_empty=False)

    def __init__(self, name, kind, **fields):
        self.name = name
        self.kind = kind
        for key, value in self.FIELDS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.FIELDS:
                raise EvidenceError("field " + key)
            setattr(self, key, value)


def blank():
    return bytes((index * 7 + 0x40) & 0xFF for index in range(OUT_SIZE))


def added_time(case):
    if case.added is not None:
        return case.added
    return (case.start[0], (case.start[1] + case.duration) & MASK[4], case.start[2])


class Spec:
    """The rule list, kept apart from the evaluator: it edits a copy of the fixture bytes and lists the expected calls."""

    def __init__(self, case, before, where):
        self.case = case
        self.image = bytearray(before)
        self.events = []
        self.where = where

    def put(self, addr, data):
        at = addr - HEAP_BASE
        self.image[at:at + len(data)] = data

    def word(self, addr, size=8):
        at = addr - HEAP_BASE
        return int.from_bytes(self.image[at:at + size], "little")

    def done(self, tag):
        self.put(OUT, struct.pack("<H", tag))
        return "done", tuple(self.events), bytes(self.image)

    def stake_quorum(self, epoch, chosen):
        case = self.case
        if epoch not in [row[0] for row in case.epochs] or not self.where["epoch_root"]:
            self.events.append(("drop_status", TAG_EPOCH_MISSING))
            return False
        self.events.append(("stakes", self.where["epoch_rows"][epoch]))
        stakes = self.where["stakes"]
        if not stakes:
            root = self.where["stake_root"]
            self.events.append(("drop_stakes", int(root != 0), root, 0))
            return False
        total = 0
        for key in sorted(stakes):
            total += stakes[key]
            if total > TOP:
                raise Overflowed()
        signed = 0
        if chosen:
            for key in sorted(chosen):
                if key in stakes:
                    signed = min(TOP, signed + stakes[key])
        self.events.append(("drop_stakes", 1, self.where["stake_root"], len(stakes)))
        return bool(chosen) and 3 * signed > 2 * total

    def advance(self, force, now, target):
        case = self.case
        start_at, cur_at = STATE + S_START, STATE + S_CUR
        cur = self.word(cur_at)
        if cur > target:
            return False
        old_bucket = unix_seconds(case.start[0], case.start[1]) // case.duration
        new_bucket = unix_seconds(now[0], now[1]) // case.duration
        active = self.word(STATE + S_ACTIVE)
        flag = active == 0 and (force & 0xFF != 0 or case.v_len == 3)
        if not flag and new_bucket <= old_bucket:
            return False
        if case.v_len:
            if not case.v_root:
                raise Unwrapped()
            self.events.append(("clone", self.where["cur_root"], self.where["cur_height"]))
            value = struct.pack("<3Q", CLONE_ROOT, CLONE_HEIGHT, case.v_len)
        else:
            value = bytes(24)
        self.events.append(("insert", target, value + pack_time(case.start)))
        count = self.word(STATE + S_EPOCHS + 0x10)
        if case.old is None:
            count += 1
        else:
            self.events.append(("drop_map", case.old[0], case.old[1]))
            for _ in range(case.old[2]):
                self.events.append(("drop_old", ROW_DROP))
        self.put(STATE + S_EPOCHS + 0x10, struct.pack("<Q", count))
        if flag:
            self.put(STATE + S_ACTIVE, struct.pack("<Q", cur))
            active = cur
        self.put(cur_at, struct.pack("<Q", min(target + 1, TOP)))
        self.put(start_at, pack_time(now))
        if case.once:
            self.events.append(("once",))
        self.prune(active)
        return True

    def prune(self, active):
        case = self.case
        pops = 0
        holder = STATE + S_EPOCHS
        while self.word(holder + 0x10) > PRUNE_ABOVE:
            root = self.word(holder)
            if root == 0:
                break
            height = self.word(holder + 8)
            leaf = root
            for _ in range(height):
                leaf = self.word(leaf + 0x220)
            count = self.word(leaf + 0x21A, 2)
            if count == 0 or self.word(leaf + 8) >= active:
                break
            first = self.word(leaf + 8)
            value = bytes(self.image[leaf + 0x60 - HEAP_BASE:leaf + 0x88 - HEAP_BASE])
            self.events.append(("pop", first, leaf))
            drop_first(self.image, leaf - HEAP_BASE, count)
            self.put(holder + 0x10, struct.pack("<Q", self.word(holder + 0x10) - 1))
            if pops < len(case.shrink) and case.shrink[pops]:
                if root == 0 or height == 0:
                    raise Unwrapped()
                child = self.word(root + 0x220)
                self.put(holder, struct.pack("<Q", child))
                self.put(holder + 8, struct.pack("<Q", height - 1))
                self.put(child, bytes(8))
                self.events.append(("free", root, 0x280))
            pops += 1
            if struct.unpack_from("<I", value, 0x18)[0]:
                self.events.append(("drop_map", struct.unpack_from("<Q", value, 0)[0], struct.unpack_from("<Q", value, 0x10)[0]))

    def drained(self):
        self.events.append(("drained", len(self.case.signatures)))

    def row_events(self, row_at, epoch, nonce):
        case = self.case
        encoded = b"abi" + struct.pack("<QQ", epoch, nonce)
        self.events.append(("abi", b"forceIncreaseEpoch", epoch, nonce))
        self.events.extend(("token", at) for at in range(3))
        self.events.append(("free", TOKENS, 0x78))
        self.events.append(("absorb", encoded))
        self.events.append(("free", ENCODED, 0x40))
        inner = hashlib.sha256(encoded).digest()
        source = 0x61 if case.chain & 0xFF == 3 else 0x62
        self.events.append(("agent", source, inner))
        if case.digest_fail == row_at:
            return None
        digest = hashlib.sha256(bytes([source]) + inner).digest()
        return digest

    def force(self):
        case = self.case
        events = self.events
        events.append(("time", pack_time(case.start), bits(float(case.duration))))
        now = added_time(case)
        active = case.active
        epoch_row = dict(case.epochs).get(active) if self.where["epoch_root"] else None
        present = self.where["epoch_root"] and active in dict(case.epochs)
        count = case.n_word if case.n_word is not None else len(case.signatures)
        if not present:
            events.append(("drop_status", TAG_EPOCH_MISSING))
            done = self.advance(case.chain, now, self.word(STATE + S_CUR))
            if not done and case.once:
                events.append(("once",))
            self.put(OUT, struct.pack("<H", TAG_OK if done else TAG_FORCE_FAILED))
            self.drained()
            return self.done(TAG_OK if done else TAG_FORCE_FAILED)
        if count > MAX_SIGNATURES:
            self.drained()
            self.put(OUT + 0x18, struct.pack("<Q", count))
            return self.done(TAG_LENGTH)
        epoch = case.epoch
        if epoch >= NUMBER_CAP:
            self.put(OUT + 8, struct.pack("<Q", epoch))
            self.drained()
            return self.done(TAG_NUMBER)
        cur = self.word(STATE + S_CUR)
        if epoch < cur:
            if case.once:
                events.append(("once",))
            events.append(("drop_set", 0))
            self.drained()
            return self.done(TAG_FORCE_FAILED)
        chosen = []
        rows = self.where["validators"]

        def stop(tag, payload=None):
            events.append(("free", SOURCE_BUF, 1))
            self.drained()
            events.append(("drop_set", len(chosen)))
            if payload is not None:
                self.put(OUT + 8, struct.pack("<Q", payload))
            return self.done(tag)

        for at, (index, verdict) in enumerate(sorted(case.signatures)):
            digest = self.row_events(at, epoch, case.nonce)
            if digest is None:
                events.append(("report",))
                return stop(TAG_RECOVER, 0x777)
            events.append(("recover", signature_of(index), digest))
            if verdict == "fail":
                return stop(TAG_RECOVER, 0x888)
            if case.v_null or index not in rows:
                return stop(TAG_INVALID_VALIDATOR)
            events.append(("drop_status", TAG_INVALID_VALIDATOR))
            if verdict != "ok":
                return stop(TAG_SIGNER)
            events.append(("set", key_of(index)))
            chosen.append(key_of(index))
            events.append(("free", SOURCE_BUF, 1))
        self.drained()
        passed = self.stake_quorum(active, chosen)
        if not passed:
            events.append(("drop_set", len(chosen)))
            return self.done(TAG_QUORUM)
        done = self.advance(case.chain, now, epoch)
        if not done:
            events.append(("crossroads",))
            events.append(("drop_set", len(chosen)))
            return self.done(TAG_FORCE_FAILED)
        self.put(STATE + S_ACTIVE, struct.pack("<Q", epoch))
        events.append(("drop_set", len(chosen)))
        return self.done(TAG_OK)

    def lookup(self):
        case = self.case
        rows = dict(case.epochs)
        if not self.where["epoch_root"] or case.target not in rows:
            return self.done(TAG_EPOCH_MISSING)
        if case.v_null or case.lookup not in self.where["validators"]:
            return self.done(TAG_INVALID_VALIDATOR)
        self.events.append(("drop_status", TAG_INVALID_VALIDATOR))
        self.put(OUT + 2, user_of(case.lookup))
        return self.done(TAG_OK)

    def track(self):
        case = self.case
        if case.target in case.tracked and not case.t_null:
            return self.done(TAG_TRACKER)
        self.events.append(("build",))
        self.events.append(("vacant", TRACKER + 0x18, case.target, self.where["t_leaf"], self.where["t_slot"], bytes(24) + b"\x00\x01"))
        return self.done(TAG_OK)


class Overflowed(Exception):
    pass


class Unwrapped(Exception):
    pass


def drop_first(image, at, count):
    """Remove row 0 of an epoch map leaf held in `image` at offset `at`."""
    image[at + 8:at + 8 + 8 * (count - 1)] = image[at + 16:at + 8 + 8 * count]
    image[at + 0x60:at + 0x60 + 0x28 * (count - 1)] = image[at + 0x88:at + 0x60 + 0x28 * count]
    image[at + 0x21A:at + 0x21C] = struct.pack("<H", count - 1)


def spec_run(case, before, where):
    spec = Spec(case, before, where)
    try:
        if case.kind == FORCE:
            return spec.force()
        if case.kind == ROLL:
            done = spec.advance(case.force, case.now, case.target)
            return ("value", int(done), tuple(spec.events), bytes(spec.image))
        if case.kind == QUORUM:
            chosen = [key_of(index) for index in case.set_keys]
            return ("value", int(spec.stake_quorum(case.target, chosen)), tuple(spec.events), bytes(spec.image))
        if case.kind == LOOKUP:
            return spec.lookup()
        if case.kind == TRACK:
            return spec.track()
    except Overflowed:
        return "panic", "add_overflow", tuple(spec.events)
    except Unwrapped:
        return "panic", "unwrap", tuple(spec.events)
    rows = [row[0] for row in case.epochs]
    if case.l_null or case.l_zero:
        return ("value", (0, None), (), bytes(before))
    return ("value", (1, max(rows)), (), bytes(before))


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((ROLL, QUORUM, ENCODE_TUPLE))
        statics = machine.memory.statics
        statics[ONCE_CELL] = 0
        hooks = {SLOT_COMPARE: self.on_compare, SLOT_TIME: self.on_time, SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_ABI: self.on_abi, SLOT_ABSORB: self.on_absorb, SLOT_SQUEEZE: self.on_squeeze, SLOT_MEMCPY: self.on_memcpy, SLOT_RECOVER: self.on_recover, SLOT_CROSSROADS: self.on_crossroads, SLOT_ONCE: self.on_once, SLOT_UNWRAP: self.on_unwrap, SLOT_EXPECT: self.on_expect, SLOT_ADD: self.on_add, SLOT_ALLOC_FAIL: self.on_unwrap}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        machine.calls = {DROP_STATUS: self.on_drop_status, NEXT_SIGNATURE: self.on_next, SET_INSERT: self.on_set, DROP_SET: self.on_drop_set, AGENT_DIGEST: self.on_agent, REPORT_ERROR: self.on_report, STAKE_TOTALS: self.on_stakes, NEXT_STAKE: self.on_next_stake, CLONE_VALIDATORS: self.on_clone, INSERT_EPOCH: self.on_insert, NEXT_OLD: self.on_next_old, DROP_OLD: self.on_drop_old, POP_FIRST: self.on_pop, DROP_TOKEN: self.on_drop_token, BUILD_EMPTY: self.on_build, VACANT_INSERT: self.on_vacant}
        self.events = []
        self.case = None
        self.before = None
        self.where = None
        self.next_node = NODES

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
        self.expect(size == 0x20, "compare length")
        left, right = self.bytes_at(regs[RDI], size), self.bytes_at(regs[RSI], size)
        result = 0 if left == right else 0x1234 if left > right else -0x1234
        regs[RAX] = (0x5A5A5A5A << 32) | result & MASK[4]

    def on_time(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == STATE + S_START, "time input")
        self.events.append(("time", self.bytes_at(regs[RSI], 12), machine.xmm[0] & MASK[8]))
        machine.memory.put_bytes(regs[RDI], pack_time(added_time(self.case)))

    def on_alloc(self, machine):
        regs = machine.regs
        size = regs[RDI]
        where = {0x78: TOKENS, 0x12: TEXT_BUF, 1: SOURCE_BUF}.get(size)
        self.expect(where is not None, "alloc size")
        regs[RAX] = where

    def on_free(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 0, "free flags")
        self.events.append(("free", regs[RDI], regs[RSI]))

    def on_abi(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == TOKENS and regs[RDX] == 3, "token slice")
        data = self.bytes_at(TOKENS, 0x78)
        self.expect(data[0] == 6 and data[0x28] == 4 and data[0x50] == 4, "token kinds")
        cap, pointer, size = struct.unpack_from("<3Q", data, 8)
        self.expect(pointer == TEXT_BUF and cap == size == 18, "string token")
        self.expect(data[0x38:0x50] == bytes(24) and data[0x60:0x78] == bytes(24), "high limbs")
        text = self.bytes_at(pointer, size)
        epoch, nonce = struct.unpack_from("<Q", data, 0x30)[0], struct.unpack_from("<Q", data, 0x58)[0]
        self.events.append(("abi", text, epoch, nonce))
        machine.memory.put_bytes(ENCODED, b"abi" + struct.pack("<QQ", epoch, nonce))
        machine.memory.put_bytes(regs[RDI], struct.pack("<3Q", 0x40, ENCODED, 19))

    def on_drop_token(self, machine):
        at = machine.regs[RDI] - TOKENS
        self.expect(at % 0x28 == 0, "token stride")
        self.events.append(("token", at // 0x28))

    def on_absorb(self, machine):
        regs = machine.regs
        state = regs[RDI]
        self.expect(self.read(state + 0xD0) == RATE, "keccak rate")
        self.expect(self.read(state + 0xD8, 2) == 1, "keccak delimiter")
        self.expect(self.bytes_at(state, 0xD0) == bytes(0xD0), "keccak state")
        self.events.append(("absorb", self.bytes_at(regs[RSI], regs[RDX])))
        self.absorbed = self.bytes_at(regs[RSI], regs[RDX])

    def on_memcpy(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 0xE0, "state copy size")
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])

    def on_squeeze(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 0x20, "digest size")
        machine.memory.put_bytes(regs[RSI], hashlib.sha256(self.absorbed).digest())

    def on_agent(self, machine):
        regs = machine.regs
        data = self.bytes_at(regs[RSI], 0x58)
        cap, pointer, size = struct.unpack_from("<3Q", data, 0)
        self.expect(cap == size == 1 and pointer == SOURCE_BUF, "source vector")
        self.expect(struct.unpack_from("<Q", data, 0x38)[0] == CHAIN, "chain id")
        self.expect(data[0x40:0x58] == bytes(24), "trailing words")
        source = self.bytes_at(pointer, 1)[0]
        inner = data[0x18:0x38]
        self.events.append(("agent", source, inner))
        rows = self.rows_done
        if self.case.digest_fail == rows:
            self.word(regs[RDI], 1, 1)
            self.machine.memory.put_bytes(regs[RDI] + 8, ERROR_WORDS)
            return
        self.word(regs[RDI], 0, 1)
        machine.memory.put_bytes(regs[RDI] + 1, hashlib.sha256(bytes([source]) + inner).digest())

    def on_report(self, machine):
        self.expect(self.bytes_at(machine.regs[RDI], 0x18) == ERROR_WORDS, "error words")
        self.events.append(("report",))
        machine.regs[RAX] = 0x777

    def on_recover(self, machine):
        regs = machine.regs
        signature = self.bytes_at(regs[RSI], 0x48)
        digest = self.bytes_at(regs[RDX], 0x20)
        self.events.append(("recover", signature, digest))
        index = signature[0x47]
        verdict = dict(self.case.signatures)[index]
        self.rows_done += 1
        if verdict == "fail":
            self.word(regs[RDI], 1, 1)
            self.word(regs[RDI] + 8, 0x888)
            return
        address = signer_of(index)
        if verdict == "wrong_first":
            address = bytes([address[0] ^ 1]) + address[1:]
        elif verdict == "wrong_last":
            address = address[:19] + bytes([address[19] ^ 1])
        elif verdict == "wrong_word":
            address = address[:16] + bytes([address[16] ^ 1]) + address[17:]
        self.word(regs[RDI], 0, 1)
        machine.memory.put_bytes(regs[RDI] + 1, address)

    def on_crossroads(self, machine):
        self.events.append(("crossroads",))

    def on_once(self, machine):
        self.expect(machine.regs[RDI] == ONCE_CELL and machine.regs[RSI] == 1, "once cell")
        self.events.append(("once",))

    def on_unwrap(self, machine):
        raise Panicked("unwrap")

    def on_expect(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == HEIGHT_TEXT and regs[RSI] == 0x21, "panic text")
        self.expect(self.bytes_at(regs[RDI], 0x21) == b"assertion failed: self.height > 0", "panic text bytes")
        raise Panicked("unwrap")

    def on_add(self, machine):
        raise Panicked("add_overflow")

    def on_drop_status(self, machine):
        self.events.append(("drop_status", self.read(machine.regs[RDI], 2)))

    def on_next(self, machine):
        regs = machine.regs
        words = struct.unpack("<9Q", self.bytes_at(regs[RSI], 72))
        if not self.iter_checked:
            self.iter_checked = True
            case = self.case
            root = 0 if case.a_null else self.action_root
            count = 0 if case.a_null else (case.n_word if case.n_word is not None else len(case.signatures))
            if root:
                self.expect(words[0] == 1 and words[1] == 0 and words[2] == root and words[3] == 3, "iterator front")
                self.expect(words[4] == 1 and words[5] == 0 and words[6] == root and words[7] == 3, "iterator back")
            else:
                self.expect(words[0] == 0 and words[4] == 0, "empty iterator")
            self.expect(words[8] == count, "iterator length")
        rows = self.signature_rows
        if self.signature_at >= len(rows) or self.case.a_null:
            self.word(regs[RDI], 0)
            if not self.drained:
                self.drained = True
                self.events.append(("drained", len(self.case.signatures)))
            return
        node, slot = rows[self.signature_at]
        self.signature_at += 1
        self.word(regs[RDI], node)
        self.word(regs[RDI] + 0x10, slot)

    def fake_drain(self):
        pass

    def on_set(self, machine):
        regs = machine.regs
        key = self.bytes_at(regs[RSI], 0x20)
        self.events.append(("set", key))
        self.set_keys.append(key)
        self.write_set(regs[RDI], self.set_keys)
        regs[RAX] = 0

    def write_set(self, holder, keys):
        saved = self.next_node
        self.next_node = SET_AREA
        items = sorted((key, b"") for key in keys)
        shape = "leaf" if len(items) <= 11 else "tall" if len(items) == 15 else "deep"
        built = self.tree(SET_MAP, items, shape, b"\xFD" * 0x20)
        self.next_node = saved
        self.word(holder, built[0])
        self.word(holder + 8, built[1])
        self.word(holder + 0x10, len(items))

    def on_drop_set(self, machine):
        root, height, count = struct.unpack("<3Q", self.bytes_at(machine.regs[RDI], 24))
        self.expect(count == len(self.set_keys) and (root != 0) == bool(self.set_keys), "set words")
        self.events.append(("drop_set", len(self.set_keys)))

    def on_stakes(self, machine):
        regs = machine.regs
        self.events.append(("stakes", regs[RSI]))
        built = self.where["stake_built"]
        self.word(regs[RDI], built[0])
        self.word(regs[RDI] + 8, built[1])
        self.word(regs[RDI] + 0x10, built[2])

    def on_next_stake(self, machine):
        regs = machine.regs
        words = struct.unpack("<9Q", self.bytes_at(regs[RSI], 72))
        self.expect(words[0] == words[4] and (not words[0] or words[1] == words[5] == 0), "iterator words")
        self.events.append(("drop_stakes", words[0], words[2] if words[0] else 0, words[8]))
        self.word(regs[RDI], 0)

    def on_clone(self, machine):
        regs = machine.regs
        self.events.append(("clone", regs[RSI], regs[RDX]))
        machine.memory.put_bytes(regs[RDI], struct.pack("<3Q", CLONE_ROOT, CLONE_HEIGHT, self.case.v_len))

    def on_insert(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == STATE + S_EPOCHS, "epoch map")
        data = bytearray(self.bytes_at(regs[RCX], 0x24))
        if data[:8] == bytes(8):
            data[8:16] = bytes(8)
        self.events.append(("insert", regs[RDX], bytes(data)))
        old = self.case.old
        if old is None:
            self.word(STATE + S_EPOCHS + 0x10, self.read(STATE + S_EPOCHS + 0x10) + 1)
            machine.memory.put_bytes(regs[RDI], bytes(0x18) + bytes(4))
            return
        machine.memory.put_bytes(regs[RDI], struct.pack("<3Q", old[0], 1, old[1]) + struct.pack("<I", 77))
        self.old_left = old[2]

    def on_next_old(self, machine):
        regs = machine.regs
        words = struct.unpack("<9Q", self.bytes_at(regs[RSI], 72))
        if not self.old_started:
            self.old_started = True
            self.expect(words[0] == words[4] and (not words[0] or words[1] == words[5] == 0), "iterator words")
            self.events.append(("drop_map", words[2] if words[0] else 0, words[8]))
        if self.old_left:
            self.old_left -= 1
            self.word(regs[RDI], ROW_DROP - 0x40)
            self.word(regs[RDI] + 0x10, 1)
        else:
            self.word(regs[RDI], 0)
            self.old_started = False

    def on_drop_old(self, machine):
        self.events.append(("drop_old", machine.regs[RDI]))

    def on_pop(self, machine):
        regs = machine.regs
        node, height, slot, holder = struct.unpack("<4Q", self.bytes_at(regs[RSI], 32))
        self.expect(height == 0 and slot == 0 and holder == STATE + S_EPOCHS, "pop cursor")
        memory = self.machine.memory
        count = self.read(node + 0x21A, 2)
        first = self.read(node + 8)
        data = self.bytes_at(node + 8, 8) + self.bytes_at(node + 0x60, 0x28)
        self.events.append(("pop", first, node))
        drop_first(memory.heap, node - HEAP_BASE, count)
        machine.memory.put_bytes(regs[RDI], data)
        flag = self.pops < len(self.case.shrink) and self.case.shrink[self.pops]
        self.pops += 1
        if flag:
            self.word(regs[RDX], 1, 1)

    def on_build(self, machine):
        regs = machine.regs
        holder = self.bytes_at(regs[RSI], 32)
        source = self.bytes_at(regs[RDX], 48)
        self.expect(holder[8:32] == bytes(24), "builder cursor")
        self.expect(source[:8] == bytes(8) and source[40:48] == bytes(8), "builder source")
        self.events.append(("build",))

    def on_vacant(self, machine):
        regs = machine.regs
        holder, key, node, height, slot = struct.unpack("<5Q", self.bytes_at(regs[RSI], 40))
        self.expect(height == 0, "vacant height")
        value = bytearray(self.bytes_at(regs[RDX], 0x1A))
        value[8:16] = bytes(8)
        self.events.append(("vacant", holder, key, node, slot if node else None, bytes(value)))

    def node(self, layout, items, children, stale_key, parent=0, slot=0):
        base = self.next_node
        self.next_node += layout.stride
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * layout.stride)
        spots = {}
        for at in range(11):
            key, value = items[at] if at < len(items) else (stale_key, b"\xFF" * layout.val_size)
            memory.put_bytes(base + layout.key_at + layout.key_size * at, key)
            if layout.val_size:
                memory.put_bytes(base + layout.val_at + layout.val_size * at, value)
            if at < len(items):
                spots[key] = base + layout.val_at + layout.val_size * at
        self.word(base + layout.len_at, len(items), 2)
        self.word(base + layout.parent_at, parent)
        self.word(base + layout.slot_at, slot, 2)
        for at, child in enumerate(children):
            self.word(base + layout.edge_at + 8 * at, child)
        return base, spots

    def link(self, layout, parent, children):
        for slot, child in enumerate(children):
            self.word(child + layout.parent_at, parent)
            self.word(child + layout.slot_at, slot, 2)

    def tree(self, layout, items, shape, stale_key):
        items = sorted(items)
        if shape == "leaf":
            base, spots = self.node(layout, items, (), stale_key)
            return base, 0, spots
        if shape == "tall":
            return self.tall(layout, items, stale_key)
        half = len(items) // 2
        left, one = self.node(layout, items[:half], (), stale_key)
        right, two = self.node(layout, items[half + 1:], (), stale_key)
        base, spots = self.node(layout, items[half:half + 1], (left, right), stale_key)
        self.link(layout, base, (left, right))
        spots.update(one)
        spots.update(two)
        return base, 1, spots

    def tall(self, layout, items, stale):
        spots = {}
        leaves = []
        for at in (0, 4, 8, 12):
            base, found = self.node(layout, items[at:at + 3], (), stale)
            leaves.append(base)
            spots.update(found)
        low, one = self.node(layout, items[3:4], leaves[:2], stale)
        high, two = self.node(layout, items[11:12], leaves[2:], stale)
        root, three = self.node(layout, items[7:8], (low, high), stale)
        self.link(layout, low, leaves[:2])
        self.link(layout, high, leaves[2:])
        self.link(layout, root, (low, high))
        spots.update(one)
        spots.update(two)
        spots.update(three)
        return root, 2, spots

    def validators_value(self, indexes, shape, salt=0):
        items = []
        for index in indexes:
            value = struct.pack("<3Q", 0xD0 + index, 0xE0 + index, 0xF0 + index) + user_of(index + salt) + signer_of(index + salt)
            items.append((key_of(index), value))
        return self.tree(VALIDATOR_MAP, items, shape, key_of(indexes[0] if indexes else 1))

    def epoch_map(self, case, where):
        rows = []
        where["epoch_rows"] = {}
        for epoch, date in case.epochs:
            active = epoch == case.active or case.kind == LOOKUP and epoch == case.target
            if active and not case.v_null:
                built = self.validators_value(case.validators, case.v_shape)
                value = struct.pack("<3Q", built[0], built[1], len(case.validators))
                where["validators"] = set(case.validators)
            elif active:
                value = struct.pack("<3Q", 0, 0, 0)
                where["validators"] = set()
            else:
                built = self.validators_value(case.validators, "leaf", 16)
                value = struct.pack("<3Q", built[0], 0, len(case.validators))
            rows.append((struct.pack("<Q", epoch), value + struct.pack("<iII", date, 5, 6) + b"\xEE" * 4))
        where.setdefault("validators", set())
        if not rows and case.e_shape != "stale":
            where["epoch_root"] = 0
            self.word(STATE + S_EPOCHS, 0)
            self.word(STATE + S_EPOCHS + 8, 0)
            self.word(STATE + S_EPOCHS + 0x10, case.len_word or 0)
            return
        built = self.tree(EPOCH_MAP, rows, case.e_shape if rows else "leaf", struct.pack("<Q", case.active))
        where["epoch_root"] = built[0]
        for key, spot in built[2].items():
            where["epoch_rows"][struct.unpack("<Q", key)[0]] = spot
        self.word(STATE + S_EPOCHS, built[0])
        self.word(STATE + S_EPOCHS + 8, built[1])
        self.word(STATE + S_EPOCHS + 0x10, case.len_word if case.len_word is not None else len(rows))

    def stakes(self, case, where):
        stakes = case.stakes if case.stakes is not None else tuple((index, 100) for index in case.validators)
        where["stakes"] = {key_of(index): value for index, value in stakes}
        if not stakes or case.stake_empty:
            where["stakes"] = {}
            where["stake_built"] = (0, POISON, 0)
            where["stake_root"] = 0
            if case.stake_empty == "stale":
                built = self.tree(STAKE_MAP, [], "leaf", key_of(1))
                where["stake_built"] = (built[0], 0, 0)
                where["stake_root"] = built[0]
            return
        items = [(key_of(index), struct.pack("<Q", value)) for index, value in stakes]
        built = self.tree(STAKE_MAP, items, case.stake_shape, key_of(case.validators[0]))
        where["stake_built"] = (built[0], built[1], len(items))
        where["stake_root"] = built[0]

    def action(self, case):
        rows = sorted(case.signatures)
        self.signature_rows = []
        first = 0
        for chunk in range(0, max(len(rows), 1), 11):
            base = self.next_node
            self.next_node += NODE_STRIDE
            self.machine.memory.put_bytes(base, bytes([FILL]) * NODE_STRIDE)
            first = first or base
            for slot, (index, _) in enumerate(rows[chunk:chunk + 11]):
                self.machine.memory.put_bytes(base + 0x20 * slot, key_of(index))
                self.machine.memory.put_bytes(base + 0x168 + 0x48 * slot, signature_of(index))
                self.signature_rows.append((base, slot))
        self.action_root = 0 if case.a_null else first
        count = case.n_word if case.n_word is not None else len(rows)
        data = struct.pack("<3Q", self.action_root, 3, count) + struct.pack("<QQ", case.epoch, case.nonce)
        self.machine.memory.put_bytes(ACTION, data)

    def staking(self, case, where):
        cur = None
        if case.v_root and case.v_len:
            cur = self.validators_value((9,), "leaf", 32)
        where["cur_root"], where["cur_height"] = (cur[0], 0) if cur else (0, 0)
        data = struct.pack("<Q", case.duration) + struct.pack("<3Q", where["cur_root"], 0, case.v_len) + pack_time(case.start) + b"\xBB" * 4
        self.machine.memory.put_bytes(STATE, data)
        self.word(STATE + S_ACTIVE, case.active)
        self.word(STATE + S_CUR, case.cur)
        self.machine.memory.put_bytes(STATE + 0x58, b"\xDE" * 0x18)

    def tracker(self, case, where):
        self.word(TRACKER + 0x18, 0)
        self.word(TRACKER + 0x20, 0)
        self.word(TRACKER + 0x28, len(case.tracked))
        if case.t_null:
            where["t_leaf"], where["t_slot"] = 0, None
            return
        items = [(struct.pack("<Q", key), b"\x33" * 0x20) for key in case.tracked]
        built = self.tree(TRACKER_MAP, items, case.t_shape, struct.pack("<Q", case.target))
        self.word(TRACKER + 0x18, built[0])
        self.word(TRACKER + 0x20, built[1])
        node = built[0]
        for _ in range(built[1]):
            count = self.read(node + 0x1C2, 2)
            keys = [self.read(node + 0x168 + 8 * at) for at in range(count)]
            node = self.read(node + 0x1C8 + 8 * sum(1 for key in keys if key < case.target))
        keys = [self.read(node + 0x168 + 8 * at) for at in range(self.read(node + 0x1C2, 2))]
        where["t_leaf"], where["t_slot"] = node, sum(1 for key in keys if key < case.target)

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE, bytes([FILL]) * COMPARED)
        memory.put_bytes(OUT, blank())
        memory.statics[ONCE_CELL] = case.once
        where = {}
        self.next_node = NODES
        self.events = []
        self.case = case
        self.where = where
        self.signature_at = 0
        self.signature_rows = []
        self.iter_checked = False
        self.drained = False
        self.set_keys = []
        self.rows_done = 0
        self.absorbed = b""
        self.pops = 0
        self.old_left = 0
        self.old_started = False
        self.action_root = 0
        if case.kind == TRACK:
            self.tracker(case, where)
        else:
            self.staking(case, where)
            self.epoch_map(case, where)
            self.stakes(case, where)
            self.action(case)
            memory.put_bytes(KEY_AT, key_of(case.lookup))
            memory.put_bytes(NOW_AT, pack_time(case.now))
            if case.kind == QUORUM:
                if case.set_keys:
                    self.set_keys = [key_of(index) for index in case.set_keys]
                    self.write_set(SET_AT, self.set_keys)
                else:
                    self.word(SET_AT, 0)
                    self.word(SET_AT + 8, 0)
                    self.word(SET_AT + 0x10, 0)
        self.before = memory.bytes_at(HEAP_BASE, COMPARED)

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        junk = case.extra_high << 8
        try:
            if case.kind == FORCE:
                self.machine.run(FORCE, {RDI: OUT, RSI: STATE, RDX: case.chain | junk, RCX: ACTION})
            elif case.kind == ROLL:
                got = self.machine.run(ROLL, {RDI: STATE, RSI: case.force | junk, RDX: NOW_AT, RCX: case.target})
                return "value", got & 0xFF, tuple(self.events), memory.bytes_at(HEAP_BASE, COMPARED)
            elif case.kind == QUORUM:
                root, height = self.read(STATE + S_EPOCHS), self.read(STATE + S_EPOCHS + 8)
                got = self.machine.run(QUORUM, {RDI: root, RSI: height, RDX: case.target, RCX: SET_AT})
                return "value", got & 0xFF, tuple(self.events), memory.bytes_at(HEAP_BASE, COMPARED)
            elif case.kind == LOOKUP:
                self.machine.run(LOOKUP, {RDI: OUT, RSI: STATE, RDX: KEY_AT, RCX: case.target})
            elif case.kind == TRACK:
                self.machine.run(TRACK, {RDI: OUT, RSI: TRACKER, RDX: case.target})
            else:
                got = self.machine.run(LAST, {RDI: STATE})
                pair = (got & 1, self.machine.regs[RDX] if got & 1 else None)
                return "value", pair, tuple(self.events), memory.bytes_at(HEAP_BASE, COMPARED)
        except Panicked as stop:
            return "panic", stop.args[0], tuple(self.events)
        return "done", tuple(self.events), memory.bytes_at(HEAP_BASE, COMPARED)


LOW = 19000
THREE = ((1, 100), (2, 100), (3, 100))
FULL = tuple((index, "ok") for index in (1, 2, 3))
TWO = FULL[:2]
ONE = FULL[:1]
LATE = (BASE_DATE, 3600 + 86400, 9)
HEAVY = dict(validators=(1, 2, 3), stakes=THREE)
MANY = tuple(range(1, 14))
FIFTEEN = tuple(range(1, 16))
LONG_ROWS = tuple((index, 100) for index in MANY)
SIXTEEN_EPOCHS = tuple((index, LOW) for index in range(1, 16))


def date_of(year, ordinal, flags=5):
    return (year << 13) | (ordinal << 4) | flags


FORCE_NAMED = (
    ("plain", dict()), ("all_validators", dict(validators=(1, 2, 3), stakes=THREE)),
    ("chain_zero", dict(chain=0)), ("chain_one", dict(chain=1)), ("chain_two", dict(chain=2)), ("chain_four", dict(chain=4)), ("chain_top", dict(chain=0xFF)), ("chain_high_bits", dict(chain=3, extra_high=0xABCDEF)), ("chain_low_byte_only", dict(chain=2, extra_high=0x3)),
    ("nonce_zero", dict(nonce=0)), ("nonce_top", dict(nonce=TOP)),
    ("no_signatures", dict(signatures=())), ("null_action", dict(a_null=True, signatures=())), ("one_of_three", dict(signatures=ONE, **HEAVY)), ("two_of_three", dict(signatures=TWO, **HEAVY)), ("three_of_three", dict(signatures=FULL, **HEAVY)),
    ("two_thirds_exact", dict(signatures=TWO, validators=(1, 2, 3), stakes=((1, 2), (2, 2), (3, 2)))), ("two_thirds_plus", dict(signatures=TWO, validators=(1, 2, 3), stakes=((1, 101), (2, 100), (3, 100)))), ("two_thirds_minus", dict(signatures=TWO, validators=(1, 2, 3), stakes=((1, 100), (2, 100), (3, 101)))),
    ("zero_stake_signers", dict(signatures=TWO, validators=(1, 2, 3), stakes=((1, 0), (2, 0), (3, 100)))), ("all_zero_stake", dict(signatures=FULL, validators=(1, 2, 3), stakes=((1, 0), (2, 0), (3, 0)))), ("signer_without_stake_row", dict(signatures=FULL, validators=(1, 2, 3, 4), stakes=((1, 100), (2, 100), (4, 100)))), ("no_stake_rows", dict(stake_empty=True)), ("empty_stake_root", dict(stake_empty="stale")), ("active_missing_null_action", dict(active=4, a_null=True, signatures=())),
    ("active_missing_rolls", dict(active=4)), ("active_missing_refused", dict(active=4, added=(BASE_DATE, 3600, 9))), ("active_missing_once", dict(active=4, added=(BASE_DATE, 3600, 9), once=1)), ("active_missing_ignores_epoch", dict(active=4, epoch=1)), ("active_missing_ignores_count", dict(active=4, n_word=20000)), ("active_missing_ignores_cap", dict(active=4, epoch=TOP)), ("active_missing_null_map", dict(epochs=())), ("active_missing_null_map_stale", dict(epochs=(), active=0, chain=0, v_len=3)),
    ("active_missing_tall", dict(active=40, e_shape="tall", epochs=SIXTEEN_EPOCHS)), ("active_found_tall", dict(active=8, e_shape="tall", epochs=SIXTEEN_EPOCHS, cur=20, epoch=30)), ("active_found_deep", dict(active=7, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13], cur=20, epoch=30)), ("active_missing_deep", dict(active=40, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13])),
    ("count_limit", dict(n_word=10000)), ("count_over", dict(n_word=10001)), ("count_top", dict(n_word=TOP)), ("count_over_null_root", dict(a_null=True, n_word=10001, signatures=())),
    ("epoch_equal_cur", dict(epoch=7)), ("epoch_below_cur", dict(epoch=6)), ("epoch_above_cur", dict(epoch=9)), ("epoch_zero", dict(epoch=0)), ("epoch_cap_less", dict(epoch=NUMBER_CAP - 1)), ("epoch_cap", dict(epoch=NUMBER_CAP)), ("epoch_cap_more", dict(epoch=NUMBER_CAP + 1)), ("epoch_top", dict(epoch=TOP)), ("epoch_below_once", dict(epoch=6, once=2)), ("epoch_cap_null", dict(epoch=NUMBER_CAP, a_null=True, signatures=())), ("epoch_low_null", dict(epoch=6, a_null=True, signatures=())),
    ("recover_fails_first", dict(signatures=((1, "fail"), (2, "ok")))), ("recover_fails_later", dict(signatures=((1, "ok"), (2, "ok"), (3, "fail")))), ("digest_fails_first", dict(digest_fail=0)), ("digest_fails_later", dict(digest_fail=2)),
    ("wrong_first_byte", dict(signatures=((1, "wrong_first"),))), ("wrong_last_byte", dict(signatures=((1, "wrong_last"),))), ("wrong_byte_16", dict(signatures=((1, "wrong_word"),))), ("wrong_after_good", dict(signatures=((1, "ok"), (2, "wrong_last")))),
    ("unknown_slot", dict(signatures=((9, "ok"),))), ("unknown_after_good", dict(signatures=((1, "ok"), (9, "ok")))), ("unknown_low", dict(validators=(5, 6), signatures=((2, "ok"),))), ("null_validators", dict(v_null=True)), ("unknown_before_mismatch", dict(signatures=((9, "wrong_last"),))), ("fail_before_unknown", dict(signatures=((9, "fail"),))),
    ("validators_deep", dict(validators=MANY, v_shape="deep", stakes=LONG_ROWS, stake_shape="deep", signatures=tuple((index, "ok") for index in MANY[:10]))), ("validators_tall", dict(validators=FIFTEEN, v_shape="tall", stake_shape="tall", stakes=tuple((index, 100) for index in FIFTEEN), signatures=tuple((index, "ok") for index in FIFTEEN[:11]))), ("validators_deep_miss", dict(validators=tuple(index * 2 for index in range(1, 14)), v_shape="deep", signatures=((5, "ok"),))), ("validators_tall_miss", dict(validators=tuple(index * 2 for index in range(1, 16)), v_shape="tall", signatures=((31, "ok"),))),
    ("twelve_signatures", dict(validators=MANY, v_shape="deep", stakes=LONG_ROWS, stake_shape="deep", signatures=tuple((index, "ok") for index in MANY[:12]))), ("stakes_deep", dict(validators=MANY, stake_shape="deep", stakes=LONG_ROWS, signatures=tuple((index, "ok") for index in MANY[:9]))), ("stakes_tall", dict(validators=FIFTEEN, stake_shape="tall", stakes=tuple((index, 100) for index in FIFTEEN), signatures=tuple((index, "ok") for index in FIFTEEN[:11]))),
    ("stake_total_overflow", dict(validators=(1, 2, 3), stakes=((1, TOP), (2, 1), (3, 0)))), ("stake_total_top", dict(validators=(1, 2, 3), stakes=((1, TOP - 1), (2, 1), (3, 0)))), ("stake_large_cross", dict(signatures=TWO, validators=(1, 2, 3), stakes=((1, 1 << 62), (2, 1 << 62), (3, 1 << 60)))),
    ("time_refused_after_signatures", dict(added=(BASE_DATE, 3600, 9))), ("time_earlier_refused", dict(added=(BASE_DATE, 0, 0))), ("time_refused_once", dict(added=(BASE_DATE, 3600, 9), once=3)), ("duration_one", dict(duration=1)), ("duration_huge", dict(duration=1 << 40, added=(BASE_DATE, 3600, 9))), ("duration_top", dict(duration=TOP, added=(BASE_DATE, 3600, 9))),
    ("no_current_validators", dict(v_len=0, v_root=False)), ("current_len_three", dict(v_len=3)), ("current_len_null_root", dict(v_root=False)), ("replaced_row", dict(old=(0x7000, 2, 0))), ("replaced_rows", dict(old=(0x7000, 2, 3))), ("replaced_null", dict(old=(0, 0, 0))),
    ("prune_after_force", dict(len_word=1000, epochs=((2, LOW), (5, LOW), (6, LOW)))), ("no_prune_below", dict(len_word=999)), ("activates_while_active_zero", dict(active=0, epochs=((0, LOW), (6, LOW)), chain=1)), ("once_after_force", dict(once=5)),
)
ROLL_NAMED = (
    ("same_bucket", dict()), ("next_bucket", dict(now=LATE)), ("below_cur", dict(now=LATE, target=6)), ("equal_cur", dict(now=LATE, target=7)), ("above_cur", dict(now=LATE, target=8)), ("target_top", dict(now=LATE, target=TOP)), ("target_top_less", dict(now=LATE, target=TOP - 1)), ("cur_top_refused", dict(now=LATE, cur=TOP, target=TOP - 1)), ("cur_top", dict(now=LATE, cur=TOP, target=TOP)),
    ("boundary_before", dict(start=(BASE_DATE, 86399, 0), now=(BASE_DATE, 86399, 7))), ("boundary_at", dict(start=(BASE_DATE, 86399, 0), now=(BASE_DATE, 86400, 0))), ("earlier_now", dict(start=(BASE_DATE, 3600, 0), now=(BASE_DATE, 0, 0))), ("nanos_ignored", dict(start=(BASE_DATE, 3600, 0), now=(BASE_DATE, 3600, 0xFFFFFFFF))), ("day_step", dict(now=(BASE_DATE + (1 << 4), 3600, 0))), ("year_step", dict(now=(BASE_DATE + (1 << 13), 0, 0))),
    ("duration_one_same", dict(duration=1, now=(BASE_DATE, 3600, 0))), ("duration_one_next", dict(duration=1, now=(BASE_DATE, 3601, 0))), ("duration_7", dict(duration=7, start=(BASE_DATE, 6, 0), now=(BASE_DATE, 7, 0))), ("duration_2_32", dict(duration=1 << 32, start=(BASE_DATE, 3600, 0), now=(BASE_DATE + (1 << 13) * 200, 0, 0))), ("duration_2_33_bucket", dict(duration=1 << 33, now=(date_of(2300, 1), 0, 0))), ("duration_low_32", dict(duration=0xFFFFFFFF, now=LATE)), ("duration_top", dict(duration=TOP, now=LATE)),
    ("before_1970_both", dict(start=(date_of(1969, 100), 0, 0), now=(date_of(1969, 200), 0, 0))), ("before_1970_start", dict(start=(date_of(1969, 100), 0, 0), now=(date_of(1970, 2), 0, 0))), ("year_zero", dict(start=(date_of(0, 1), 0, 0), now=(date_of(2000, 1), 0, 0))), ("year_negative", dict(start=(date_of(-5, 1), 0, 0), now=(date_of(-4, 1), 0, 0))), ("year_negative_now", dict(start=(date_of(2000, 1), 0, 0), now=(date_of(-400, 1), 0, 0))), ("year_top_chrono", dict(start=(date_of(262000, 1), 0, 0), now=(date_of(262001, 1), 0, 0), duration=3600)),
    ("flag_force", dict(active=0, force=1)), ("flag_force_top", dict(active=0, force=0xFF)), ("flag_force_high_bits_zero", dict(active=0, force=0, extra_high=0x123456, v_len=4)), ("flag_len_three", dict(active=0, v_len=3)), ("flag_len_four_same", dict(active=0, v_len=4)), ("flag_len_two_same", dict(active=0, v_len=2)), ("flag_len_four_next", dict(active=0, v_len=4, now=LATE)), ("flag_below_cur", dict(active=0, force=1, target=6)), ("active_set_force", dict(active=2, force=1)), ("active_set_len_three", dict(active=2, v_len=3)), ("flag_force_next", dict(active=0, force=1, now=LATE)),
    ("no_validators", dict(v_len=0, v_root=False, now=LATE)), ("null_root_with_len", dict(v_root=False, now=LATE)), ("flag_null_root", dict(active=0, force=1, v_root=False)), ("replaced", dict(now=LATE, old=(0x7000, 2, 0))), ("replaced_three", dict(now=LATE, old=(0x7000, 2, 3))), ("replaced_null", dict(now=LATE, old=(0, 0, 0))), ("once", dict(now=LATE, once=1)), ("once_refused", dict(once=1)),
    ("prune_limit_no", dict(now=LATE, len_word=999)), ("prune_limit_yes", dict(now=LATE, len_word=1000)), ("prune_key_equal_active", dict(now=LATE, len_word=1000, epochs=((5, LOW), (6, LOW)))), ("prune_key_above_active", dict(now=LATE, len_word=1000, epochs=((6, LOW), (8, LOW)))), ("prune_two", dict(now=LATE, len_word=1001, epochs=((1, LOW), (2, LOW), (5, LOW)))), ("prune_stops_at_active", dict(now=LATE, len_word=1010, epochs=((1, LOW), (2, LOW), (5, LOW), (6, LOW)))), ("prune_new_active", dict(now=LATE, active=0, force=1, len_word=1001, cur=4, epochs=((1, LOW), (2, LOW), (5, LOW)))), ("prune_new_active_stops", dict(now=LATE, active=0, force=1, len_word=1010, cur=2, epochs=((1, LOW), (2, LOW), (5, LOW)))),
    ("prune_date_zero", dict(now=LATE, len_word=1000, epochs=((2, 0), (5, LOW)))), ("prune_null_map", dict(now=LATE, len_word=2000, epochs=())), ("prune_empty_leaf", dict(now=LATE, len_word=2000, e_shape="stale", epochs=())), ("prune_deep", dict(now=LATE, len_word=1001, active=9, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13])), ("prune_tall", dict(now=LATE, len_word=1001, active=9, e_shape="tall", epochs=SIXTEEN_EPOCHS)), ("prune_shrink", dict(now=LATE, len_word=1000, active=9, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13], shrink=(True,))), ("prune_shrink_tall", dict(now=LATE, len_word=1000, active=9, e_shape="tall", epochs=SIXTEEN_EPOCHS, shrink=(True,))), ("prune_shrink_leaf_panics", dict(now=LATE, len_word=1000, shrink=(True,))), ("prune_shrink_then_more", dict(now=LATE, len_word=1001, active=9, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13], shrink=(True, False))), ("prune_first_leaf_empties", dict(now=LATE, len_word=1010, active=9, e_shape="deep", epochs=SIXTEEN_EPOCHS[:5])),
)


def pin(label, date):
    """Both sides of one date: the rows must give exactly unix_seconds for `now` and for `start`."""
    seconds = unix_seconds(date, 0)
    base = date_of(1970, 1)
    return ((label + "_now_at", dict(duration=seconds, start=(base, 0, 0), now=(date, 0, 0))), (label + "_now_past", dict(duration=seconds + 1, start=(base, 0, 0), now=(date, 0, 0))),
            (label + "_start_at", dict(duration=seconds, start=(date, 0, 0), now=(date, 0, 0))), (label + "_start_past", dict(duration=seconds + 1, start=(date, 0, 0), now=(date, seconds + 1, 0))))


ROLL_NAMED += pin("pin_2001", date_of(2001, 61)) + pin("pin_2101", date_of(2101, 305)) + pin("pin_2026", date_of(2026, 305)) + pin("pin_2004", date_of(2004, 366)) + (
    ("bucket_wide_flag", dict(duration=1 << 33, active=0, force=1)), ("bucket_wide_active", dict(duration=1 << 33, active=2, force=1)), ("bucket_wide_len_three", dict(duration=1 << 33, active=0, v_len=3)), ("bucket_wide_no_flag", dict(duration=1 << 33, active=0)),
    ("once_prune_no", dict(now=LATE, once=1, len_word=999)), ("once_prune_yes", dict(now=LATE, once=1, len_word=1000)),
)
FORCE_NAMED += (("active_right_deep", dict(active=11, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13], cur=20, epoch=30)), ("active_right_tall", dict(active=14, e_shape="tall", epochs=SIXTEEN_EPOCHS, cur=20, epoch=30)),)
QUORUM_NAMED = (
    ("stake_root_no_rows", dict(target=5, stake_empty="stale")), ("set_tall", dict(target=5, validators=FIFTEEN, stake_shape="tall", stakes=tuple((index, 3) for index in FIFTEEN), set_keys=FIFTEEN)),
    ("plain", dict(target=5)), ("epoch_absent", dict(target=4)), ("map_null", dict(target=5, epochs=())), ("epoch_tall", dict(target=8, e_shape="tall", epochs=SIXTEEN_EPOCHS, active=8)), ("epoch_tall_miss", dict(target=40, e_shape="tall", epochs=SIXTEEN_EPOCHS)), ("epoch_deep", dict(target=7, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13], active=7)), ("epoch_deep_miss", dict(target=40, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13])),
    ("no_set", dict(target=5, set_keys=())), ("no_stakes", dict(target=5, stake_empty=True)), ("no_set_no_stakes", dict(target=5, set_keys=(), stake_empty=True)), ("set_outside_stakes", dict(target=5, set_keys=(8, 9))), ("set_partly_outside", dict(target=5, set_keys=(1, 2, 3, 9), validators=(1, 2, 3), stakes=THREE)), ("exact_two_thirds", dict(target=5, set_keys=(1, 2), stakes=THREE, validators=(1, 2, 3))), ("one_above", dict(target=5, set_keys=(1, 2), stakes=((1, 101), (2, 100), (3, 100)), validators=(1, 2, 3))), ("one_below", dict(target=5, set_keys=(1, 2), stakes=((1, 100), (2, 100), (3, 101)), validators=(1, 2, 3))), ("all", dict(target=5, set_keys=(1, 2, 3, 4))), ("all_zero", dict(target=5, set_keys=(1, 2), stakes=((1, 0), (2, 0)), validators=(1, 2))),
    ("total_top", dict(target=5, set_keys=(1,), stakes=((1, TOP),), validators=(1,))), ("total_overflow", dict(target=5, stakes=((1, TOP), (2, 1)), validators=(1, 2), set_keys=(1,))), ("total_overflow_late", dict(target=5, stakes=((1, 1 << 63), (2, 1 << 62), (3, 1 << 62)), validators=(1, 2, 3), set_keys=(1,))), ("wide_product_true", dict(target=5, set_keys=(1, 2), stakes=((1, 1 << 62), (2, 1 << 62), (3, 1 << 63)), validators=(1, 2, 3))), ("wide_product_equal", dict(target=5, set_keys=(1,), stakes=((1, 3 << 61), (2, 3 << 60)), validators=(1, 2))), ("wide_low_word", dict(target=5, set_keys=(1,), stakes=((1, 0xAAAAAAAAAAAAAAAB), (2, 0x5555555555555554)), validators=(1, 2))), ("wide_low_word_less", dict(target=5, set_keys=(1,), stakes=((1, 0xAAAAAAAAAAAAAAAA), (2, 0x5555555555555555)), validators=(1, 2))),
    ("stakes_deep", dict(target=5, stake_shape="deep", validators=MANY, stakes=LONG_ROWS, set_keys=MANY[:9])), ("stakes_tall", dict(target=5, stake_shape="tall", validators=FIFTEEN, stakes=tuple((index, 7) for index in FIFTEEN), set_keys=FIFTEEN[:11])), ("stakes_eleven", dict(target=5, validators=MANY[:11], stakes=LONG_ROWS[:11], set_keys=MANY[:8])), ("set_deep", dict(target=5, validators=MANY, stake_shape="deep", stakes=LONG_ROWS, set_keys=MANY)), ("set_deep_sparse", dict(target=5, validators=(2, 4), stakes=((2, 5), (4, 5)), set_keys=MANY)), ("set_tall_keys", dict(target=5, validators=FIFTEEN, stake_shape="tall", stakes=tuple((index, index) for index in FIFTEEN), set_keys=FIFTEEN[:14])), ("set_missing_first", dict(target=5, validators=(5, 6, 7), stakes=((5, 1), (6, 1), (7, 9)), set_keys=(1, 7))), ("set_missing_last", dict(target=5, validators=(5, 6, 7), stakes=((5, 1), (6, 1), (7, 9)), set_keys=(7, 15))),
)
LOOKUP_NAMED = (
    ("plain", dict(target=5)), ("second", dict(target=5, lookup=3)), ("last", dict(target=5, lookup=4)), ("key_absent", dict(target=5, lookup=9)), ("epoch_absent", dict(target=4)), ("map_null", dict(target=5, epochs=())), ("null_validators", dict(target=5, v_null=True)), ("epoch_deep", dict(target=7, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13])), ("epoch_deep_miss", dict(target=40, e_shape="deep", epochs=SIXTEEN_EPOCHS[:13])), ("epoch_tall", dict(target=8, e_shape="tall", epochs=SIXTEEN_EPOCHS)), ("key_deep", dict(target=5, lookup=7, v_shape="deep", validators=MANY)), ("key_deep_miss", dict(target=5, lookup=31, v_shape="deep", validators=MANY)), ("key_deep_low_miss", dict(target=5, lookup=1, v_shape="deep", validators=tuple(index * 2 for index in range(1, 14)))), ("key_tall", dict(target=5, lookup=12, v_shape="tall", validators=FIFTEEN)), ("key_tall_miss", dict(target=5, lookup=31, v_shape="tall", validators=FIFTEEN)),
)
LAST_NAMED = (
    ("leaf", dict()), ("one_row", dict(epochs=((9, LOW),))), ("deep", dict(e_shape="deep", epochs=SIXTEEN_EPOCHS[:13])), ("tall", dict(e_shape="tall", epochs=SIXTEEN_EPOCHS)), ("null", dict(epochs=(), l_null=True)), ("zero_len", dict(len_word=0, l_zero=True)), ("eleven", dict(epochs=SIXTEEN_EPOCHS[:11])),
)
TRACK_NAMED = (
    ("hit", dict(target=5, tracked=(1, 5, 9))), ("miss_low", dict(target=0, tracked=(1, 5, 9))), ("miss_middle", dict(target=4, tracked=(1, 5, 9))), ("miss_high", dict(target=10, tracked=(1, 5, 9))), ("null_root", dict(target=5, tracked=(), t_null=True)), ("empty_leaf", dict(target=5, tracked=())), ("deep_hit", dict(target=70, t_shape="deep", tracked=tuple(index * 10 for index in range(1, 14)))), ("deep_root_hit", dict(target=70, t_shape="deep", tracked=tuple(index * 10 for index in range(1, 15)))), ("deep_miss", dict(target=75, t_shape="deep", tracked=tuple(index * 10 for index in range(1, 14)))), ("tall_hit", dict(target=120, t_shape="tall", tracked=tuple(index * 10 for index in range(1, 16)))), ("tall_miss", dict(target=125, t_shape="tall", tracked=tuple(index * 10 for index in range(1, 16)))), ("key_top", dict(target=TOP, tracked=(TOP,))), ("eleven_miss", dict(target=TOP, tracked=tuple(range(1, 12)))),
)
GROUPS = ((FORCE, FORCE_NAMED), (ROLL, ROLL_NAMED), (QUORUM, QUORUM_NAMED), (LOOKUP, LOOKUP_NAMED), (LAST, LAST_NAMED), (TRACK, TRACK_NAMED))


def named_cases():
    return [Case(name, kind, **fields) for kind, group in GROUPS for name, fields in group]


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11 ^ state


def vector_cases(count):
    source = lcg(0x3368)
    rows = []
    for index in range(count):
        word, other, third = next(source), next(source), next(source)
        if index % 3 == 0:
            members = tuple(range(1, 5 + (word & 7)))
            stakes = tuple((key, (other >> (key * 4)) & 0xFF) for key in members)
            signers = tuple((key, "ok") for key in members if third >> key & 1)
            rows.append(Case("v%d" % index, FORCE, validators=members, stakes=stakes, signatures=signers, chain=word >> 8 & 3, epoch=6 + (word >> 10 & 3), nonce=other))
        elif index % 3 == 1:
            shift = word & 31
            rows.append(Case("v%d" % index, ROLL, duration=1 + (other >> (shift + 20)), start=(date_of(1960 + (word >> 8 & 127), 1 + (word >> 16 & 255)), third & 0x1FFFF, 0), now=(date_of(1960 + (other >> 8 & 127), 1 + (other >> 16 & 255)), third >> 20 & 0x1FFFF, 0), active=word >> 24 & 1, force=word >> 25 & 1, v_len=word >> 26 & 3 or 1, target=6 + (word >> 28 & 3)))
        else:
            members = tuple(range(1, 4 + (word & 7)))
            stakes = tuple((key, other >> ((key * 7) & 31)) for key in members)
            limit = 1 << 64
            while sum(value for _, value in stakes) >= limit:
                stakes = tuple((key, value >> 1) for key, value in stakes)
            chosen = tuple(key for key in members if third >> key & 1)
            rows.append(Case("v%d" % index, QUORUM, target=5, validators=members, stakes=stakes, set_keys=chosen))
    return rows


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case, harness.before, harness.where)
        if got != want:
            if got[0] == want[0] and got[0] in ("done", "value"):
                diff = [hex(HEAP_BASE + at) for at in range(COMPARED) if got[-1][at] != want[-1][at]][:12]
                raise EvidenceError("case %s %#x: %r != %r diff %s" % (case.name, case.kind, got[:-1], want[:-1], diff))
            raise EvidenceError("case %s %#x: %r != %r" % (case.name, case.kind, got[:3], want[:3]))
        outcomes.append(got)
    return outcomes


def calendar_rows(harness):
    """Real rows against the standard calendar: floor(U/X) is 1 and floor(U/(X+1)) is 0 only when U is exactly X."""
    rows = []
    epoch = datetime.date(1970, 1, 1)
    for year, month, day in ((1970, 1, 1), (1970, 1, 2), (1971, 3, 1), (1972, 2, 29), (1972, 3, 1), (1999, 12, 31), (2000, 2, 29), (2000, 3, 1), (2024, 12, 31), (2026, 10, 31), (2100, 3, 1), (2400, 2, 29), (9999, 12, 31)):
        value = datetime.date(year, month, day)
        ordinal = value.timetuple().tm_yday
        seconds = (value - epoch).days * 86400
        date = date_of(year, ordinal)
        if unix_seconds(date, 0) != seconds:
            raise EvidenceError("calendar rule at %s" % value)
        answers = []
        for duration in (seconds, seconds + 1):
            if duration == 0:
                answers.append(1)
                continue
            case = Case("calendar", ROLL, duration=duration, start=(date_of(1970, 1), 0, 0), now=(date, 0, 0), target=7)
            got = harness.run(case)
            if got != spec_run(case, harness.before, harness.where):
                raise EvidenceError("calendar case %s" % value)
            answers.append(got[1])
        if answers != [1, 0]:
            raise EvidenceError("calendar bucket %s %r" % (value, answers))
        rows.append((value.isoformat(), ordinal, "%#x" % date, seconds, answers[0], answers[1]))
    return rows


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


def slot_loads(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", text):
        at = match.start()
        if at + 7 <= len(text) and start + at + 7 + struct.unpack_from("<i", text, at + 3)[0] == slot:
            hits.append(start + at)
    return hits


def caller_rows(image):
    relative = image.relative()
    rows = []
    for slot, target, role, count, kind in ((SLOT_FORCE, FORCE, "force_increase_epoch", 3, "call"), (SLOT_LAST, LAST, "last_epoch_key", 6, "call"), (SLOT_LOOKUP, LOOKUP, "validator_user", 2, "load")):
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        sites = sorted(slot_sites(image, slot) if kind == "call" else slot_loads(image, slot))
        if len(sites) != count:
            raise EvidenceError("slot %#x has %d sites" % (slot, len(sites)))
        rows.append(("slot %#x" % slot, role, "%#x" % target, len(sites), " ".join("%#x" % site for site in sites)))
    for target, role, count in ((ROLL, "advance_epoch", 5), (QUORUM, "stake_quorum", 8), (TRACK, "signature_tracker_slot", 6), (ENCODE_TUPLE, "signed_tuple_encode", 4)):
        sites = sorted(direct_to(image, target))
        if len(sites) != count:
            raise EvidenceError("%#x has %d direct calls" % (target, len(sites)))
        rows.append(("direct", role, "%#x" % target, len(sites), " ".join("%#x" % site for site in sites)))
    return rows


FIELDS = (
    ("Staking", 0x33651AC, 0x58A819, 12, "epoch_states", 0x30, 0x33651CA, "498d7630"), ("Staking", 0x33651F2, 0x58A825, 12, "active_epoch", 0x48, 0x3365210, "498b5648"), ("Staking", 0x3365237, 0x58A831, 15, "cur_epoch_state", 8, 0x3365255, "498d7608"), ("Staking", 0x3365278, 0x58A840, 9, "cur_epoch", 0x50, 0x3365296, "498b5650"), ("Staking", 0x33652BD, 0x58A849, 22, "epoch_duration_seconds", 0, 0x33652D7, "498b16"),
    ("EpochState", 0x3365B6C, 0x206BA0, 16, "validator_states", 0, 0x3365B8B, "4c89f6"), ("EpochState", 0x3365BA9, 0x58A886, 10, "start_time", 0x18, 0x3365BC3, "4983c618"),
    ("ValidatorState", 0x3365D26, 0x58A8B5, 11, "delegations", 0, 0x3365D47, "4c89fe"), ("ValidatorState", 0x3365D68, 0x20ACC0, 8, None, 0x18, 0x3365D86, "498d5718"), ("ValidatorState", 0x3365DC9, 0x58A79F, 9, "cold_user", 0x2C, 0x3365DE3, "4983c72c"),
    ("ForceIncreaseEpochAction", 0x3981DD6, 0x5A75B0, 23, "validatorsAndSignatures", 0, 0x3981E0D, "4d89f8"), ("ForceIncreaseEpochAction", 0x3981E2B, 0x5A75C7, 14, "newActiveEpoch", 0x18, 0x3981E45, "498b5718"), ("ForceIncreaseEpochAction", 0x3981E68, 0x5A5ED8, 5, "nonce", 0x20, 0x3981E82, "498b5720"),
)


def field_rows(image):
    rows = []
    for owner, site, key, size, text, offset, proof, form in FIELDS:
        data = bytes(image.blob[image.offset(site):image.offset(site) + 12])
        if data[:3] != b"\x48\x8d\x35" or site + 7 + struct.unpack_from("<i", data, 3)[0] != key or data[7] != 0xBA or struct.unpack_from("<I", data, 8)[0] != size:
            raise EvidenceError("key row %#x" % site)
        found = bytes(image.blob[image.offset(key):image.offset(key) + size]).decode("ascii")
        if text is not None and found != text:
            raise EvidenceError("key text %s" % found)
        want = bytes.fromhex(form)
        if bytes(image.blob[image.offset(proof):image.offset(proof) + len(want)]) != want:
            raise EvidenceError("field proof %#x" % proof)
        rows.append((owner, "%#x" % site, "%#x" % key, found, "%#x" % offset, "%#x" % proof, form))
    return rows


def constant_rows(image):
    rows = []
    table = ((0x58C012, b"forceIncreaseEpoch"),)
    for va, wanted in table:
        if bytes(image.blob[image.offset(va):image.offset(va) + len(wanted)]) != wanted:
            raise EvidenceError("constant text %#x" % va)
        rows.append(("signed_string", "%#x" % va, wanted.decode("ascii")))
    head = (
        ("signature_limit_compare", 0x3368455, "4981fd11270000", "cmp r13, 10001; jb continues"),
        ("number_cap", 0x336857A, "48b8cccccccccccccc0c", "movabs rax, 0x0ccccccccccccccc"),
        ("keccak_rate", 0x3368995, "48c78424f002000088000000", "qword [rsp+0x2f0] = 0x88"),
        ("keccak_delimiter", 0x33689A1, "66c78424f80200000100", "word [rsp+0x2f8] = 1"),
        ("chain_id", 0x3368AAF, "48c78424580200003905000000000000"[:24], "qword [rsp+0x258] = 0x539"),
        ("source_base", 0x336877F, "b162", "cl = 0x62, then sub the chain==3 bit"),
        ("prune_compare", 0x3369A1B, "48817b40e9030000", "cmp [S+0x40], 1001"),
        ("second_prune_compare", 0x3369A40, "48817b40e8030000", "cmp [S+0x40], 1000"),
        ("quorum_factor", 0x3367387, "ba03000000", "edx = 3, mul by the signed sum"),
        ("quorum_double", 0x3367394, "4801f6", "add rsi, rsi: total * 2 with its top bit kept apart"),
        ("seconds_per_day", 0x3369758, "4869c980510100", "imul rcx, rcx, 86400"),
        ("unix_day_shift", 0x336974F, "81c1c506f5ff", "add ecx, -719163"),
    )
    for name, va, form, note in head:
        want = bytes.fromhex(form)
        if bytes(image.blob[image.offset(va):image.offset(va) + len(want)]) != want:
            raise EvidenceError("constant row %s %s" % (name, bytes(image.blob[image.offset(va):image.offset(va) + len(want)]).hex()))
        rows.append((name, "%#x" % va, note))
    return rows


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in TEXT_TAGS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
        at = data.find(b"\x48\x8d\x35")
        if at < 0:
            rows.append(("%#x" % tag, "%#x" % arm, "(formatted arm)"))
            continue
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0] if data[at + 7] == 0xBA else 0
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + min(size, 80)]).decode("ascii", "replace")))
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
            if harness.run(case) != spec_run(case, harness.before, harness.where):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error):
            return case
    return None


NEGATIVE_YEAR = "row of the year <= 0 branch: a low bit edit keeps the seconds negative and the max(0) clamp hides it; no chain date reaches it"
EIGHT = "the unrolled eight-step descent starts at height 8; the bound picks between two walks of one path and no tree here is that tall"
FIRST_LEAF = "first leaf length: only tested against 0 or the slot 0, and a leaf reached with rows left has a nonzero word at both offsets"
SATURATE = "saturating add of the signed sum: signed keys are unique and a subset of the stake map whose checked total did not overflow, so the carry never sets"
UNWIND = "the word is read only on an unwind landing pad, which no case reaches"
SECOND_WALK = "second walk for a key the first walk already found in an unchanged map: it cannot miss, so the height and the missing branch are unread"
ROOT_WORD = "compare of the stake root with 0: a map with rows has a root, so an edit to compare with 1 gives the same branch"
SEEDED = "the frame word is already zero from the clear of the keccak state just above"
LOCAL_VEC = "capacity word of a local vector that only the unwind path frees"
SIGN_FIX = "sign bit of a signed divide: the shifted year is positive on every path, also after the 400 year cycles are added"
EXPECTED_SURVIVORS = {
    (0x33685ab, "condition"): UNWIND,
    (0x3368a6b, "displacement"): SEEDED,
    (0x3368b6f, "immediate"): SECOND_WALK,
    (0x3368b7d, "displacement"): SECOND_WALK,
    (0x3368bd3, "immediate"): SECOND_WALK,
    (0x3368e17, "displacement"): SECOND_WALK,
    (0x33696ef, "immediate"): NEGATIVE_YEAR,
    (0x33696f8, "immediate"): NEGATIVE_YEAR,
    (0x33696ff, "immediate"): NEGATIVE_YEAR,
    (0x3369706, "immediate"): NEGATIVE_YEAR,
    (0x3369710, "immediate"): NEGATIVE_YEAR,
    (0x33697a2, "immediate"): NEGATIVE_YEAR,
    (0x33697ab, "immediate"): NEGATIVE_YEAR,
    (0x33697b2, "immediate"): NEGATIVE_YEAR,
    (0x33697b9, "immediate"): NEGATIVE_YEAR,
    (0x33697c3, "immediate"): NEGATIVE_YEAR,
    (0x336973a, "immediate"): SIGN_FIX,
    (0x33697ee, "immediate"): SIGN_FIX,
    (0x3369a95, "immediate"): EIGHT,
    (0x3369b25, "immediate"): EIGHT,
    (0x3366cd5, "immediate"): EIGHT,
    (0x3366db8, "immediate"): EIGHT,
    (0x3366ee5, "immediate"): EIGHT,
    (0x3366fc8, "immediate"): EIGHT,
    (0x33676fd, "immediate"): EIGHT,
    (0x3369b6e, "displacement"): FIRST_LEAF,
    (0x3366d32, "displacement"): FIRST_LEAF,
    (0x3367100, "immediate"): SATURATE,
    (0x3367107, "condition"): SATURATE,
    (0x336710b, "condition"): SATURATE,
    (0x3366e4c, "immediate"): ROOT_WORD,
    (0x33673a0, "immediate"): ROOT_WORD,
    (0x3c97afc, "immediate"): LOCAL_VEC,
    (0x3c97b09, "immediate"): LOCAL_VEC,
}


def cases_for(target, cases):
    wanted = {FORCE: FORCE, ROLL: ROLL, QUORUM: QUORUM, LOOKUP: LOOKUP, LAST: LAST, TRACK: TRACK, ENCODE_TUPLE: FORCE}[target]
    return [case for case in cases if case.kind == wanted]


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    for target in TARGETS:
        chosen = cases_for(target, cases)
        if target == ENCODE_TUPLE:
            chosen = chosen[:4]
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            if first_failure(harness, chosen) is not None:
                results.append((va, kind, "killed", "whole run"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=600):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    check_cases(harness, vector_cases(vectors))
    calendar = calendar_rows(harness)
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, callers=caller_rows(image), constants=constant_rows(image), fields=field_rows(image), statuses=status_rows(image), calendar=calendar)
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    if outcome[0] == "panic":
        return outcome[0], outcome[1], ",".join(str(event[0]) for event in outcome[2]), ""
    if outcome[0] == "value":
        return str(outcome[1]), "", ",".join(str(event[0]) for event in outcome[2]), hashlib.sha256(outcome[3]).hexdigest()[:16]
    data = outcome[2]
    at = OUT - HEAP_BASE
    tag = struct.unpack_from("<H", data, at)[0]
    return "%#x" % tag, data[at:at + 0x20].hex(), ",".join(str(event[0]) for event in outcome[1]), hashlib.sha256(data).hexdigest()[:16]


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("callers.tsv", ("reach", "role", "target", "sites", "addresses"), result["callers"])
    tsv("constants.tsv", ("name", "address", "note"), result["constants"])
    tsv("field-names.tsv", ("struct", "key_site", "key_address", "key", "offset", "proof_address", "proof_bytes"), result["fields"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("calendar.tsv", ("date", "ordinal", "packed", "unix_seconds", "rolled_with_duration_x", "rolled_with_duration_x_plus_1"), result["calendar"])
    tsv("outcomes.tsv", ("entry", "case", "result", "out_head", "events", "state_digest"),
        [("%#x" % case.kind, case.name) + describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
        "named_by_entry": {NAMES[kind]: len(group) for kind, group in GROUPS},
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
