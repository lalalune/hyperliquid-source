#!/usr/bin/env python3
"""Rebuild the node #115 static-configuration name path and prove it against the bytes.

The static configuration reader 0x17783e0 ends in a one byte network name: a JSON document is read, trailing white space is
checked, a name is classified against 79 spellings, and a missing `aws_name` field falls back to a second file that is trimmed
and classified again. Seven functions of that path run as real bytes in a Python x86-64 evaluator: the plain classifier
0x1775500, the serde classifier 0x1774100, the Unicode trim 0x1778840, the missing-name reader 0x1773fd0, the document end check
0x1775dd0, the quoted-name reader 0x1777080 and the static reader 0x17783e0. Only the allocator, the panic entries, the file
read, the path builders, the JSON string parser, the document reader and the error constructors are contract stubs. A separately
written specification (the 79 spellings read from the file's own pointer arrays, the Unicode White_Space set, the four ASCII
white-space bytes of the end check) predicts every result, every stub call and every panic site. Code bytes, table bytes and
the specification are then perturbed to show the comparison can fail. No disassembler text is parsed and the binary is never
executed. Standard library only.
"""

import argparse
import bisect
import fractions
import hashlib
import json
import math
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

PERP, SPOT = "perp", "spot"
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
STEP_LIMIT = 300000
MUTANT_STEP_LIMIT = 8000
FAKE_MEMCMP = 0x7E000000



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

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/", "/base/", "/chrono-"):
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
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at")

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
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
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
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 0:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd", ("x", reg), rm, 8)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, width)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x13 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
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
            return finish("bt", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
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
        self.overlay = {}
        self.log = None

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
            if self.log is not None and buffer is self.heap:
                self.log.append((addr, count))
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return self.statics[addr].to_bytes(count, "little")
        try:
            offset = self.image.offset(addr)
        except EvidenceError:
            raise Halt("read outside every mapping: %#x" % addr)
        data = bytearray(self.image.blob[offset:offset + count])
        for index in range(count):
            if addr + index in self.overlay:
                data[index] = self.overlay[addr + index]
        return bytes(data)

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
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.last = 0

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
        self.keep_rdx = self.keep_float = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        kept = self.xmm[0]
        self.xmm = [POISON | POISON << 64] * 16
        if self.keep_float:
            self.xmm[0] = kept

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
            self.last = pc
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            right = self.get(row.a, 8)
            right = right - (1 << 64) if right & SIGN[8] else right
            product = (left * right) & ((1 << 128) - 1)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
        elif op == "jmp":
            return row.target
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.stub(hook)
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
        elif op == "nop":
            pass
        elif op == "div":
            divisor = self.get(row.a, width)
            if divisor == 0:
                raise Halt("division by zero at %#x" % row.va)
            dividend = (self.regs[RDX] & MASK[width]) << (8 * width) | (self.regs[RAX] & MASK[width])
            quotient, remainder = divmod(dividend, divisor)
            if quotient > MASK[width]:
                raise Halt("division overflow at %#x" % row.va)
            self.regs[RAX], self.regs[RDX] = quotient, remainder
        elif op == "jmpi":
            return self.get(row.a, 8)
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "movsx":
            value = self.get(row.b, row.cc)
            self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)
        elif op == "ud2":
            raise Panicked("ud2 at %#x" % row.va)
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
                self.xmm[row.a[1]] = self.low(row.b) if row.b[0] != "r" else self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "cmpeqsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left == right else 0)
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "divsd":
                result = left / right if right else math.copysign(math.inf, left) * math.copysign(1.0, right) if left == left and left else math.nan
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
            value = self.get(row.b, row.width)
            self.set_low(row.a[1], to_bits(float(value - (1 << (8 * row.width)) if value & SIGN[row.width] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "andnpd":
            self.xmm[row.a[1]] = (~self.xmm[row.a[1]] & ((1 << 128) - 1)) & self.vector(row.b)
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
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")




# ---- node #115 static-config name path: coordinates ----

H = HEAP_BASE
OUTBUF = H + 0x200
SCRATCH = H + 0x400
INPUT = H + 0x1000
BUFFER_GUARD = 0x40
USED = 0x6000
U64 = MASK[8]

PLAIN, SERDE, TRIM = 0x1775500, 0x1774100, 0x1778840
MISSING, ENDCHK, QUOTED, STATIC = 0x1773FD0, 0x1775DD0, 0x1777080, 0x17783E0
FUNCTIONS = (("plain_name_classifier", PLAIN), ("serde_name_classifier", SERDE), ("name_trim", TRIM),
             ("missing_name_reader", MISSING), ("document_end_check", ENDCHK), ("quoted_name_reader", QUOTED),
             ("static_reader", STATIC))
NAME_ARRAYS = (0x63F8788, 0x6410CE8)
NAME_COUNT = 79
UNKNOWN = 0x4F
DEFAULT_NAME = 0x21
JUMP_TABLES = {PLAIN: 0x481D0C, SERDE: 0x481BA0}
JUMP_SLOTS = 12
WS_SLOT = 0x64DFC30
WS_TABLE = 0x479266
MASK_WS = 0x100002600

# GOT slots the path reaches through `call *slot(%rip)`; every one is a RELATIVE relocation in the file.
SLOTS = dict(free=0x64DF4A0, unwrap=0x64DF6A0, expect=0x64DF520, format=0x64DF6E8, read=0x64E09C0, path=0x64E23E0,
             classify=0x64E2400, string=0x64E08F8, resume=0x64DF4C0)
# Direct callees that stay contract stubs: (name, address).
DIRECT = dict(error_new=0x1775EE0, document=0x17771B0, drop_io=0x1778770, unknown_variant=0x1777FD0,
              invalid_type=0x1776910, position=0x1778060)
ERROR_BASE = 0xE0000000
BOX_AT = H + 0x900
READER = H + 0x500
FILE_ID = 0x1234


def relative_map(image):
    cached = getattr(image, "relative_cache", None)
    if cached is None:
        cached = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        image.relative_cache = cached
    return cached


def read_u64(image, va):
    return struct.unpack_from("<Q", image.blob, image.offset(va))[0]


def read_names(image, base):
    relative = relative_map(image)
    names = []
    for number in range(NAME_COUNT):
        slot = base + 16 * number
        start = image.offset(relative[slot])
        names.append(bytes(image.blob[start:start + read_u64(image, slot + 8)]))
    return names


def read_jump_table(image, function):
    table = JUMP_TABLES[function]
    start = image.offset(table)
    return [table + struct.unpack_from("<i", image.blob, start + 4 * number)[0] for number in range(JUMP_SLOTS)]


# ---- the specification: written from the names and the Unicode White_Space property, not from the code ----

WHITE_SPACE = frozenset(list(range(9, 14)) + [0x20, 0x85, 0xA0, 0x1680] + list(range(0x2000, 0x200B)) +
                        [0x2028, 0x2029, 0x202F, 0x205F, 0x3000])


class Spec:
    def __init__(self, names):
        self.names = names
        self.index = {name: number for number, name in enumerate(names)}

    def classify(self, data):
        return self.index.get(bytes(data), UNKNOWN)


def spec_trim(data):
    """str::trim over valid UTF-8: (start offset, length); an all-white-space input gives (0, 0)."""
    text = data.decode("utf-8")
    first = last = None
    at = 0
    for char in text:
        size = len(char.encode("utf-8"))
        if ord(char) not in WHITE_SPACE:
            if first is None:
                first = at
            last = at + size
        at += size
    return (0, 0) if first is None else (first, last - first)


# ---- the evaluator harness ----

class Rig:
    """One machine with every GOT slot of the path bound to its RELATIVE target and the stubs below installed."""

    def __init__(self, image, patches=None, overlay=None):
        self.image = image
        self.machine = machine = Machine(image, patches)
        machine.step_limit = STEP_LIMIT if not patches and not overlay else MUTANT_STEP_LIMIT
        machine.memory.overlay = overlay or {}
        relative = relative_map(image)
        self.target = {name: relative[slot] for name, slot in SLOTS.items()}
        for slot in list(SLOTS.values()) + [WS_SLOT]:
            machine.memory.statics[slot] = relative[slot]
        if self.target["classify"] != PLAIN:
            raise EvidenceError("classify slot does not point at the plain classifier")
        if relative[WS_SLOT] != WS_TABLE:
            raise EvidenceError("white-space table slot moved")
        machine.real = frozenset((PLAIN, SERDE, TRIM, MISSING, ENDCHK, QUOTED, STATIC))
        hooks = dict(free=self.on_free, unwrap=self.on_unwrap, expect=self.on_unwrap, format=self.on_format, read=self.on_read,
                     path=self.on_path, string=self.on_string, resume=self.on_unwrap)
        machine.slots = {self.target[name]: hook for name, hook in hooks.items() if name != "classify"}
        machine.calls = {DIRECT["error_new"]: self.on_error_new, DIRECT["document"]: self.on_document,
                         DIRECT["drop_io"]: self.on_drop_io, DIRECT["unknown_variant"]: self.on_unknown_variant,
                         DIRECT["invalid_type"]: self.on_invalid_type, DIRECT["position"]: self.on_position}
        self.events = []
        self.script = {}

    # -- memory --
    def load(self, data, at=INPUT):
        memory = self.machine.memory
        memory.reset(USED)
        self.events = []
        memory.put_bytes(at - BUFFER_GUARD, bytes([0xC3]) * BUFFER_GUARD)
        memory.put_bytes(at + len(data), bytes([0x3C]) * BUFFER_GUARD)
        memory.put_bytes(at, data)
        memory.log = []

    def reads_inside(self, low, high):
        """True when every logged heap read lies inside [low, high)."""
        return all(low <= addr and addr + count <= high for addr, count in self.machine.memory.log
                   if addr >= INPUT - BUFFER_GUARD)

    def guards_intact(self, data, at=INPUT):
        memory = self.machine.memory
        return (memory.bytes_at(at - BUFFER_GUARD, BUFFER_GUARD) == bytes([0xC3]) * BUFFER_GUARD and
                memory.bytes_at(at + len(data), BUFFER_GUARD) == bytes([0x3C]) * BUFFER_GUARD and
                memory.bytes_at(at, len(data)) == data)

    def call(self, entry, args):
        try:
            return ("ret", self.machine.run(entry, args))
        except Panicked as stop:
            return ("panic", stop.args[0])

    # -- contract stubs: each records its arguments and returns what the caller consumes --
    def on_free(self, machine):
        self.events.append(("free", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_unwrap(self, machine):
        raise Panicked(("panic", machine.regs[RCX], machine.regs[R8]))

    def on_unknown_variant(self, machine):
        regs = machine.regs
        self.events.append(("unknown_variant", regs[RDI], regs[RSI], regs[RDX], regs[RCX]))
        regs[RAX] = ERROR_BASE + regs[RSI]

    def on_invalid_type(self, machine):
        self.events.append(("invalid_type", machine.regs[RDX]))
        machine.regs[RAX] = ERROR_BASE + 0x100

    def on_position(self, machine):
        self.events.append(("position", machine.regs[RDI]))
        machine.regs[RAX] = machine.regs[RDI] + 0x1000

    def on_error_new(self, machine):
        memory = machine.memory
        code = memory.read(machine.regs[RSI], 8)
        self.events.append(("error_new", code))
        memory.write(BOX_AT, 8, self.script.get("kind", 2))
        memory.write(BOX_AT + 8, 8, 0)
        memory.write(BOX_AT + 0x10, 8, 0)
        memory.write(BOX_AT + 0x18, 8, code)
        machine.regs[RAX] = BOX_AT

    def on_drop_io(self, machine):
        self.events.append(("drop_io", machine.regs[RDI]))

    def on_path(self, machine):
        cap, ptr, size = self.script["path"]
        memory = machine.memory
        out = machine.regs[RDI]
        self.events.append(("path",))
        memory.write(out, 8, cap)
        memory.write(out + 8, 8, ptr)
        memory.write(out + 16, 8, size)

    def on_format(self, machine):
        cap, ptr, size = self.script["format"]
        memory = machine.memory
        out = machine.regs[RDI]
        self.events.append(("format", machine.regs[RSI]))
        memory.write(out, 8, cap)
        memory.write(out + 8, 8, ptr)
        memory.write(out + 16, 8, size)

    def on_read(self, machine):
        word, ptr, size = self.script["read"]
        memory = machine.memory
        out = machine.regs[RDI]
        self.events.append(("read", machine.regs[RSI], machine.regs[RDX]))
        memory.write(out, 8, word)
        memory.write(out + 8, 8, ptr)
        memory.write(out + 16, 8, size)

    def on_string(self, machine):
        tag, ptr, size, moved = self.script["string"]
        memory = machine.memory
        out = machine.regs[RDI]
        self.events.append(("string", machine.regs[RDX]))
        memory.write(out, 4, tag)
        memory.write(out + 8, 8, ptr)
        memory.write(out + 16, 8, size)
        if moved is not None:
            memory.write(machine.regs[RDX] + 0x28, 8, moved)

    def on_document(self, machine):
        tag, value, moved, box, scratch = self.script["document"]
        memory = machine.memory
        out = machine.regs[RDI]
        reader = machine.regs[RSI]
        self.events.append(("document",))
        memory.write(out, 1, tag)
        if tag == 0:
            memory.write(out + 1, 1, value)
        else:
            memory.write(out + 8, 8, box)
        if moved is not None:
            memory.write(reader + 0x28, 8, moved)
        if scratch is not None:
            memory.write(reader, 8, scratch[0])
            memory.write(reader + 8, 8, scratch[1])


# ---- plain and serde classifiers, trim: observation and specification ----

def watch(rig, data, entry, args):
    rig.load(data)
    outcome = rig.call(entry, args)
    inside = rig.reads_inside(INPUT, INPUT + len(data)) and rig.guards_intact(data)
    return outcome, inside


def real_plain(rig, data):
    outcome, inside = watch(rig, data, PLAIN, {RDI: INPUT, RSI: len(data)})
    return outcome[0], outcome[1] & 0xFF, inside


def real_serde(rig, data):
    memory = rig.machine.memory
    outcome, inside = watch(rig, data, SERDE, {RDI: OUTBUF, RSI: INPUT, RDX: len(data)})
    tag = memory.read(OUTBUF, 1)
    word = memory.read(OUTBUF + 1, 1) if tag == 0 else memory.read(OUTBUF + 8, 8)
    return outcome[0], tag, word, tuple(rig.events), inside


def real_trim(rig, data):
    outcome, inside = watch(rig, data, TRIM, {RDI: INPUT, RSI: len(data)})
    regs = rig.machine.regs
    return outcome[0], (regs[RAX] - INPUT) & U64, regs[RDX], inside


def spec_plain(spec, data):
    return "ret", spec.classify(data), True


def spec_serde(spec, data):
    index = spec.classify(data)
    if index == UNKNOWN:
        return "ret", 1, ERROR_BASE + len(data), (("unknown_variant", INPUT, len(data), NAME_ARRAYS[1], NAME_COUNT),), True
    return "ret", 0, index, (), True


def spec_trim_row(data):
    start, size = spec_trim(data)
    return "ret", start, size, True


# ---- the four flows: observation (real bytes + stubs) and specification ----

PATH_AT = H + 0x3000
SENTINEL = 1 << 63
PANIC_READ = ("panic", 0x6411298, 0x64111D8)
PANIC_NAME = ("panic", 0x6411278, 0x64111F0)
FORMAT_ENTRY = 0x4401EF
STRING_TYPE = 0x6411390
SCRUB = 0x77


def box_kind(rig, box):
    memory = rig.machine.memory
    return memory.read(box, 8), memory.read(box + 8, 8), memory.read(box + 0x10, 8)


def lay_error(rig, kind, first, second):
    """A 0x28 byte error box the caller inspects: kind word, then two words."""
    memory = rig.machine.memory
    memory.write(BOX_AT + 0x100, 8, kind)
    memory.write(BOX_AT + 0x108, 8, first)
    memory.write(BOX_AT + 0x110, 8, second)
    return BOX_AT + 0x100


# -- missing-name reader 0x1773fd0: path -> read -> trim -> classify -> free --

def real_missing(rig, case):
    path_cap, word, content, file_cap = case
    rig.load(content)
    rig.script = dict(path=(path_cap, PATH_AT, 9), read=(word if word == SENTINEL else file_cap, INPUT, len(content)))
    outcome = rig.call(MISSING, {})
    inside = rig.reads_inside(INPUT, INPUT + len(content)) and rig.guards_intact(content)
    value = outcome[1] & 0xFF if outcome[0] == "ret" else outcome[1]
    return outcome[0], value, tuple(rig.events), inside


def spec_missing(spec, case):
    path_cap, word, content, file_cap = case
    events = [("path",), ("read", PATH_AT, 9)]
    if path_cap:
        events.append(("free", PATH_AT, path_cap, 0))
    if word == SENTINEL:
        return "panic", PANIC_READ, tuple(events), True
    start, size = spec_trim(content)
    index = spec.classify(content[start:start + size])
    if index == UNKNOWN:
        return "panic", PANIC_NAME, tuple(events), True
    if file_cap:
        events.append(("free", INPUT, file_cap, 0))
    return "ret", index, tuple(events), True


# -- document end check 0x1775dd0: document reader, then only white space may follow --

def real_endcheck(rig, case):
    content, position, document = case
    rig.load(content)
    memory = rig.machine.memory
    for number, value in enumerate((INPUT, len(content), position, 0, INPUT, len(content))):
        memory.write(READER + 8 * number, 8, value)
    rig.script = dict(document=document)
    outcome = rig.call(ENDCHK, {RDI: OUTBUF, RSI: READER})
    tag = memory.read(OUTBUF, 1)
    word = memory.read(OUTBUF + 1, 1) if tag == 0 else memory.read(OUTBUF + 8, 8)
    inside = rig.reads_inside(INPUT, INPUT + len(content)) and rig.guards_intact(content)
    return outcome[0], tag, word, tuple(rig.events), inside


def spec_endcheck(case):
    content, position, document = case
    tag, value, moved, box, scratch = document
    events = [("document",)]
    if tag != 0:
        result = (tag, box)
    else:
        at = position if moved is None else moved
        result = (0, value)
        while at < len(content):
            byte = content[at]
            if byte > 0x20 or not MASK_WS >> byte & 1:
                events.append(("error_new", 0x16))
                result = (1, BOX_AT)
                break
            at += 1
    if scratch is not None and scratch[0]:
        events.append(("free", scratch[1], scratch[0], 0))
    return ("ret",) + result + (tuple(events), True)


# -- quoted name reader 0x1777080: skip white space, expect '"', parse the string, classify it --

def real_quoted(rig, case):
    text, position, string = case
    rig.load(text)
    memory = rig.machine.memory
    for number, value in enumerate((0, 0, SCRUB, INPUT, len(text), position)):
        memory.write(READER + 8 * number, 8, value)
    rig.script = dict(string=string)
    outcome = rig.call(QUOTED, {RDI: OUTBUF, RSI: READER})
    tag = memory.read(OUTBUF, 1)
    word = memory.read(OUTBUF + 8, 8)
    final = memory.read(READER + 0x28, 8)
    scrub = memory.read(READER + 0x10, 8)
    inside = rig.reads_inside(INPUT, INPUT + len(text)) and rig.guards_intact(text)
    return outcome[0], tag, word, final, scrub, tuple(rig.events), inside


def spec_quoted(spec, case):
    text, position, string = case
    tag, ptr, size, moved = string
    events = []
    at = position
    scrub = SCRUB
    while True:
        if at >= len(text):
            events.append(("error_new", 5))
            return "ret", UNKNOWN, BOX_AT, at, scrub, tuple(events), True
        byte = text[at]
        at += 1
        if byte <= 0x20 and MASK_WS >> byte & 1:
            continue
        break
    if byte != 0x22:
        events.append(("invalid_type", STRING_TYPE))
        events.append(("position", ERROR_BASE + 0x100))
        return "ret", UNKNOWN, ERROR_BASE + 0x100 + 0x1000, at - 1, scrub, tuple(events), True
    events.append(("string", READER))
    if moved is not None:
        at = moved
    if tag == 2:
        return "ret", UNKNOWN, ptr, at, 0, tuple(events), True
    name = text[ptr - INPUT:ptr - INPUT + size]
    index = spec.classify(name)
    if index == UNKNOWN:
        events.append(("unknown_variant", ptr, size, NAME_ARRAYS[1], NAME_COUNT))
        events.append(("position", ERROR_BASE + size))
        return "ret", UNKNOWN, ERROR_BASE + size + 0x1000, at, 0, tuple(events), True
    return "ret", index, READER, at, 0, tuple(events), True


# -- static reader 0x17783e0: format path, read file, document + end check, name or the default 33 --

def real_static(rig, case):
    content, path_cap, read, document, box_spec = case
    rig.load(content)
    box = lay_error(rig, *box_spec) if box_spec else 0
    word, error_repr = read
    rig.script = dict(format=(path_cap, PATH_AT, 15), read=(word, INPUT if word != SENTINEL else error_repr, len(content)),
                      document=document[:3] + (box if document[0] and box else document[3], document[4]))
    outcome = rig.call(STATIC, {RDI: 0x71, RSI: 0x72})
    inside = rig.reads_inside(INPUT, INPUT + len(content)) and rig.guards_intact(content)
    value = outcome[1] & 0xFF if outcome[0] == "ret" else outcome[1]
    return outcome[0], value, tuple(rig.events), inside


def spec_static(case):
    content, path_cap, read, document, box_spec = case
    word, error_repr = read
    tag, value, moved, box, scratch = document
    events = [("format", FORMAT_ENTRY), ("read", PATH_AT, 15)]
    if word == SENTINEL:
        events.append(("drop_io", error_repr))
        if path_cap:
            events.append(("free", PATH_AT, path_cap, 0))
        return "ret", DEFAULT_NAME, tuple(events), True
    end = spec_endcheck((content, 0, (tag, value, moved, BOX_AT + 0x100 if tag and box_spec else box, scratch)))
    events.extend(end[3])
    result = DEFAULT_NAME
    if end[1] == 0:
        result = end[2]
    else:
        box_at = end[2]
        kind, first, second = box_spec if box_at == BOX_AT + 0x100 else (2, 0, 0)
        if kind == 1:
            events.append(("drop_io", first))
        elif kind == 0 and second:
            events.append(("free", first, second, 0))
        events.append(("free", box_at, 0x28, 0))
    if word:
        events.append(("free", INPUT, word, 0))
    if path_cap:
        events.append(("free", PATH_AT, path_cap, 0))
    return "ret", result, tuple(events), True


# ---- case generation (deterministic; no clocks, no hash order) ----

class Lcg:
    def __init__(self, seed):
        self.state = seed & U64

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & U64
        return self.state >> 33

    def below(self, count):
        return self.next() % count


PAD = (b"", b" ", b"\n", b"\t\r", " ".encode(), "　".encode(), " ".encode(), "\u0085".encode(), b" \n ",
       " ".encode(), b"\x0b", b"\x0c", "  ".encode())
CHAR_POOL = ("a", "Z", "0", " ", "\t", "\n", "\x0b", "\x1f", "\x7f", "\x80", "\x84", "\u0085", " ", "¡", "ᙿ", " ",
             "ᚁ", "᠎", "῿", " ", " ", "​", "‧", " ", " ", "‪", " ", "‰",
             "⁞", " ", "⁠", "⿿", "　", "、", "﻿", "\U00010000", "\U0001f600", "\U0010ffff", "é")


def name_inputs(names, random_count):
    rng = Lcg(0x115)
    for name in names:
        yield "exact", name
    for name in names:
        for at in range(len(name)):
            for label, flip in (("bit0", 1), ("case", 0x20), ("high", 0x80)):
                yield label, name[:at] + bytes([name[at] ^ flip]) + name[at + 1:]
        yield "short", name[:-1]
        yield "nul", name + b"\0"
        yield "extra", name + b"x"
        yield "lead", b"x" + name
        for at in range(len(name) - 1):
            swapped = bytearray(name)
            swapped[at], swapped[at + 1] = swapped[at + 1], swapped[at]
            if bytes(swapped) != name:
                yield "swap", bytes(swapped)
    for _ in range(random_count):
        first, second = names[rng.below(len(names))], names[rng.below(len(names))]
        cut = rng.below(min(len(first), len(second)) + 1)
        yield "splice", first[:cut] + second[cut:]
    for length in range(41):
        for fill in (0, 0xFF, 0x61, 0x41):
            yield "fill", bytes([fill]) * length
    for _ in range(random_count):
        yield "random", bytes(rng.below(256) for _ in range(rng.below(17)))


def trim_inputs(random_count):
    rng = Lcg(0x8840)
    for point in list(range(0x3101)) + list(range(0x3101, 0x110000, 509)) + [0xD7FF, 0xE000, 0xFEFF, 0xFFFF, 0x10000, 0x10FFFF]:
        if 0xD800 <= point <= 0xDFFF:
            continue
        char = chr(point).encode()
        yield "single", char
        yield "trail", b"a" + char
    for _ in range(random_count):
        yield "mixed", "".join(CHAR_POOL[rng.below(len(CHAR_POOL))] for _ in range(rng.below(11))).encode()


def missing_inputs(names, count):
    rng = Lcg(0x3FD0)
    cases = []
    for name in names:
        for variant in range(3):
            pad = lambda: PAD[rng.below(len(PAD))]
            cases.append(((0, 24, 0)[variant], 0, pad() + name + pad(), (0, 32, 7)[variant]))
    unknown = (b"", b" ", b"\xc2\xa0", b"nvtestnet", b"NvTestnet2x", b"Nv Testnet", b"\xe2\x80\x8bEc",
               b"NvTestnet\0", b"\x1fEc", b"EC", b"Ec Ec", b"\n\n", b"\xf0\x9f\x98\x80")
    for content in unknown:
        for path_cap, file_cap in ((0, 0), (24, 16)):
            cases.append((path_cap, 0, content, file_cap))
    for path_cap in (0, 8, 24):
        cases.append((path_cap, SENTINEL, b"", 0))
        cases.append((path_cap, SENTINEL, b"Ec", 0))
    for _ in range(count):
        name = names[rng.below(len(names))]
        cases.append((rng.below(3) * 8, 0, PAD[rng.below(len(PAD))] + name + PAD[rng.below(len(PAD))], rng.below(3) * 16))
    return cases


def endcheck_inputs(count):
    rng = Lcg(0x5DD0)
    ok = (0, 33, None, 0, None)
    cases = []
    for byte in range(256):
        cases.append((b"x" + bytes([byte]), 1, ok))
        cases.append((bytes([byte]), 0, (0, byte, 1 if byte & 1 else None, 0, None)))
    cases.append((b" \n\t\r  ", 0, ok))
    cases.append((b"", 0, ok))
    cases.append((b"abc", 7, ok))
    for number in range(1, 13):
        cases.append((b"{}", 0, (1, 0, None, 0x3000 + number, (8 * (number % 2), 0x900 + number) if number % 3 else None)))
    pool = (9, 10, 13, 32, 11, 12, 0x21, 0x61, 0x80, 0xA0)
    for _ in range(count):
        content = bytes(pool[rng.below(len(pool))] for _ in range(rng.below(9)))
        moved = None if rng.below(3) == 0 else rng.below(len(content) + 2)
        scratch = None if rng.below(2) == 0 else (8 * rng.below(3), 0xA00 + rng.below(16))
        cases.append((content, rng.below(len(content) + 2), (0, rng.below(80), moved, 0, scratch)))
    return cases


def quoted_inputs(names, count):
    rng = Lcg(0x7080)
    cases = []
    for name in names:
        for lead in (b"", b" ", b"\n\t \r"):
            text = lead + b'"' + name + b'" ,'
            start = INPUT + len(lead) + 1
            cases.append((text, 0, (0, start, len(name), len(lead) + len(name) + 2)))
    for label, data in name_inputs(names, 0):
        if label in ("bit0", "case", "short") and rng.below(40) == 0:
            cases.append((b'"' + data + b'"', 0, (rng.below(2), INPUT + 1, len(data), len(data) + 2)))
    for byte in range(256):
        cases.append((bytes([byte]) + b'"Ec"', 0, (0, INPUT + 2, 2, 5)))
    for text, position in ((b"", 0), (b"   ", 0), (b"abc", 5), (b"   ", 1), (b"\n", 1)):
        cases.append((text, position, (0, 0, 0, None)))
    cases.append((b'"ab', 0, (2, 0x4242, 0, None)))
    cases.append((b' "ab', 0, (2, 0x4343, 0, 9)))
    for _ in range(count):
        name = names[rng.below(len(names))]
        lead = PAD[rng.below(len(PAD))]
        cut = rng.below(len(name) + 1)
        text = lead + b'"' + name + b'"'
        cases.append((text, rng.below(len(lead) + 1), (rng.below(3) // 2 * 2, INPUT + len(lead) + 1, cut, len(text))))
    return cases


def static_inputs(names, count):
    rng = Lcg(0x83E0)
    contents = (b"{}", b"{}  \n", b"{} x", b"{}\xc2\xa0", b"{}\x0b", b"{}\r\n\t ", b"")
    cases = []
    for content in contents:
        for value in (0, 1, 33, 78, 79, 255):
            for path_cap in (0, 24):
                for file_cap in (0, 64):
                    cases.append((content, path_cap, (file_cap, 0), (0, value, len(content) if content[-1:] != b"x" else 2, 0, None), None))
    for number in range(len(names)):
        cases.append((b"{} \n", 0, (16, 0), (0, number, 2, 0, None), None))
    for error_repr in (0x31, 0x4141):
        for path_cap in (0, 24):
            cases.append((b"{}", path_cap, (SENTINEL, error_repr), (0, 0, 0, 0, None), None))
    for kind, first, second in ((0, 0x2222, 0x20), (0, 0x2222, 0), (1, 0x3333, 0), (2, 0, 0), (3, 7, 9)):
        for scratch in (None, (24, 0x99)):
            for path_cap in (0, 8):
                cases.append((b"{}", path_cap, (0, 0), (1, 0, None, 0, scratch), (kind, first, second)))
    for _ in range(count):
        content = contents[rng.below(len(contents))]
        if rng.below(4) == 0:
            document = (1, 0, None, 0, None if rng.below(2) else (8, 0x77))
            cases.append((content, rng.below(2) * 8, (rng.below(2) * 8, 0), document, (rng.below(4), 0x5000 + rng.below(8), rng.below(2) * 16)))
        else:
            document = (0, rng.below(256), None if rng.below(2) else rng.below(len(content) + 2), 0, None)
            cases.append((content, rng.below(2) * 8, (rng.below(2) * 8, 0), document, None))
    return cases


# ---- the families: runner, specification, outcome label ----

def label_name(observed, case):
    return "unknown" if observed[1] == UNKNOWN else "name"


def label_serde(observed, case):
    return "unknown variant error" if observed[1] == 1 else "name"


def label_trim(observed, case):
    return "empty" if observed[2] == 0 else "trimmed" if observed[2] != len(case) else "unchanged"


def label_missing(observed, case):
    return {PANIC_READ: "panic read error", PANIC_NAME: "panic unknown name"}.get(observed[1], "name" if observed[0] == "ret" else "?")


def label_endcheck(observed, case):
    events = [event[0] for event in observed[3]]
    if observed[1] == 0:
        return "ok"
    return "trailing characters" if "error_new" in events else "reader error"


def label_quoted(observed, case):
    if observed[1] != UNKNOWN:
        return "name"
    events = [event[0] for event in observed[5]]
    return "end of input" if events == ["error_new"] else "not a string" if "invalid_type" in events else \
        "unknown variant" if "unknown_variant" in events else "string error"


def label_static(observed, case):
    events = observed[2]
    names = [event[0] for event in events]
    if "document" not in names:
        return "read error"
    if "error_new" in names:
        return "trailing characters"
    if any(event[0] == "free" and event[2] == 0x28 for event in events):
        return "document error"
    return "document value"


def families(spec, names, scale):
    count = max(8, 1000 // scale)
    return (
        ("plain", PLAIN, lambda: (data for _, data in name_inputs(names, count)), real_plain, lambda c: spec_plain(spec, c), label_name),
        ("serde", SERDE, lambda: (data for _, data in name_inputs(names, count)), real_serde, lambda c: spec_serde(spec, c), label_serde),
        ("trim", TRIM, lambda: (data for _, data in trim_inputs(3000 // scale)), real_trim, spec_trim_row, label_trim),
        ("missing", MISSING, lambda: iter(missing_inputs(names, 300 // scale)), real_missing, lambda c: spec_missing(spec, c), label_missing),
        ("endcheck", ENDCHK, lambda: iter(endcheck_inputs(300 // scale)), real_endcheck, spec_endcheck, label_endcheck),
        ("quoted", QUOTED, lambda: iter(quoted_inputs(names, 300 // scale)), real_quoted, lambda c: spec_quoted(spec, c), label_quoted),
        ("static", STATIC, lambda: iter(static_inputs(names, 300 // scale)), real_static, spec_static, label_static),
    )


def show_input(case):
    if isinstance(case, bytes):
        return case[:20].hex() + ("+%d" % (len(case) - 20) if len(case) > 20 else "")
    return repr(case)[:90]


def analyse(image, spec, names, scale, rows_every):
    rig = Rig(image)
    counts, outcomes, rows, bad = {}, {}, [], []
    for key, function, make, runner, predict, labeller in families(spec, names, scale):
        total = 0
        for number, case in enumerate(make()):
            observed = runner(rig, case)
            expected = predict(case)
            total += 1
            if observed != expected:
                bad.append((key, show_input(case), observed, expected))
                continue
            label = labeller(observed, case)
            outcomes[(key, label)] = outcomes.get((key, label), 0) + 1
            if number % rows_every[key] == 0:
                rows.append((key, number, label, show_input(case), str(observed[1])[:24]))
        counts[key] = total
    return rig, counts, outcomes, rows, bad


# ---- negative controls: byte mutants, wrong specifications, corrupted inputs ----

def rows_of(image, function):
    start, end = image.exact_fde(function)
    return decode_range(image, start, end)


def jcc_flip(image, row):
    first = image.blob[image.offset(row.va)]
    at = row.va if 0x70 <= first <= 0x7F else row.va + 1
    return {at: image.blob[image.offset(at)] ^ 1}


def imm_flip(image, row, which=0, mask=0x01):
    at = row.va + row.imm_at + which
    return {at: image.blob[image.offset(at)] ^ mask}


def spread(rows, count):
    """`count` rows spread over the list, first and last included."""
    if len(rows) <= count:
        return list(rows)
    return [rows[number * (len(rows) - 1) // (count - 1)] for number in range(count)]


def build_mutants(image, stride):
    """(function key, description, code patches, data overlay): each is expected to change an observable result."""
    out = []
    plain = rows_of(image, PLAIN)
    returns = [row for row in plain if row.op == "mov" and row.a == ("r", RAX) and row.b[0] == "i" and row.width == 1]
    for row in returns[::stride]:
        out.append(("plain", "plain return immediate %#x at %#x ^1" % (row.b[1], row.va), imm_flip(image, row), {}))
    xors = [row for row in plain if row.op == "xor" and row.b and row.b[0] == "i" and row.imm_size]
    for row in spread(xors, 6):
        out.append(("plain", "plain xor immediate at %#x ^1" % row.va, imm_flip(image, row), {}))
    jccs = [row for row in plain if row.op == "jcc"]
    for row in spread(jccs, 5):
        out.append(("plain", "plain conditional at %#x inverted" % row.va, jcc_flip(image, row), {}))
    for slot in (0, 5, 11):
        at = JUMP_TABLES[PLAIN] + 4 * slot
        out.append(("plain", "plain jump table slot %d low byte ^4" % slot, {}, {at: image.blob[image.offset(at)] ^ 4}))

    serde = rows_of(image, SERDE)
    stores = [row for row in serde if row.op == "mov" and row.a and row.a[0] == "m" and row.b and row.b[0] == "i" and row.width == 1]
    for row in stores[::stride * 2]:
        out.append(("serde", "serde result byte %#x at %#x ^1" % (row.b[1], row.va), imm_flip(image, row), {}))
    for row in spread([row for row in serde if row.op == "xor" and row.b and row.b[0] == "i"], 3):
        out.append(("serde", "serde xor immediate at %#x ^1" % row.va, imm_flip(image, row), {}))
    for row in spread([row for row in serde if row.op == "jcc"], 3):
        out.append(("serde", "serde conditional at %#x inverted" % row.va, jcc_flip(image, row), {}))
    count = [row for row in serde if row.op == "mov" and row.a == ("r", RCX) and row.b[0] == "i" and row.b[1] == UNKNOWN][0]
    out.append(("serde", "serde error table count immediate at %#x ^1" % count.va, imm_flip(image, count), {}))
    for slot in (1, 7):
        at = JUMP_TABLES[SERDE] + 4 * slot
        out.append(("serde", "serde jump table slot %d low byte ^4" % slot, {}, {at: image.blob[image.offset(at)] ^ 4}))

    trim = rows_of(image, TRIM)
    for row in spread([row for row in trim if row.op == "jcc"], 12):
        out.append(("trim", "trim conditional at %#x inverted" % row.va, jcc_flip(image, row), {}))
    for row in [row for row in trim if row.op == "cmp" and row.b and row.b[0] == "i" and row.b[1] in (0x1680, 0x3000, 0x20, 0x5)]:
        out.append(("trim", "trim compare %#x at %#x ^1" % (row.b[1], row.va), imm_flip(image, row), {}))
    for index in (0x85, 0xA0, 0x28, 0x5F, 0x00):
        out.append(("trim", "white-space table entry %#x flipped" % index, {}, {WS_TABLE + index: image.blob[image.offset(WS_TABLE + index)] ^ 3}))

    for key, function, count in (("missing", MISSING, 6), ("endcheck", ENDCHK, 4), ("quoted", QUOTED, 6), ("static", STATIC, 5)):
        rows = rows_of(image, function)
        for row in spread([row for row in rows if row.op == "jcc"], count):
            out.append((key, "%s conditional at %#x inverted" % (key, row.va), jcc_flip(image, row), {}))
    for key, function in (("missing", MISSING), ("quoted", QUOTED), ("static", STATIC)):
        for row in rows_of(image, function):
            if row.op == "cmp" and row.b and row.b[0] == "i" and row.b[1] in (UNKNOWN, 0x22):
                out.append((key, "%s compare %#x at %#x ^1" % (key, row.b[1], row.va), imm_flip(image, row), {}))
            if row.op == "mov" and row.a == ("r", RBP) and row.b and row.b[0] == "i" and row.b[1] == DEFAULT_NAME:
                out.append((key, "%s default %#x at %#x ^1" % (key, row.b[1], row.va), imm_flip(image, row), {}))
    for key, function in (("endcheck", ENDCHK), ("quoted", QUOTED)):
        for row in rows_of(image, function):
            if row.op == "mov" and row.b and row.b[0] == "i" and row.b[1] == MASK_WS:
                for which in (1, 4):
                    out.append((key, "%s white-space mask byte %d at %#x ^1" % (key, which, row.va), imm_flip(image, row, which), {}))
    return out


def owner_instruction(image, cache, patches):
    """Start of the instruction that holds the lowest patched byte."""
    address = min(patches)
    start, _ = image.fde(address)
    if start not in cache:
        cache[start] = rows_of(image, start)
    return [row.va for row in cache[start] if row.va <= address < row.next][0]


def detect(image, spec, names, key, patches, overlay, scale):
    """Run the family's cases on a patched machine; the first disagreement (or a halt) is the detection."""
    family = [f for f in families(spec, names, scale) if f[0] == key][0]
    rig = Rig(image, patches, overlay)
    try:
        for number, case in enumerate(family[2]()):
            if family[3](rig, case) != family[4](case):
                return "detected", "case %d" % number
    except (Halt, EvidenceError, Panicked, IndexError, ValueError, KeyError, struct.error, OverflowError) as stop:
        return "detected", "halt: %s" % str(stop)[:40]
    return "survived", "all cases agree"


class Altered:
    """Temporarily replace module-level specification inputs; used to prove wrong models disagree with the bytes."""

    def __init__(self, **changes):
        self.changes = changes

    def __enter__(self):
        module = globals()
        self.saved = {name: module[name] for name in self.changes}
        module.update(self.changes)

    def __exit__(self, *exc):
        globals().update(self.saved)


def lower_classify(self, data):
    folded = {name.lower(): number for number, name in enumerate(self.names)}
    return folded.get(bytes(data).lower(), UNKNOWN)


def prefix_classify(self, data):
    for number, name in enumerate(self.names):
        if bytes(data).startswith(name):
            return number
    return UNKNOWN


def length_classify(self, data):
    for number, name in enumerate(self.names):
        if len(name) == len(data):
            return number
    return UNKNOWN


def short_classify(self, data):
    data = bytes(data)
    for number, name in enumerate(self.names):
        if len(name) == len(data) and name[:-1] == data[:-1]:
            return number
    return UNKNOWN


def variants(image, spec, names, scale):
    base = WHITE_SPACE
    ascii_only = frozenset(range(9, 14)) | {0x20}
    table = (
        ("trim set without U+0085", dict(WHITE_SPACE=base - {0x85}), "trim"),
        ("trim set without U+00A0", dict(WHITE_SPACE=base - {0xA0}), "trim"),
        ("trim set without U+1680", dict(WHITE_SPACE=base - {0x1680}), "trim"),
        ("trim set without U+2028", dict(WHITE_SPACE=base - {0x2028}), "trim"),
        ("trim set without U+202F", dict(WHITE_SPACE=base - {0x202F}), "trim"),
        ("trim set without U+3000", dict(WHITE_SPACE=base - {0x3000}), "trim"),
        ("trim set plus U+180E", dict(WHITE_SPACE=base | {0x180E}), "trim"),
        ("trim set plus U+200B", dict(WHITE_SPACE=base | {0x200B}), "trim"),
        ("trim set plus 0x1c..0x1f (Python str.strip)", dict(WHITE_SPACE=base | {0x1C, 0x1D, 0x1E, 0x1F}), "trim"),
        ("trim set ASCII only", dict(WHITE_SPACE=ascii_only), "trim"),
        ("end check mask plus 0x0b", dict(MASK_WS=MASK_WS | 1 << 0x0B), "endcheck"),
        ("end check mask without 0x20", dict(MASK_WS=MASK_WS & ~(1 << 0x20)), "endcheck"),
        ("end check mask without 0x09", dict(MASK_WS=MASK_WS & ~(1 << 9)), "endcheck"),
        ("end check mask without 0x0d", dict(MASK_WS=MASK_WS & ~(1 << 13)), "endcheck"),
        ("quoted reader skips 0x0b too", dict(MASK_WS=MASK_WS | 1 << 0x0B), "quoted"),
        ("classifier ignores case", dict(), "plain"),
        ("classifier matches prefixes", dict(), "plain"),
        ("classifier matches length only", dict(), "plain"),
        ("classifier ignores the last byte", dict(), "serde"),
        ("unknown marker 78 instead of 79", dict(UNKNOWN=78), "plain"),
        ("serde error table count 78", dict(NAME_COUNT=78), "serde"),
        ("static default 32 instead of 33", dict(DEFAULT_NAME=32), "static"),
        ("static entry at the text address 0x4401f1", dict(FORMAT_ENTRY=0x4401F1), "static"),
        ("missing-name panic sites swapped", dict(PANIC_READ=PANIC_NAME, PANIC_NAME=PANIC_READ), "missing"),
    )
    methods = {"classifier ignores case": lower_classify, "classifier matches prefixes": prefix_classify,
               "classifier matches length only": length_classify, "classifier ignores the last byte": short_classify}
    rows = []
    for label, changes, key in table:
        saved = Spec.classify
        if label in methods:
            Spec.classify = methods[label]
        try:
            with Altered(**changes):
                family = [f for f in families(spec, names, scale) if f[0] == key][0]
                rig = Rig(image)
                first, disagreeing, tried = None, 0, 0
                for number, case in enumerate(family[2]()):
                    tried += 1
                    if family[3](rig, case) != family[4](case):
                        disagreeing += 1
                        first = number if first is None else first
        finally:
            Spec.classify = saved
        rows.append((label, key, "-" if first is None else first, disagreeing, tried))
    return rows


def check_digest(blob):
    if hashlib.sha256(blob).hexdigest() != SHA256:
        raise EvidenceError("binary SHA-256 mismatch")


def check_whitespace_table(table):
    for index in range(256):
        value = table[index]
        if index >= 0x80 and bool(value & 1) != (index in WHITE_SPACE):
            raise EvidenceError("table bit 0 disagrees at %#x" % index)
        if bool(value & 2) != (0x2000 + index in WHITE_SPACE):
            raise EvidenceError("table bit 1 disagrees at %#x" % index)


def check_name_arrays(first, second):
    if first != second:
        raise EvidenceError("the two name arrays disagree")


def raises(function, *args):
    try:
        function(*args)
    except (EvidenceError, Halt, KeyError, IndexError):
        return True
    return False


def corrupt_controls(image, spec, names):
    controls = []
    damaged = bytearray(image.blob)
    damaged[100] ^= 1
    controls.append(("one flipped byte changes the binary digest", raises(check_digest, damaged)))
    del damaged
    second = read_names(image, NAME_ARRAYS[1])
    second[40] = second[40][:-1] + bytes([second[40][-1] ^ 1])
    controls.append(("a name array differing in one byte is refused", raises(check_name_arrays, names, second)))
    table = bytearray(image.blob[image.offset(WS_TABLE):image.offset(WS_TABLE) + 256])
    check_whitespace_table(table)
    for index, label in ((0x85, "bit 0 of U+0085"), (0x28, "bit 1 of U+2028"), (0x00, "bit 1 of U+2000")):
        broken = bytearray(table)
        broken[index] ^= 3
        controls.append(("white-space table with %s flipped is refused" % label, raises(check_whitespace_table, broken)))
    relative = relative_map(image)
    for slot, label in ((SLOTS["classify"], "classify slot retargeted"), (WS_SLOT, "white-space table slot retargeted")):
        image.relative_cache = dict(relative)
        image.relative_cache[slot] += 1
        try:
            controls.append((label, raises(Rig, image)))
        finally:
            image.relative_cache = relative
    controls.append(("entry inside a function is not an FDE start", raises(image.exact_fde, PLAIN + 1)))
    controls.append(("an address in .bss has no file bytes", raises(image.offset, 0x6500098)))
    controls.append(("an address past every section is refused", raises(image.offset, 0x7FFFFFFFFF)))
    rig = Rig(image)
    data = names[7]
    real_plain(rig, data)
    controls.append(("a read window one byte short is flagged", not rig.reads_inside(INPUT, INPUT + len(data) - 1)))
    rig.machine.memory.put_bytes(INPUT - 1, b"\0")
    controls.append(("a damaged guard byte is flagged", not rig.guards_intact(data)))
    bare = Rig(image)
    bare.machine.slots = {}
    bare.load(b"Ec")
    controls.append(("a path without its stubs halts instead of guessing", raises(bare.call, MISSING, {})))
    return controls


# ---- coverage, per-name sites, evidence rendering ----

def coverage(image, seen):
    rows = []
    for name, function in FUNCTIONS:
        instructions = rows_of(image, function)
        starts = [row.va for row in instructions]
        stepped = [va for va in starts if va in seen]
        dark = [va for va in starts if va not in seen]
        rows.append((name, hex(function), hex(instructions[-1].next), len(starts), len(stepped),
                     " ".join(hex(va) for va in dark[:6]) + (" ..." if len(dark) > 6 else "")))
    return rows


def name_sites(image, spec, names):
    rig = Rig(image)
    machine = rig.machine
    rows = []
    jump_plain, jump_serde = read_jump_table(image, PLAIN), read_jump_table(image, SERDE)
    for number, name in enumerate(names):
        rig.load(name)
        before = machine.steps
        rig.call(PLAIN, {RDI: INPUT, RSI: len(name)})
        plain_steps, plain_site = machine.steps - before, machine.last
        rig.load(name)
        before = machine.steps
        rig.call(SERDE, {RDI: OUTBUF, RSI: INPUT, RDX: len(name)})
        serde_steps, serde_site = machine.steps - before, machine.last
        slot = len(name) - 2
        bucket = hex(jump_plain[slot]) if 0 <= slot < JUMP_SLOTS else "-"
        rows.append((number, name.decode(), len(name), slot if 0 <= slot < JUMP_SLOTS else "-", bucket, plain_steps, hex(plain_site),
                     serde_steps, hex(serde_site)))
    return rows


def bucket_rows(image, names):
    plain, serde = read_jump_table(image, PLAIN), read_jump_table(image, SERDE)
    rows = []
    for slot in range(JUMP_SLOTS):
        length = slot + 2
        members = [number for number, name in enumerate(names) if len(name) == length]
        rows.append((slot, length, hex(plain[slot]), hex(serde[slot]), len(members), " ".join(map(str, members))))
    return rows


STUB_ROLES = (
    ("slot", "free", "0x64df4a0", "deallocate: records (pointer, capacity, 0) in call order"),
    ("slot", "unwrap", "0x64df6a0", "Result::unwrap panic; the Location/vtable pair (rcx, r8) names the site"),
    ("slot", "expect", "0x64df520", "second panic entry, same recording"),
    ("slot", "resume", "0x64df4c0", "unwind landing pad call, never reached on a normal return"),
    ("slot", "format", "0x64df6e8", "path formatter: writes {capacity, pointer, length}; entry argument recorded"),
    ("slot", "read", "0x64e09c0", "file read: writes {capacity or 1<<63, pointer or error, length}"),
    ("slot", "path", "0x64e23e0", "aws_name path builder 0x1772fa0: writes {capacity, pointer, length}"),
    ("slot", "string", "0x64e08f8", "JSON string parser: writes {tag, pointer, length}; tag 2 is an error"),
    ("slot", "classify", "0x64e2400", "resolves to the plain classifier 0x1775500 and runs real"),
    ("call", "error_new", "0x1775ee0", "serde error constructor: records the code word, returns a 0x28 byte box"),
    ("call", "document", "0x17771b0", "document reader: writes the tag byte, the value byte or an error box"),
    ("call", "drop_io", "0x1778770", "io::Error drop: records its argument"),
    ("call", "unknown_variant", "0x1777fd0", "unknown-variant error: records (pointer, length, table, count)"),
    ("call", "invalid_type", "0x1776910", "invalid-type error: records the expectation pointer"),
    ("call", "position", "0x1778060", "attaches the reader position to an error"),
)


def table_text(rows):
    return "".join("\t".join(str(cell) for cell in row) + "\n" for row in rows)


def render(image, scale, rows_every, stride):
    names = read_names(image, NAME_ARRAYS[0])
    check_name_arrays(names, read_names(image, NAME_ARRAYS[1]))
    spec = Spec(names)
    table_bytes = bytes(image.blob[image.offset(WS_TABLE):image.offset(WS_TABLE) + 256])
    check_whitespace_table(table_bytes)
    rig, counts, outcomes, rows, bad = analyse(image, spec, names, scale, rows_every)
    if bad:
        raise EvidenceError("%d disagreements, first %r" % (len(bad), bad[0]))
    total = sum(counts.values())
    mutants, cache = [], {}
    for key, description, patches, overlay in build_mutants(image, stride):
        site = owner_instruction(image, cache, patches) if patches else None
        if site is not None and site not in rig.machine.seen:
            mutants.append((key, description, "not stepped", "instruction %#x is never executed by any case" % site))
            continue
        result, how = detect(image, spec, names, key, patches, overlay, scale)
        mutants.append((key, description, result, how))
    wrong = variants(image, spec, names, scale)
    controls = corrupt_controls(image, spec, names)
    detected_mutants = sum(1 for row in mutants if row[2] == "detected")
    detected_variants = sum(1 for row in wrong if row[3] > 0)
    detected_controls = sum(1 for _, ok in controls if ok)
    negative = detected_mutants + len(wrong) + len(controls)
    detected = detected_mutants + detected_variants + detected_controls
    files = {}
    files["names.tsv"] = "index\tname\tlength\tjump slot\tplain bucket\tplain steps\tplain return site\tserde steps\tserde return site\n" + \
        table_text(name_sites(image, spec, names))
    files["buckets.tsv"] = "jump slot\tname length\tplain target\tserde target\tnames\tindices\n" + table_text(bucket_rows(image, names))
    files["whitespace-table.tsv"] = "index\tvalue\tbit 0 (U+0080..U+00FF)\tbit 1 (U+2000..U+20FF)\n" + table_text(
        (hex(index), hex(value), bool(value & 1), bool(value & 2)) for index, value in enumerate(table_bytes) if value)
    files["cases.tsv"] = "family\tcase\toutcome\tinput\tresult\n" + table_text(rows)
    files["outcomes.tsv"] = "family\toutcome\tcases\n" + table_text((key, label, outcomes[(key, label)]) for key, label in sorted(outcomes))
    files["coverage.tsv"] = "function\tstart\tend\tinstructions\tstepped\tnot stepped (first)\n" + table_text(coverage(image, rig.machine.seen))
    files["stubs.tsv"] = "kind\tname\ttarget\tcontract\n" + table_text(STUB_ROLES)
    files["mutants.tsv"] = "family\tmutation\tresult\tdetail\n" + table_text(mutants)
    files["variants.tsv"] = "wrong model\tfamily\tfirst disagreeing case\tdisagreeing cases\tcases tried\n" + table_text(wrong)
    files["controls.tsv"] = "control\tdetected\n" + table_text(controls)
    summary = dict(binary_sha256=SHA256, cases=total, per_family=counts, disagreements=0, names=len(names),
                   functions=[dict(name=name, address=hex(va)) for name, va in FUNCTIONS],
                   mutants=len(mutants), mutants_detected=detected_mutants,
                   mutants_not_stepped=sum(1 for row in mutants if row[2] == "not stepped"),
                   mutants_survived=sum(1 for row in mutants if row[2] == "survived"), wrong_models=len(wrong), wrong_models_detected=detected_variants,
                   controls=len(controls), controls_detected=detected_controls)
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps(dict(cases=total, negative_controls=negative, negative_detected=detected,
                                            mutants_not_counted=len(mutants) - detected_mutants), indent=1, sort_keys=True) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (folder / name).write_text(text)


ROWS_EVERY = dict(plain=5, serde=10, trim=36, missing=3, endcheck=4, quoted=4, static=3)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--scale", type=int, default=1, help="divide the random case counts")
    parser.add_argument("--stride", type=int, default=3, help="mutate every Nth return immediate of the plain classifier")
    args = parser.parse_args(argv)
    image = load_image()
    write_outputs(args.out, render(image, args.scale, ROWS_EVERY, args.stride))
    return 0


if __name__ == "__main__":
    sys.exit(main())
