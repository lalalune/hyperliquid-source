#!/usr/bin/env python3
"""Pin the node #94 spot order gate and its half-of-supply size check from ELF bytes.

Functions 0x445f170, 0x445f4f0 and 0x26d1cf0 run the ordered admission checks shared by spot orders
and spot TWAPs. The last check rejects an order when size * 10^(weiDecimals - szDecimals) passes
supply >> 1 or does not fit 64 bits. The real bytes run in a Python evaluator over real B-tree and
hash table fixtures, with only the hash, key compare, outcome and record calls stubbed, and a
separately written specification predicts every outcome. No objdump or readelf output is parsed,
and the binary is never executed. Standard library only.

    python3 tools/spot_half_supply_gate.py --out <dir>
"""


import argparse
import bisect
import collections
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
HEAP_SIZE = 0x40000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 6000


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
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd"}
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
            return self.get(row.a, 8)
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
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
        elif op == "nop":
            pass
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
                if right == 0.0:
                    raise Halt("float division by zero at %#x" % row.va)
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
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")




# ---- targets ----

COPIES = (
    {"gate": 0x445F170, "supply": 0x4927990, "vault": 0x8D0, "callers": (0x4ADF6CE, 0x4C17CF2)},
    {"gate": 0x445F4F0, "supply": 0x4927990, "vault": 0x1350, "callers": (0x4ADFECE, 0x4C19602)},
    {"gate": 0x26D1CF0, "supply": 0x284BAD0, "vault": 0x8D0, "callers": (0x21F8719, 0x24F7C77)},
)
AMOUNT = 0x37606B0
HASH = 0x399C4A0
SCALERS = (0x4CA6A90, 0x230B0E0)
SLOT_OUTCOME = 0x5773198
SLOT_RECORD = 0x5774760
SLOT_AMOUNT = 0x5774768
SLOT_COMPARE = 0x576E488
SLOT_BOUNDS = 0x576DFC8
SLOT_PANIC = 0x576E470
BOUNDS_META = 0x56F1FD8
BOUNDS_TOKEN = 0x56F21F0
SCALE_PANIC = 0x56F2270
TAG_TABLE = 0x59A8D0
OUTCOME_TABLE = 0x59B088
OUTCOME_ARM = 0x3801CDC
OUTCOME_PIECES = 0x1E6818

TAG_OK = 0x186
TAG_ZERO = 0x5E
TAG_HALTED = 0x71
TAG_REDUCE = 0xF4
TAG_VAULT = 0x1D
TAG_SPOT = 0x17F
TAG_OUTCOME = 0x17D
TAG_FALLBACK = 0x17C
TAG_SIZE = 0x66
TAG_HALF = 0x67
AUX_OUTCOME = 7
META_KEY_LEA = 0x3721D61
META_VALUE_LEA = 0x3721D7F
SERIALIZERS = (0x26CE3F0, 0x26CE6C0, 0x3721D10, 0x3722120, 0x445DA80, 0x445DDD0)
SUPPLY_KEY = b"token_to_max_supply"
SUPPLY_KEY_SIZE = b"\xba\x13\x00\x00\x00"
ORDER = (TAG_ZERO, TAG_HALTED, TAG_REDUCE, TAG_VAULT, TAG_SPOT, TAG_FALLBACK, TAG_SIZE, TAG_HALF)

# Offsets of the fields the gate reads, from the second argument.
TOKENS = 0x10
META_POINTER = 0x178
META_COUNT = 0x180
META_STRIDE = 0x20
OUTCOME_FLAG = 0x168
HALT_ROOT = 0x260
FALLBACK_CTRL = 0x80
FALLBACK_MASK = 0x88
FALLBACK_ITEMS = 0x98
FALLBACK_HASHER = 0xA0
SUPPLY_ROOT = 0x388
TOKEN_POINTER = 0x180
TOKEN_COUNT = 0x188
TOKEN_STRIDE = 0xE8
SZ_DECIMALS = 0x48
WEI_DECIMALS = 0x49
RECORD_KEY = 0x30

HEAP_USED = 0xE000
OUT = HEAP_BASE + 0x100
USER = HEAP_BASE + 0x200
STATE = HEAP_BASE + 0x1000
CONTEXT = HEAP_BASE + 0x2000
META = HEAP_BASE + 0x3800
HALT_NODES = HEAP_BASE + 0x4000
SUPPLY_NODES = HEAP_BASE + 0x4400
VAULT_NODES = HEAP_BASE + 0x5000
TABLE_CTRL = HEAP_BASE + 0x8400
RECORD = HEAP_BASE + 0x8600
TOKEN_ROWS = HEAP_BASE + 0x9000
STACK_ARGUMENT = STACK_TOP - 0x100
BUCKETS = 64
H2 = 0x5A
EMPTY = 0xFF
BOUNDS_MARK = 0xD0000001
PANIC_MARK = 0xD0000002
COMPARE_MARK = 0xD0000003
DECOY = 0xC3C3C3C3C3C3C3C3

HALT_LAYOUT = {"first": 8, "stride": 8, "count": 0x62, "child": 0x70, "value": 0x64, "value_size": 1, "size": 0x100}
SUPPLY_LAYOUT = {"first": 8, "stride": 8, "count": 0xBA, "child": 0xC0, "value": 0x60, "value_size": 8, "size": 0x180}
VAULT_LAYOUT = {"first": 0x798, "stride": 20, "count": 0x876, "child": 0x878, "value": None, "value_size": 0, "size": 0x900}


class Case:
    __slots__ = ("sz", "index", "meta_count", "token", "book", "halt", "reduce", "vault", "outcome", "flag", "fallback", "start", "link", "record",
                 "supply", "sz_decimals", "wei_decimals", "token_count", "deep", "side")

    def __init__(self, sz=1, supply=1000, sz_decimals=2, wei_decimals=2, **extra):
        self.sz, self.supply, self.sz_decimals, self.wei_decimals = sz, supply, sz_decimals, wei_decimals
        self.index, self.meta_count, self.token, self.book = 1, 3, 12, 0x4000000000000123
        self.halt, self.reduce, self.vault, self.outcome, self.flag = "open", 0, "other", 0, 0
        self.fallback, self.start, self.link, self.record = "miss_empty", 3, 0x7777, None
        self.token_count, self.deep, self.side = 16, False, "left"
        for name, value in extra.items():
            setattr(self, name, value)


FALLBACK_HITS = ("hit_first", "hit_second", "full_hit", "third_hit")
FALLBACK_KINDS = ("empty", "miss_empty", "miss_collide", "full_miss") + FALLBACK_HITS


def spec(case):
    """Outcome as (kind, code, aux, event list), written from the check order and not from the fixtures."""
    events = []

    def tag(code, aux=None):
        return ("tag", code, aux, tuple(events))

    if case.sz == 0:
        return tag(TAG_ZERO)
    if case.index >= case.meta_count:
        return ("panic", BOUNDS_META, (case.index, case.meta_count), ())
    if case.halt != "open":
        return tag(TAG_HALTED)
    if case.reduce:
        return tag(TAG_REDUCE)
    if case.vault == "member":
        return tag(TAG_VAULT)
    events.append("outcome")
    if case.outcome == 1:
        return tag(TAG_SPOT)
    if case.outcome and case.flag == 1:
        return tag(TAG_OUTCOME, AUX_OUTCOME)
    if case.fallback != "empty":
        events.append("hash")
        if case.fallback in FALLBACK_HITS:
            events.append("record")
            if case.record == "same":
                return tag(TAG_FALLBACK)
    if case.supply is None:
        return tag(TAG_SIZE)
    if case.token >= case.token_count:
        return ("panic", BOUNDS_TOKEN, None, tuple(events))
    if case.wei_decimals < case.sz_decimals or case.wei_decimals - case.sz_decimals > 19:
        return ("panic", SCALE_PANIC, None, tuple(events))
    product = case.sz * 10 ** (case.wei_decimals - case.sz_decimals)
    if product >> 64 or product > case.supply >> 1:
        return tag(TAG_HALF)
    return tag(TAG_OK)


def tree_shape(needle, present, deep, side):
    """Sorted node contents as (root keys, left keys, right keys); leaves only when not deep."""
    keys = [needle - 3, needle + 3]
    if present:
        keys = [needle - 3, needle, needle + 3]
    if not deep:
        return keys, None, None
    if side == "left":
        return [needle + 5], keys, [needle + 9]
    if side == "right":
        return [needle - 5], [needle - 9], keys
    if present:
        return [needle], [needle - 3], [needle + 3]
    return [needle + 1], [needle - 3], [needle + 3]


class Harness:
    def __init__(self, image, copy, patches=None):
        self.image = image
        self.copy = copy
        self.machine = Traced(image, patches)
        relative = image.relative()
        memory = self.machine.memory
        hooks = {}
        for slot, mark, hook in ((SLOT_OUTCOME, None, self.on_outcome), (SLOT_RECORD, None, self.on_record), (SLOT_COMPARE, COMPARE_MARK, self.on_compare),
                                 (SLOT_BOUNDS, BOUNDS_MARK, self.on_bounds), (SLOT_PANIC, PANIC_MARK, self.on_panic)):
            target = relative.get(slot, mark)
            if target is None:
                raise EvidenceError("slot without a relocation: %#x" % slot)
            memory.statics[slot] = target
            hooks[target] = hook
        if relative.get(SLOT_AMOUNT) != AMOUNT:
            raise EvidenceError("amount slot changed")
        memory.statics[SLOT_AMOUNT] = AMOUNT
        self.machine.slots = hooks
        self.machine.calls = {HASH: self.on_hash}
        self.machine.real = frozenset((AMOUNT, copy["supply"]))
        self.case = None
        self.events = []
        self.user = bytes(20)
        self.hash_word = 0

    def on_outcome(self, machine):
        self.events.append("outcome")
        if machine.regs[RDI] != STATE + TOKENS or machine.regs[RSI] != self.case.token:
            raise Halt("outcome arguments differ")
        machine.regs[RAX] = POISON & ~0xFF | self.case.outcome

    def on_hash(self, machine):
        self.events.append("hash")
        if machine.regs[RDI] != STATE + FALLBACK_HASHER or machine.memory.read(machine.regs[RSI], 8) != self.case.token:
            raise Halt("hash arguments differ")
        machine.regs[RAX] = self.hash_word

    def on_record(self, machine):
        self.events.append("record")
        case = self.case
        if machine.regs[RDI] != STATE + TOKENS or machine.regs[RSI] != case.link:
            raise Halt("record arguments differ")
        machine.regs[RAX] = RECORD if case.record else 0

    def on_compare(self, machine):
        regs = machine.regs
        if regs[RDI] != USER or regs[RDX] != 20:
            raise Halt("key compare arguments differ")
        left, right = self.user, machine.memory.bytes_at(regs[RSI], 20)
        value = 0
        for one, two in zip(left, right):
            if one != two:
                value = one - two
                break
        regs[RAX] = POISON & ~MASK[4] | value & MASK[4]

    def on_bounds(self, machine):
        raise Panicked((machine.regs[RDX], machine.regs[RDI], machine.regs[RSI]))

    def on_panic(self, machine):
        raise Panicked((machine.regs[RDI], None, None))

    def write_tree(self, base, layout, shape, needle, target, decoy, encode):
        memory = self.machine.memory

        def node(at, keys, children):
            memory.write(at + layout["count"], 2, len(keys))
            for slot in range(11):
                memory.put_bytes(at + layout["first"] + slot * layout["stride"], encode(keys[slot] if slot < len(keys) else needle))
                if layout["value"] is not None:
                    value = target if slot < len(keys) and keys[slot] == needle else decoy
                    memory.write(at + layout["value"] + slot * layout["value_size"], layout["value_size"], value)
            for slot, child in enumerate(children):
                memory.write(at + layout["child"] + slot * 8, 8, child)

        root, left, right = shape
        if left is None:
            node(base, root, ())
            return base, 0
        node(base, root, (base + layout["size"], base + 2 * layout["size"]))
        node(base + layout["size"], left, ())
        node(base + 2 * layout["size"], right, ())
        return base, 1

    def prepare(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_USED)
        self.case = case
        self.events = []
        user = (case.book * 0x9E3779B97F4A7C15 | 1 << 100) & ((1 << 150) - 1) | 0x42 << 152
        self.user = user.to_bytes(20, "big")
        memory.put_bytes(USER, self.user)
        memory.write(STACK_ARGUMENT, 8, CONTEXT)
        memory.write(STATE + META_POINTER, 8, META)
        memory.write(STATE + META_COUNT, 8, case.meta_count)
        for row in range(min(case.meta_count, 8)):
            memory.write(META + row * META_STRIDE, 8, case.token if row == case.index else DECOY + row)
            memory.write(META + row * META_STRIDE + 8, 8, case.book if row == case.index else DECOY - row)
        memory.write(STATE + OUTCOME_FLAG, 1, case.flag)
        if case.halt == "no_root":
            memory.write(STATE + HALT_ROOT, 8, 0)
            memory.write(STATE + HALT_ROOT + 8, 8, DECOY)
        else:
            shape = tree_shape(case.book, case.halt != "absent", case.deep, case.side)
            target = 0 if case.halt == "open" else 1
            root, height = self.write_tree(HALT_NODES, HALT_LAYOUT, shape, case.book, target, target ^ 1, lambda key: (key & MASK[8]).to_bytes(8, "little"))
            memory.write(STATE + HALT_ROOT, 8, root)
            memory.write(STATE + HALT_ROOT + 8, 8, height)
        offset = self.copy["vault"]
        if case.vault == "none":
            memory.write(CONTEXT + offset, 8, 0)
            memory.write(CONTEXT + offset + 8, 8, DECOY)
        else:
            shape = tree_shape(user, case.vault == "member", case.deep, case.side)
            root, height = self.write_tree(VAULT_NODES, VAULT_LAYOUT, shape, user, 0, 0, lambda key: key.to_bytes(20, "big"))
            memory.write(CONTEXT + offset, 8, root)
            memory.write(CONTEXT + offset + 8, 8, height)
        self.write_table(case)
        if case.record:
            memory.write(RECORD + RECORD_KEY, 8, case.link if case.record == "same" else case.link ^ 1)
        if case.supply is None:
            if case.deep:
                root, height = self.write_tree(SUPPLY_NODES, SUPPLY_LAYOUT, tree_shape(case.token, False, True, case.side), case.token, 0, 0x55,
                                               lambda key: key.to_bytes(8, "little"))
            else:
                root, height = 0, 0
        else:
            root, height = self.write_tree(SUPPLY_NODES, SUPPLY_LAYOUT, tree_shape(case.token, True, case.deep, case.side), case.token, case.supply,
                                           case.supply ^ MASK[8], lambda key: key.to_bytes(8, "little"))
        memory.write(STATE + SUPPLY_ROOT, 8, root)
        memory.write(STATE + SUPPLY_ROOT + 8, 8, height)
        memory.write(STATE + TOKENS + TOKEN_POINTER, 8, TOKEN_ROWS)
        memory.write(STATE + TOKENS + TOKEN_COUNT, 8, case.token_count)
        if case.token < case.token_count:
            memory.write(TOKEN_ROWS + case.token * TOKEN_STRIDE + SZ_DECIMALS, 1, case.sz_decimals)
            memory.write(TOKEN_ROWS + case.token * TOKEN_STRIDE + WEI_DECIMALS, 1, case.wei_decimals)

    def write_table(self, case):
        memory = self.machine.memory
        control = bytearray([EMPTY]) * BUCKETS
        start = case.start
        entries = {}
        kind = case.fallback

        def bucket(offset):
            return (start + offset) & (BUCKETS - 1)

        def put(offset, key, value):
            control[bucket(offset)] = H2
            entries[bucket(offset)] = (key, value)

        if kind in ("full_hit", "full_miss", "third_hit"):
            for offset in range(32 if kind == "third_hit" else 16):
                control[bucket(offset)] = 0x80 if offset & 1 else 0x11
                entries[bucket(offset)] = (DECOY, DECOY)
        if kind == "miss_collide":
            put(1, case.token + 1, DECOY)
        elif kind in ("hit_first", "empty"):
            put(2, case.token, case.link)
        elif kind == "hit_second":
            put(1, case.token + 1, DECOY)
            put(3, case.token, case.link)
        elif kind == "full_hit":
            put(16, case.token, case.link)
        elif kind == "third_hit":
            put(48, case.token, case.link)
        for slot in range(BUCKETS):
            memory.write(TABLE_CTRL + slot, 1, control[slot])
            key, value = entries.get(slot, (DECOY, DECOY))
            memory.write(TABLE_CTRL - 16 * (slot + 1), 8, key)
            memory.write(TABLE_CTRL - 16 * (slot + 1) + 8, 8, value)
        for slot in range(16):
            memory.write(TABLE_CTRL + BUCKETS + slot, 1, control[slot])
        memory.write(STATE + FALLBACK_CTRL, 8, TABLE_CTRL)
        memory.write(STATE + FALLBACK_MASK, 8, BUCKETS - 1)
        memory.write(STATE + FALLBACK_ITEMS, 8, 0 if kind == "empty" else 1 + (case.token & 3))
        self.hash_word = H2 << 57 | (case.book & 0xFFFFFF) << 6 | start

    def run_case(self, case):
        self.prepare(case)
        machine = self.machine
        memory = machine.memory
        try:
            result = machine.run(self.copy["gate"], {RDI: OUT, RSI: STATE, RDX: USER, RCX: case.index, R8: case.sz, R9: POISON & ~0xFF | case.reduce})
        except Panicked as panic:
            location, one, two = panic.args[0]
            return ("panic", location, None if one is None else (one, two), tuple(self.events))
        if result != OUT:
            raise Halt("rax is not the out pointer")
        tag = memory.read(OUT, 2)
        aux = memory.read(OUT + 2, 1) if tag == TAG_OUTCOME else None
        rest = memory.bytes_at(OUT + (3 if aux is not None else 2), 32)
        if rest != bytes([STACK_MARK]) * 32:
            raise Halt("result wrote more than its fields")
        return ("tag", tag, aux, tuple(self.events))

    def run_amount(self, value, decimals):
        """The real size helper alone, on a one-row token table with sz decimals 0."""
        machine = self.machine
        memory = machine.memory
        memory.reset(HEAP_USED)
        memory.write(STATE + TOKENS + TOKEN_POINTER, 8, TOKEN_ROWS)
        memory.write(STATE + TOKENS + TOKEN_COUNT, 8, 1)
        memory.write(TOKEN_ROWS + SZ_DECIMALS, 1, 0)
        memory.write(TOKEN_ROWS + WEI_DECIMALS, 1, decimals)
        machine.path = []
        ok = machine.run(AMOUNT, {RDI: STATE + TOKENS, RSI: 0, RDX: value})
        return ok, machine.regs[RDX], machine.path


class Traced(Machine):
    def __init__(self, image, patches=None):
        super().__init__(image, patches)
        self.edges = collections.Counter()
        self.path = []

    def step(self, row):
        if row.op == "jcc":
            self.edges[(row.va, self.condition(row.cc))] += 1
        self.path.append(row)
        if len(self.path) > 4000:
            del self.path[:2000]
        return super().step(row)


# ---- vectors ----

def named_cases():
    half = 500
    return [
        ("zero size", Case(0)),
        ("zero size beats a bad index", Case(0, index=9, meta_count=3)),
        ("zero size beats halted", Case(0, halt="flagged")),
        ("index at the row count", Case(1, index=3, meta_count=3)),
        ("index above the row count", Case(1, index=8, meta_count=3)),
        ("no rows", Case(1, index=0, meta_count=0)),
        ("last row", Case(1, index=2, meta_count=3)),
        ("first row", Case(1, index=0, meta_count=3)),
        ("halt map empty", Case(1, halt="no_root")),
        ("book absent from the halt map", Case(1, halt="absent")),
        ("book absent, deep tree", Case(1, halt="absent", deep=True)),
        ("book flagged", Case(1, halt="flagged")),
        ("book flagged in the root", Case(1, halt="flagged", deep=True, side="root")),
        ("book open in the right leaf", Case(1, deep=True, side="right")),
        ("halted beats reduce-only", Case(1, halt="flagged", reduce=1)),
        ("reduce-only", Case(1, reduce=1)),
        ("reduce byte 2", Case(1, reduce=2)),
        ("reduce byte 0x80", Case(1, reduce=0x80)),
        ("reduce-only beats a vault", Case(1, reduce=1, vault="member")),
        ("user is a vault", Case(1, vault="member")),
        ("user is a vault, right leaf", Case(1, vault="member", deep=True, side="right")),
        ("user is a vault, root", Case(1, vault="member", deep=True, side="root")),
        ("no vaults", Case(1, vault="none")),
        ("not a vault, deep tree", Case(1, deep=True)),
        ("vault beats outcome state", Case(1, vault="member", outcome=1)),
        ("outcome word 1", Case(1, outcome=1)),
        ("outcome word 1, flag 1", Case(1, outcome=1, flag=1)),
        ("outcome word 2, flag 1", Case(1, outcome=2, flag=1)),
        ("outcome word 2, flag 0", Case(1, outcome=2, flag=0)),
        ("outcome word 2, flag 2", Case(1, outcome=2, flag=2)),
        ("outcome word 0xff, flag 1", Case(1, outcome=0xFF, flag=1)),
        ("outcome word 0, flag 1", Case(1, outcome=0, flag=1)),
        ("empty link map ignores a stale row", Case(1, fallback="empty", record="same")),
        ("link miss with a tag collision", Case(1, fallback="miss_collide")),
        ("link miss past a full group", Case(1, fallback="full_miss")),
        ("link hit, no record", Case(1, fallback="hit_first")),
        ("link hit, other record", Case(1, fallback="hit_first", record="other")),
        ("link hit, same record", Case(1, fallback="hit_first", record="same")),
        ("link hit past a collision", Case(1, fallback="hit_second", record="same")),
        ("link hit in the next group", Case(1, fallback="full_hit", record="same")),
        ("link hit in the third group", Case(1, fallback="third_hit", record="same")),
        ("link hit across the mirror", Case(1, fallback="hit_first", record="same", start=62)),
        ("fallback beats a missing supply", Case(1, fallback="hit_first", record="same", supply=None)),
        ("no supply entry", Case(1, supply=None)),
        ("no supply entry, deep tree", Case(1, supply=None, deep=True)),
        ("no supply entry, right leaf", Case(1, supply=None, deep=True, side="right")),
        ("supply in the root", Case(1, deep=True, side="root")),
        ("supply in the right leaf", Case(1, deep=True, side="right")),
        ("no supply beats a bad token", Case(1, supply=None, token=20, token_count=20)),
        ("size at half", Case(half)),
        ("size one over half", Case(half + 1)),
        ("odd supply floors the half", Case(half, supply=1001)),
        ("odd supply, one over", Case(half + 1, supply=1001)),
        ("supply zero", Case(1, supply=0)),
        ("supply one", Case(1, supply=1)),
        ("supply two", Case(1, supply=2)),
        ("supply two, size two", Case(2, supply=2)),
        ("supply u64 maximum", Case(1 << 62, supply=MASK[8])),
        ("top half of u64", Case((1 << 63) - 1, supply=MASK[8])),
        ("just over the top half", Case(1 << 63, supply=MASK[8])),
        ("k 2 at half", Case(5, supply=1000, sz_decimals=2, wei_decimals=4)),
        ("k 2 over half", Case(6, supply=1000, sz_decimals=2, wei_decimals=4)),
        ("k 1 product wraps to a small value", Case(0x199999999999999A, supply=MASK[8], sz_decimals=0, wei_decimals=1)),
        ("k 19 fits", Case(1, supply=MASK[8] - 1, sz_decimals=0, wei_decimals=19)),
        ("k 19 wraps", Case(2, supply=MASK[8], sz_decimals=0, wei_decimals=19)),
        ("k 16 at half", Case(5, supply=10 ** 17, sz_decimals=0, wei_decimals=16)),
        ("k 20 panics", Case(1, sz_decimals=0, wei_decimals=20)),
        ("wei below sz panics", Case(1, sz_decimals=3, wei_decimals=2)),
        ("token at the table end", Case(1, token=16, token_count=16)),
    ]


def lcg(seed):
    state = seed
    while True:
        state = (state * 0xD1342543DE82EF95 + 1) & MASK[8]
        yield state >> 11 ^ state


def random_cases(count, seed=0x9E3779B97F4A7C15):
    source = lcg(seed)

    def pick(limit):
        return next(source) % limit

    rows = []
    for serial in range(count):
        decimals = pick(9)
        scale = (0, 1, 2, 3, 8, 16, 19, 20)[pick(8)] if pick(4) == 0 else pick(5)
        multiplier = 10 ** scale
        supply = (next(source), next(source) >> 20, pick(1 << 32), pick(4), None)[pick(5)] if pick(3) == 0 else next(source) >> pick(40)
        base = (supply or 2) // 2 // multiplier
        sz = (base, base, base + 1, 1 + pick(1 << 20), next(source), MASK[8] // multiplier + 1, 0 if pick(8) == 0 else base)[pick(7)] & MASK[8]
        meta_count = 1 + pick(8)
        record = (None, "other", "same")[pick(3)]
        fallback = FALLBACK_KINDS[pick(len(FALLBACK_KINDS))] if pick(2) == 0 else "miss_empty"
        case = Case(sz, supply, decimals, decimals + scale if pick(30) else max(0, decimals - 1), index=pick(meta_count + (pick(16) == 0)), meta_count=meta_count,
                    token=10 + pick(48), book=16 + (next(source) >> 2), halt=("open", "open", "open", "open", "open", "absent", "flagged", "no_root")[pick(8)],
                    reduce=(0, 0, 0, 0, 0, 0, 0, 1 + pick(255))[pick(8)], vault=("other", "other", "other", "none", "none", "other", "other", "member")[pick(8)],
                    outcome=(0, 0, 0, 1, 2, 3 + pick(250))[pick(6)], flag=pick(3), fallback=fallback, start=pick(BUCKETS), link=next(source), record=record,
                    deep=bool(pick(2)), side=("left", "right", "root")[pick(3)])
        case.token_count = case.token + 1 + pick(8) if pick(30) else case.token
        rows.append(("random %d" % serial, case))
    return rows


def run_all(harness, sets):
    for name, case in sets:
        try:
            got = harness.run_case(case)
        except (Halt, EvidenceError) as error:
            return "stopped: %s" % str(error)[:60]
        if got != spec(case):
            return "differs: %s" % name
    return None


# ---- whole-domain pass ----

SUCCESS_TAIL = bytes.fromhex("a801")
TAIL = bytes.fromhex("48d1eb4839da")
FINAL_BLOCK = 0x37606E2
FINAL_BYTES = bytes.fromhex("31f64889d048f7e14889c2400f91c64889f059c3")
SCALE_WINDOW = (AMOUNT, 0x376078A)


def amount_row_rules(image):
    """Facts for one k: the size word reaches only the final mul, and that mul decides everything."""
    at = image.offset(FINAL_BLOCK)
    if bytes(image.blob[at:at + len(FINAL_BYTES)]) != FINAL_BYTES:
        raise EvidenceError("final multiply block changed")


def taint_walk(rows):
    """Follow the size word through one recorded path; any use but a move or the final mul is an error."""
    tainted = {RDX}
    finals = 0
    for row in rows:
        if row.va == FINAL_BLOCK + 5:
            if RAX not in tainted or RCX in tainted:
                raise EvidenceError("final multiply operands changed")
            finals += 1
            break
        if row.op == "mul":
            if row.a == ("r", RDI) and not tainted & {RAX, RDI}:
                tainted -= {RAX, RDX}
                continue
            raise EvidenceError("size reached an earlier multiply at %#x" % row.va)
        if row.op == "mov" and row.a[0] == "r" and row.width == 8 and row.b[0] in ("r", "i"):
            source = row.b[0] == "r" and row.b[1] in tainted
            tainted.discard(row.a[1])
            if source:
                tainted.add(row.a[1])
            continue
        for register in tainted:
            if uses(row, register):
                raise EvidenceError("size reached %s at %#x" % (row.op, row.va))
    if finals != 1:
        raise EvidenceError("path missed the final multiply")


def uses(row, register):
    for operand in (row.a, row.b):
        if not operand:
            continue
        if operand[0] == "r" and operand[1] == register:
            return True
        if operand[0] == "m" and register in (operand[1], operand[2]):
            return True
    return False


def amount_ladder(harness):
    """For each k: one path for every size, multiplier from real bytes, first failing size."""
    amount_row_rules(harness.image)
    rows = []
    for decimals in range(20):
        ok, multiplier, path = harness.run_amount(1, decimals)
        if ok != 1 or multiplier != 10 ** decimals:
            raise EvidenceError("multiplier differs at k %d" % decimals)
        taint_walk(path)
        last = MASK[8] // multiplier
        addresses = [row.va for row in path]
        for value in (0, 2, last, last + 1, MASK[8]):
            if value > MASK[8]:
                continue
            done, product, other = harness.run_amount(value, decimals)
            if [row.va for row in other] != addresses:
                raise EvidenceError("path depends on the size at k %d" % decimals)
            exact = value * multiplier
            if (done == 1) != (exact <= MASK[8]) or product != exact & MASK[8]:
                raise EvidenceError("helper differs at k %d value %#x" % (decimals, value))
        rows.append((decimals, multiplier, len(path), last, last + 1 if last < MASK[8] else ""))
    return rows


def tail_facts(image, copy):
    """The bytes from the helper call to the two result writes, the same in every copy."""
    low, high = image.exact_fde(copy["gate"])
    rows = decode_range(image, low, high)
    calls = [index for index, row in enumerate(rows) if row.op == "calli" and row.a[4] == SLOT_AMOUNT]
    if len(calls) != 1:
        raise EvidenceError("amount calls differ in %#x" % low)
    window = rows[calls[0] + 1:calls[0] + 5]
    data = b"".join(bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size]) for row in window)
    if [row.op for row in window] != ["test", "jcc", "shr", "cmp"] or not data.startswith(SUCCESS_TAIL) or data[-6:] != TAIL:
        raise EvidenceError("comparison tail changed in %#x" % low)
    branch = rows[calls[0] + 5]
    if branch.op != "jcc" or branch.cc != 7 or branch.target != window[1].target or window[1].cc != 4:
        raise EvidenceError("failure branches changed in %#x" % low)
    success = rows[calls[0] + 7]
    failure = next(row for row in rows if row.va == branch.target)
    after = rows[rows.index(failure) + 1]
    if (success.op, success.b[1] & MASK[2]) != ("mov", TAG_OK) or (after.op, after.b[1] & MASK[2]) != ("mov", TAG_HALF):
        raise EvidenceError("result writes changed in %#x" % low)
    return rows[calls[0]].va, branch.va, failure.va


def threshold_runs(harness):
    """Real gate at the edges of the admitted range, over k and a ladder of supplies."""
    runs = 0
    supplies = (0, 1, 2, 3, 999, 1000, 1001, 10 ** 12, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, MASK[8] - 1, MASK[8])
    for scale in range(20):
        multiplier = 10 ** scale
        for supply in supplies:
            top = (supply >> 1) // multiplier
            last = MASK[8] // multiplier
            for sz in {1, top, top + 1, last, last + 1, MASK[8]} - {0}:
                if sz > MASK[8]:
                    continue
                case = Case(sz, supply, 0, scale)
                if harness.run_case(case) != spec(case):
                    raise EvidenceError("threshold differs: k %d supply %#x size %#x" % (scale, supply, sz))
                runs += 1
    return runs


# ---- static facts ----

def copy_differences(image):
    """Row by row against the first copy: only the vault offset and the supply call may differ."""
    first = COPIES[0]
    base_low, base_high = image.exact_fde(first["gate"])
    base_rows = decode_range(image, base_low, base_high)
    rows = []
    for copy in COPIES[1:]:
        low, high = image.exact_fde(copy["gate"])
        other = decode_range(image, low, high)
        if high - low != base_high - base_low or len(other) != len(base_rows):
            raise EvidenceError("copy size differs: %#x" % low)
        differing = []
        shift = low - base_low
        for left, right in zip(base_rows, other):
            if left.va + shift != right.va or left.op != right.op or left.size != right.size:
                raise EvidenceError("copy shape differs at %#x" % right.va)
            if left.op in ("jcc", "jmp") and base_low <= left.target < base_high:
                if left.target + shift != right.target:
                    raise EvidenceError("copy branch differs at %#x" % right.va)
                continue
            if left.op == "call":
                if left.target == right.target:
                    continue
                if (left.target, right.target) != (first["supply"], copy["supply"]):
                    raise EvidenceError("copy call differs at %#x" % right.va)
                differing.append((right.va, "supply lookup %#x" % right.target))
                continue
            if (left.a, left.b, left.width, left.cc, left.target) != (right.a, right.b, right.width, right.cc, right.target):
                if left.op == "mov" and left.b[0] == "m" and (left.b[4] - first["vault"], right.b[4] - copy["vault"]) in ((0, 0), (8, 8)):
                    differing.append((right.va, "vault field %#x" % right.b[4]))
                    continue
                raise EvidenceError("copy operand differs at %#x" % right.va)
        rows.append((copy["gate"], first["gate"], len(other), differing))
    return rows


def lookup_copies(image):
    """The two supply lookups have equal bytes, so one analysis covers both."""
    low, high = image.exact_fde(COPIES[0]["supply"])
    other_low, other_high = image.exact_fde(COPIES[2]["supply"])
    left = bytes(image.blob[image.offset(low):image.offset(high - 1) + 1])
    right = bytes(image.blob[image.offset(other_low):image.offset(other_high - 1) + 1])
    if left != right:
        raise EvidenceError("supply lookups differ")
    return (low, high, high - low), (other_low, other_high, other_high - other_low), hashlib.sha256(left).hexdigest()


def display_text(image, table, index):
    entry = struct.unpack_from("<i", image.blob, image.offset(table + 4 * index))[0]
    arm = (table + entry) & MASK[8]
    code = bytes(image.blob[image.offset(arm):image.offset(arm) + 32])
    prefix = bytes.fromhex("488b3e488b4608488b4018488d35")
    if not code.startswith(prefix) or code[18] != 0xBA:
        raise EvidenceError("unexpected Display arm %#x" % arm)
    start = arm + 18 + struct.unpack_from("<i", code, 14)[0]
    size = struct.unpack_from("<I", code, 19)[0]
    return arm, start, bytes(image.blob[image.offset(start):image.offset(start) + size]).decode("ascii")


def outcome_prefix(image):
    """Tag 0x17d prints a literal piece and one payload byte through a second table."""
    entry = struct.unpack_from("<i", image.blob, image.offset(TAG_TABLE + 4 * TAG_OUTCOME))[0]
    if (TAG_TABLE + entry) & MASK[8] != OUTCOME_ARM:
        raise EvidenceError("tag 0x17d arm changed")
    at = image.offset(OUTCOME_PIECES)
    size = image.blob[at]
    return bytes(image.blob[at + 1:at + 1 + size]).decode("ascii")


def direct_calls(image, target):
    base, text = image.text_bytes()
    found = []
    at = text.find(b"\xe8")
    while 0 <= at <= len(text) - 5:
        if base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            found.append(base + at)
        at = text.find(b"\xe8", at + 1)
    return found


def indirect_slots(image, target):
    return sorted(slot for slot, kind, addend, _ in image.relocations() if kind == 8 and addend == target)


def tag_writes(image, tag):
    """Fixed 16-bit tag writes in .text: `mov $imm16, r16` and `movw $imm16, mem`, by byte shape."""
    base, text = image.text_bytes()
    word = re.escape(struct.pack("<H", tag))
    shapes = rb"\x66[\xb8-\xbf]" + word + rb"|\x66\x41[\xb8-\xbf]" + word + rb"|\x66(?:\x41)?\xc7[\x00-\xff]{1,3}" + word
    return sorted(base + match.start() for match in re.finditer(shapes, text))


def tag_census(image):
    """Each byte hit is a real write inside a gate copy, or sits inside a rel32 of a call."""
    rows = []
    gates = {copy["gate"] for copy in COPIES}
    for at in tag_writes(image, TAG_HALF):
        start = image.fde(at)[0]
        if start in gates:
            kinds = [row.va for row in decode_range(image, start, image.fde(at)[1]) if row.va == at]
            if not kinds:
                raise EvidenceError("tag write is not an instruction: %#x" % at)
            rows.append((at, start, "gate write"))
            continue
        offset = image.offset(at - 1)
        if image.blob[offset] != 0xE8:
            raise EvidenceError("unexplained tag bytes at %#x" % at)
        target = at + 4 + struct.unpack_from("<i", image.blob, offset + 1)[0]
        rows.append((at, start, "inside the rel32 of a call to %#x" % target))
    return rows


def caller_rows(image):
    """Each call site: the state field holding the second argument and the size scaler before it."""
    rows = []
    for copy in COPIES:
        sites = direct_calls(image, copy["gate"])
        if tuple(sorted(sites)) != tuple(sorted(copy["callers"])):
            raise EvidenceError("callers changed: %#x %r" % (copy["gate"], sites))
        for site in sorted(sites):
            data = bytes(image.blob[image.offset(site - 0x110):image.offset(site)])
            lea = [match for match in re.finditer(rb"\x49\x8d[\xb5\xb6]\x80\x00\x00\x00", data)]
            scaler = []
            for at in range(len(data) - 4):
                if data[at] == 0xE8:
                    target = site - 0x110 + at + 5 + struct.unpack_from("<i", data, at + 1)[0]
                    if target in SCALERS:
                        scaler.append(target)
            if len(lea) != 1 or len(scaler) != 1:
                raise EvidenceError("caller shape changed at %#x: %d %d" % (site, len(lea), len(scaler)))
            rows.append((copy["gate"], site, image.fde(site)[0], "%#x" % 0x80, scaler[0]))
    return rows


def field_rows(image):
    """Serde keys name the two fields of the spot struct that the gate reads, from serializer bytes."""
    rows = []
    start = image.offset(META_KEY_LEA)
    key = META_KEY_LEA + 7 + struct.unpack_from("<i", image.blob, start + 3)[0]
    if bytes(image.blob[start:start + 3]) != b"\x48\x8d\x35" or bytes(image.blob[image.offset(key):image.offset(key) + 4]) != b"meta":
        raise EvidenceError("meta key changed")
    if bytes(image.blob[image.offset(META_VALUE_LEA):image.offset(META_VALUE_LEA) + 4]) != b"\x48\x8d\x7b\x10":
        raise EvidenceError("meta value lea changed")
    rows.append((image.fde(META_KEY_LEA)[0], META_KEY_LEA, key, "meta", META_VALUE_LEA, TOKENS))
    for serializer in SERIALIZERS:
        low, high = image.exact_fde(serializer)
        data = bytes(image.blob[image.offset(low):image.offset(high - 1) + 1])
        sites = []
        for match in re.finditer(rb"\x48\x8d\x35", data):
            at = match.start()
            target = low + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
            try:
                text = bytes(image.blob[image.offset(target):image.offset(target) + len(SUPPLY_KEY)])
            except EvidenceError:
                continue
            if text == SUPPLY_KEY and SUPPLY_KEY_SIZE in data[at + 7:at + 18]:
                sites.append((at, target))
        if len(sites) != 1:
            raise EvidenceError("supply key sites differ in %#x: %d" % (low, len(sites)))
        at, target = sites[0]
        begin = max(0, at - 16)
        fields = [begin + match.start() for match in re.finditer(rb"[\x48\x49\x4c\x4d]\x8d[\x80-\xbf]\x88\x03\x00\x00", data[begin:at + 48])]
        if len(fields) != 1:
            raise EvidenceError("supply field lea differs in %#x" % low)
        rows.append((low, low + at, target, SUPPLY_KEY.decode("ascii"), low + fields[0], SUPPLY_ROOT))
    return rows


def locations(image):
    relative = image.relative()
    rows = []
    for slot in (BOUNDS_META, BOUNDS_TOKEN, SCALE_PANIC):
        path, line, column = image.location(slot, relative)
        rows.append((slot, path, line, column))
    return rows


# ---- mutation controls ----

EXPECTED_SURVIVORS = {
    (0x445F3CD, "immediate"): "pshufd 0x45 picks an equal dword, every byte of xmm0 is the same tag",
}


def displacement_at(row, data):
    """File index of an 8 or 32 bit displacement, or None: taken from the end of the instruction."""
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] is None or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def mutation_targets(image, starts, seen):
    edits = []
    for start in starts:
        low, high = image.exact_fde(start)
        for row in decode_range(image, low, high):
            if row.va not in seen or row.rip_at is not None:
                continue
            data = image.blob[image.offset(row.va):image.offset(row.va) + row.size]
            if row.op == "jcc":
                at = row.size - 5 if row.size >= 6 else 0
                edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
                continue
            if row.imm_at is not None and row.op not in ("call", "jmp"):
                edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
            if row.op in ("shl", "shr") and row.imm_at is None:
                edits.append((row.va, "shift", {row.va + row.size - 1: data[row.size - 1] ^ 8}))
            at = displacement_at(row, data)
            if at is not None:
                edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def run_mutants(image, sets, seen):
    """Rows of the first copy and its supply lookup; the other copies are shown equal row by row."""
    rows = []
    copy = COPIES[0]
    for va, kind, patch in mutation_targets(image, (copy["gate"], copy["supply"]), seen):
        harness = Harness(image, copy, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        reason = run_all(harness, sets)
        if reason is None:
            rows.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "")))
        else:
            rows.append((va, kind, "killed", reason))
    survivors = sorted(key for key in {(row[0], row[1]) for row in rows if row[2] == "survived"})
    if survivors != sorted(EXPECTED_SURVIVORS):
        raise EvidenceError("survivor list changed: %s" % " ".join("%#x/%s" % row for row in survivors))
    return rows


# ---- analysis ----

UNREACHED = ()


def analyse(image, full=True, vectors=3000):
    named = named_cases()
    randoms = random_cases(vectors)
    counts = collections.Counter()
    seen = set()
    branch_rows, missing = [], []
    copies, tails = [], []
    runs = 0
    ladder = None
    for copy in COPIES:
        harness = Harness(image, copy)
        for name, case in named + randoms:
            got = harness.run_case(case)
            want = spec(case)
            if got != want:
                raise EvidenceError("%#x %s: %r != %r" % (copy["gate"], name, got, want))
            counts["panic" if got[0] == "panic" else "%#x" % got[1]] += 1
        runs += threshold_runs(harness)
        if ladder is None:
            ladder = amount_ladder(harness)
        seen |= harness.machine.seen
        edges = harness.machine.edges
        low, high = image.exact_fde(copy["gate"])
        rows = decode_range(image, low, high)
        for row in rows:
            if row.op == "jcc":
                taken, skipped = edges[(row.va, True)], edges[(row.va, False)]
                branch_rows.append((row.va, row.va - low, taken, skipped))
                for direction, count in ((True, taken), (False, skipped)):
                    if not count:
                        missing.append("%#x:%s" % (row.va, direction))
        call, branch, failure = tail_facts(image, copy)
        tails.append((copy["gate"], call, branch, failure))
        copies.append((copy["gate"], low, high, high - low, len(rows), "%#x" % copy["vault"], copy["supply"]))
    if tuple(sorted(missing)) != UNREACHED:
        raise EvidenceError("uncovered branch directions changed: %s" % " ".join(sorted(missing)))
    named_rows = []
    for name, case in named:
        kind, code, aux, events = spec(case)
        named_rows.append((name, kind, "%#x" % code, "" if aux is None else aux if isinstance(aux, int) else "%d/%d" % aux, ",".join(events)))
    tags = [(tag,) + display_text(image, TAG_TABLE, tag) for tag in ORDER]
    result = {
        "named": len(named), "random": len(randoms), "counts": counts, "outcomes": named_rows, "branches": branch_rows, "copies": copies, "tails": tails,
        "differences": copy_differences(image), "lookups": lookup_copies(image), "ladder": ladder, "threshold_runs": runs, "tags": tags,
        "outcome_text": display_text(image, OUTCOME_TABLE, AUX_OUTCOME), "outcome_prefix": outcome_prefix(image), "census": tag_census(image),
        "callers": caller_rows(image), "fields": field_rows(image), "locations": locations(image), "gate_slots": sorted(slot for copy in COPIES for slot in indirect_slots(image, copy["gate"])),
    }
    if result["gate_slots"]:
        raise EvidenceError("gate reached through a pointer: %r" % (result["gate_slots"],))
    if full:
        result["mutations"] = run_mutants(image, named + randoms[:300], seen)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("gate-copies.tsv", ("gate", "fde_start", "fde_end", "bytes", "instructions", "vault_field", "supply_lookup"),
        [("%#x" % a, "%#x" % b, "%#x" % c, d, e, f, "%#x" % g) for a, b, c, d, e, f, g in result["copies"]])
    tsv("copy-differences.tsv", ("copy", "compared_with", "instructions", "address", "difference"),
        [("%#x" % a, "%#x" % b, n, "%#x" % va, what) for a, b, n, rows in result["differences"] for va, what in rows])
    tsv("check-order.tsv", ("position", "tag", "display_arm", "text_at", "text"),
        [(index + 1, "%#x" % t, "%#x" % a, "%#x" % s, x) for index, (t, a, s, x) in enumerate(result["tags"])])
    tsv("outcomes.tsv", ("case", "kind", "tag_or_location", "aux", "calls"), result["outcomes"])
    tsv("amount-ladder.tsv", ("k", "multiplier", "path_instructions", "largest_size_that_fits", "first_size_that_wraps"), result["ladder"])
    tsv("comparison-tails.tsv", ("gate", "amount_call", "ja_branch", "failure_block"), [tuple("%#x" % cell for cell in row) for row in result["tails"]])
    tsv("branches.tsv", ("address", "offset", "taken", "not_taken"), [("%#x" % va, "%#x" % off, a, b) for va, off, a, b in result["branches"]])
    tsv("call-sites.tsv", ("gate", "site", "caller_fde", "state_field_of_second_argument", "size_scaler"),
        [("%#x" % a, "%#x" % b, "%#x" % c, d, "%#x" % e) for a, b, c, d, e in result["callers"]])
    tsv("spot-fields.tsv", ("serializer", "key_lea", "key_at", "key", "field_lea", "field_offset"),
        [("%#x" % a, "%#x" % b, "%#x" % c, d, "%#x" % e, "%#x" % f) for a, b, c, d, e, f in result["fields"]])
    tsv("tag-0x67-census.tsv", ("address", "fde", "reading"), [("%#x" % a, "%#x" % b, c) for a, b, c in result["census"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "named_cases": result["named"], "random_cases": result["random"],
        "runs_per_outcome": dict(sorted(result["counts"].items())), "threshold_runs": result["threshold_runs"],
        "amount_helper": "%#x" % AMOUNT, "admitted_k": "0..=19",
        "rule": "admitted when sz * 10^k <= supply >> 1 as integers; a product past u64 gives the same tag 0x67",
        "supply_lookups": {"first": ["%#x" % cell for cell in result["lookups"][0]], "second": ["%#x" % cell for cell in result["lookups"][1]], "sha256": result["lookups"][2]},
        "outcome_prefix": result["outcome_prefix"], "outcome_payload_7": {"arm": "%#x" % result["outcome_text"][0], "text_at": "%#x" % result["outcome_text"][1], "text": result["outcome_text"][2]},
        "panic_locations": [{"record": "%#x" % a, "path": b, "line": c, "column": d} for a, b, c, d in result["locations"]],
        "gate_pointer_slots": 0,
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
    result = analyse(image)
    files = render(result)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files), "named": result["named"], "random": result["random"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
