#!/usr/bin/env python3
"""Pin the node #94 priority order admission gate from ELF bytes.

Function 0x3978840 takes a u32 priority word, a tree of order elements and three f64 durations. A
nonzero word admits only perp ids in IOC orders of one flag, then interpolates between two
durations. A zero word sorts ids into two sets. The real bytes run in a Python evaluator with the
tree collection helpers stubbed, and a separately written specification predicts every outcome.
The weight test is checked over all 2^64 f64 bit patterns and the id classes over all 2^32 words.
No objdump or readelf output is parsed, and the binary is never executed. Standard library only.

    python3 tools/priority_admission.py --out <dir>
"""


import argparse
import bisect
import collections
import hashlib
import json
import pathlib
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
        for marker in ("/l1/", "/base/", "/library/"):
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
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq"}
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
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")




# ---- targets ----

GATE = 0x3978840
BODY_END = 0x3978EC6
SLOT_PANIC = 0x576E470
SLOT_ASSERT = 0x576E108
NEXT = 0x33B68A0
COLLECT = 0x3BB3340
INSERT = 0x33987C0
DRAIN = 0x33B6170
SCALE_AT = 0x20AEA0
ONE_AT = 0x20A730
LOCATION_ORDERED = 0x566AE28
LOCATION_POSITIVE = 0x566AE58
LOCATION_BTREE_A = 0x56E9FE8
LOCATION_BTREE_B = 0x56E8B20
TEXT_ORDERED = (0x219F95, 0x23)
TEXT_POSITIVE = (0x219F59, 0x1E)
SPLIT_TABLE = 0x59A8D0
TAG_OK = 0x186
TAG_PRIORITY = 0xB2
TAG_IOC = 0xB3
TAG_ASSET = 0xB5
TAG_TEXTS = (0xB2, 0xB3, 0xB4, 0xB5)
OFFSET_DECIDE = 0x495
OFFSET_PASS = 0x512
OFFSET_REJECT = 0x5A5
ASSET_CUTS = (0, 10000, 110000, 100000000, 1 << 32)
CALL_SITES = (0x1EA31D6, 0x1EA3FEF, 0x33DF1E0, 0x33E0259, 0x3576FEA, 0x3BDE15D, 0x4322D39, 0x4323BCF, 0x432491F, 0x4325679)
ORDER_HANDLERS = (0x1EA3140, 0x1EA3F60, 0x4322CA0, 0x4323B40, 0x4324890, 0x43255E0)

HEAP_USED = 0x8000
OUT = HEAP_BASE + 0x800
TREE = HEAP_BASE + 0xA00
TRIPLE = HEAP_BASE + 0xA40
NODES = HEAP_BASE + 0x1000
OUT_SIZE = 0x60
ELEMENT = 0x18
LEAF_SIZE = 0x118
INNER_SIZE = 0x178
NODE_PARENT_INDEX = 0x110
NODE_LEN = 0x112
NODE_EDGES = 0x118
LEAF_CAPACITY = 11
MOVED = (0x1000D0, 0x2000E0, 0x3000F0)


def ieee_divide(left, right):
    if right == 0.0:
        if left != left or left == 0.0:
            return float("nan")
        negative = (to_bits(left) ^ to_bits(right)) >> 63
        return float("-inf") if negative else float("inf")
    return left / right


class Case:
    __slots__ = ("priority", "items", "a", "b", "d", "height", "moved")

    def __init__(self, priority=0, items=(), a=0.0, b=2.0, d=1.0, height=0, moved=MOVED):
        self.priority, self.items, self.a, self.b, self.d = priority, items, a, b, d
        self.height, self.moved = height, moved


def spot_like(asset):
    return 10000 <= asset < 110000


def admitted_asset(asset):
    return asset <= 99999999 and not spot_like(asset)


def interpolation(case):
    return ieee_divide(ieee_divide(float(case.priority), -100000000.0), case.d) + 1.0


def in_unit_range(x):
    """The test on the interpolation weight, for any f64."""
    if x != x or x in (float("inf"), float("-inf")):
        return False
    if to_bits(x) == 1 << 63:
        return True
    return 0.0 <= x <= 1.0


def spec_priority(case):
    for asset, flag, tif in case.items:
        if not admitted_asset(asset):
            return ("tag", TAG_ASSET)
        if tif != 2 or flag != 1:
            return ("tag", TAG_IOC)
    x = interpolation(case)
    if not in_unit_range(x):
        return ("tag", TAG_PRIORITY)
    if not case.b >= case.a:
        return ("assert", LOCATION_ORDERED)
    span = case.b - case.a
    if not span >= 0.0:
        return ("assert", LOCATION_POSITIVE)
    return ("ok", to_bits(case.a + x * span), 0, 0, case.moved)


def spec_plain(case):
    spot, perp = [], []
    for asset, flag, tif in case.items:
        if tif == 3:
            break
        if tif == 2 and flag == 0:
            continue
        (spot if spot_like(asset) or asset >= 100000000 else perp).append(asset)
    return ("ok", to_bits(case.b) if perp else 0, digest(spot), len(spot), (digest(perp), None, len(perp)))


def digest(assets):
    value = 0
    for asset in assets:
        value = (value * 31 + asset + 1) & MASK[8]
    return value


def spec(case):
    return spec_priority(case) if case.priority else spec_plain(case)


def lcg(seed):
    state = seed
    while True:
        state = (state * 0xD1342543DE82EF95 + 1) & MASK[8]
        yield state >> 11 ^ state


class Traced(Machine):
    def __init__(self, image, patches=None):
        super().__init__(image, patches)
        self.edges = collections.Counter()

    def step(self, row):
        if row.op in ("jcc", "cmov"):
            self.edges[(row.va, self.condition(row.cc))] += 1
        return super().step(row)

    def step_vector(self, row, op):
        if op == "divsd":
            self.set_low(row.a[1], to_bits(ieee_divide(to_float(self.low(row.a)), to_float(self.low(row.b)))))
        else:
            super().step_vector(row, op)


class Harness:
    def __init__(self, image, patches=None, statics=None):
        self.image = image
        self.machine = Traced(image, patches)
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        memory = self.machine.memory
        for slot in (SLOT_PANIC, SLOT_ASSERT):
            memory.statics[slot] = self.relative[slot]
        if statics:
            memory.statics.update(statics)
        self.machine.slots = {self.relative[SLOT_PANIC]: self.on_panic, self.relative[SLOT_ASSERT]: self.on_assert}
        self.machine.calls = {NEXT: self.on_next, COLLECT: self.on_collect, INSERT: self.on_insert, DRAIN: self.on_drain}
        self.script = []
        self.collected = 0
        self.case = None

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_assert(self, machine):
        text = (machine.regs[RDI], machine.regs[RSI])
        if text not in (TEXT_ORDERED, TEXT_POSITIVE):
            raise Halt("assert text is not one of the two read from the code")
        raise Panicked(("assert", machine.regs[RDX]))

    def check_walk(self, machine, root, height, length):
        """The nine words of the owning tree iterator that the stubbed helpers would read."""
        if root:
            want = (1, 0, root, height, 1, 0, root, height, length)
        else:
            want = (0, None, None, None, 0, None, None, None, 0)
        words = [machine.memory.read(machine.regs[RSI] + 8 * index, 8) for index in range(9)]
        for got, expected in zip(words, want):
            if expected is not None and got != expected:
                raise Halt("tree iterator word differs: %r" % (words,))

    def on_next(self, machine):
        memory = machine.memory
        target = machine.regs[RDI]
        self.check_walk(machine, self.root, self.case.height, len(self.case.items))
        if self.script:
            node, index = self.script.pop(0)
            memory.write(target, 8, node)
            memory.write(target + 8, 8, 0)
            memory.write(target + 16, 8, index)
        else:
            memory.write(target, 8, 0)

    def on_collect(self, machine):
        target = machine.regs[RDI]
        self.collected += 1
        self.check_walk(machine, self.root, self.case.height, len(self.case.items))
        for index, word in enumerate(self.case.moved):
            machine.memory.write(target + 8 * index, 8, word)

    def on_insert(self, machine):
        memory = machine.memory
        target, asset = machine.regs[RDI], machine.regs[RSI] & MASK[4]
        memory.write(target, 8, (memory.read(target, 8) * 31 + asset + 1) & MASK[8])
        memory.write(target + 16, 8, memory.read(target + 16, 8) + 1)

    def on_drain(self, machine):
        self.drained += 1
        moved = self.case.moved
        self.check_walk(machine, moved[0], moved[1], moved[2] if moved[0] else 0)
        machine.memory.write(machine.regs[RDI], 8, 0 if self.drained > 1 else 1)

    def carve(self, size):
        at = self.next_node
        self.next_node += size
        return at

    def write_element(self, node, index, item):
        memory = self.machine.memory
        asset, flag, tif = item
        at = node + 8 + ELEMENT * index
        memory.write(at, 4, asset)
        memory.write(at + 8, 1, flag)
        memory.write(at + 17, 1, tif)
        return node, index

    def build(self, items, height, order):
        """One subtree over items in order; order collects (node, index) in key order."""
        memory = self.machine.memory
        if height == 0:
            node = self.carve(LEAF_SIZE)
            memory.write(node, 8, 0)
            memory.write(node + NODE_LEN, 2, len(items))
            for index, item in enumerate(items):
                order.append(self.write_element(node, index, item))
            return node
        node = self.carve(INNER_SIZE)
        memory.write(node, 8, 0)
        keys = min(10, max(1, (len(items) - 1) // 4))
        size = (len(items) - keys) // (keys + 1)
        memory.write(node + NODE_LEN, 2, keys)
        at = 0
        for edge in range(keys + 1):
            take = size if edge < keys else len(items) - at
            child = self.build(items[at:at + take], height - 1, order)
            memory.write(node + NODE_EDGES + 8 * edge, 8, child)
            memory.write(child, 8, node)
            memory.write(child + NODE_PARENT_INDEX, 2, edge)
            at += take
            if edge < keys:
                order.append(self.write_element(node, edge, items[at]))
                at += 1
        return node

    def install(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_USED)
        self.case = case
        self.next_node = NODES
        order = []
        root = self.build(list(case.items), case.height, order) if case.items else 0
        self.root = root
        memory.write(TREE, 8, root)
        memory.write(TREE + 8, 8, case.height)
        memory.write(TREE + 16, 8, len(case.items))
        for index, value in enumerate((case.a, case.b, case.d)):
            memory.write(TRIPLE + 8 * index, 8, to_bits(value))
        self.script = order
        self.collected = 0
        self.drained = 0

    def run_case(self, case):
        self.install(case)
        machine = self.machine
        memory = machine.memory
        args = {RDI: OUT, RSI: case.priority, RDX: TREE, RCX: TRIPLE}
        try:
            result = machine.run(GATE, args)
        except Panicked as stop:
            return stop.args[0]
        if result != OUT:
            raise Halt("rax is not the out pointer")
        tag = memory.read(OUT, 2)
        if self.script and (tag in (TAG_IOC, TAG_ASSET) or not case.priority):
            raise Halt("tree was not consumed")
        if tag == TAG_PRIORITY and case.moved[0] and self.drained != 2:
            raise Halt("collected tree was not consumed")
        if tag != TAG_OK:
            if memory.bytes_at(OUT + 2, OUT_SIZE - 2) != bytes([STACK_MARK]) * (OUT_SIZE - 2):
                raise Halt("error result wrote more than the tag")
            return ("tag", tag)
        value, spot_root, spot_len = memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8), memory.read(OUT + 0x20, 8)
        words = (memory.read(OUT + 0x28, 8), memory.read(OUT + 0x30, 8), memory.read(OUT + 0x38, 8))
        if case.priority:
            return ("ok", value, spot_root, spot_len, words)
        return ("ok", value, spot_root, spot_len, (words[0], None, words[2]))

    def decide(self, bits):
        """Run the weight test alone, from the movq to its two exits."""
        machine = self.machine
        machine.regs = [POISON] * 16
        machine.regs[RSP] = STACK_TOP - 0x400
        machine.regs[RAX] = TRIPLE
        machine.xmm = [POISON | POISON << 64] * 16
        machine.xmm[0] = bits
        pc = GATE + OFFSET_DECIDE
        for _ in range(100):
            if pc == GATE + OFFSET_PASS:
                return True
            if pc == GATE + OFFSET_REJECT:
                return False
            row = machine.cache.get(pc) or decode(machine.read_code, pc)
            machine.cache[pc] = row
            pc = machine.step(row)
        raise Halt("weight test did not finish")


# ---- vectors ----

GOOD = (5, 1, 2)
BUILDER = (110005, 1, 2)
TOP = (99999999, 1, 2)


def named_cases():
    many = [(index * 7, 1, 2) for index in range(40)]
    return [
        ("priority, one perp IOC order", Case(5000000, (GOOD,))),
        ("priority, builder perp id", Case(5000000, (BUILDER,))),
        ("priority, last id below 1e8", Case(5000000, (TOP,))),
        ("priority, id 9999", Case(5000000, ((9999, 1, 2),))),
        ("priority, id 10000", Case(5000000, ((10000, 1, 2),))),
        ("priority, id 109999", Case(5000000, ((109999, 1, 2),))),
        ("priority, id 110000", Case(5000000, ((110000, 1, 2),))),
        ("priority, id 1e8", Case(5000000, ((100000000, 1, 2),))),
        ("priority, top id", Case(5000000, ((MASK[4], 1, 2),))),
        ("priority, tif 0", Case(5000000, ((5, 1, 0),))),
        ("priority, tif 1", Case(5000000, ((5, 1, 1),))),
        ("priority, tif 3", Case(5000000, ((5, 1, 3),))),
        ("priority, flag 0", Case(5000000, ((5, 0, 2),))),
        ("priority, flag 2", Case(5000000, ((5, 2, 2),))),
        ("priority, asset checked before tif", Case(5000000, ((10000, 0, 0),))),
        ("priority, first bad element decides: tif then asset", Case(5000000, ((5, 1, 0), (10000, 1, 2)))),
        ("priority, first bad element decides: asset then tif", Case(5000000, ((10000, 1, 2), (5, 1, 0)))),
        ("priority, bad element last", Case(5000000, (GOOD, GOOD, GOOD, (5, 0, 2)))),
        ("priority, no elements", Case(5000000, ())),
        ("priority, no elements, empty collected root", Case(5000000, (), moved=(0, 9, 7))),
        ("priority, bad weight, empty collected root", Case(1 << 31, (GOOD,), d=0.5, moved=(0, 9, 7))),
        ("priority, 40 elements in two levels", Case(5000000, tuple(many), height=1)),
        ("priority, 40 elements in three levels", Case(5000000, tuple(many), height=2)),
        ("priority, bad element after a parent step", Case(5000000, tuple(many[:20] + [(5, 0, 2)] + many[20:]), height=1)),
        ("priority, bad element in a parent", Case(5000000, tuple(many[:3] + [(5, 0, 2)] + many[3:]), height=1)),
        ("weight 1 at priority 1", Case(1, (GOOD,))),
        ("weight 0 at p = 1e8 d", Case(100000000, (GOOD,), d=1.0)),
        ("weight below 0", Case(100000001, (GOOD,), d=1.0)),
        ("half span", Case(25000000, (GOOD,), d=0.5, a=1.0, b=3.0)),
        ("zero d", Case(5, (GOOD,), d=0.0)),
        ("negative zero d", Case(5, (GOOD,), d=-0.0)),
        ("negative d", Case(5, (GOOD,), d=-1.0)),
        ("infinite d", Case(5, (GOOD,), d=float("inf"))),
        ("negative infinite d", Case(5, (GOOD,), d=float("-inf"))),
        ("NaN d", Case(5, (GOOD,), d=float("nan"))),
        ("tiny d", Case(5, (GOOD,), d=5e-324)),
        ("a above b", Case(5, (GOOD,), a=3.0, b=2.0)),
        ("a NaN", Case(5, (GOOD,), a=float("nan"))),
        ("b NaN", Case(5, (GOOD,), b=float("nan"))),
        ("a and b infinite", Case(5, (GOOD,), a=float("inf"), b=float("inf"))),
        ("a equals b", Case(5, (GOOD,), a=2.0, b=2.0)),
        ("bad weight beats a above b", Case(1 << 31, (GOOD,), a=3.0, b=2.0, d=0.5)),
        ("plain, no elements", Case()),
        ("plain, perp order takes b", Case(0, ((5, 0, 0),))),
        ("plain, IOC flag 0 is skipped", Case(0, ((5, 0, 2),))),
        ("plain, IOC flag 1 counts", Case(0, ((5, 1, 2),))),
        ("plain, IOC flag 2 counts", Case(0, ((5, 2, 2),))),
        ("plain, spot id goes to the first set", Case(0, ((10000, 1, 0),))),
        ("plain, id 109999 first set", Case(0, ((109999, 1, 0),))),
        ("plain, id 110000 second set", Case(0, ((110000, 1, 0),))),
        ("plain, id 99999999 second set", Case(0, ((99999999, 1, 0),))),
        ("plain, id 1e8 first set", Case(0, ((100000000, 1, 0),))),
        ("plain, tif 3 ends the walk", Case(0, ((5, 1, 0), (6, 1, 3), (7, 1, 0)))),
        ("plain, tif 3 first", Case(0, ((6, 1, 3), (7, 1, 0)))),
        ("plain, only first set gives zero", Case(0, ((10000, 1, 0), (100000000, 1, 1)))),
        ("plain, both sets in order", Case(0, ((5, 1, 0), (10000, 1, 1), (7, 1, 2), (100000000, 0, 0), (9, 0, 2)))),
        ("plain, b NaN is passed through", Case(0, ((5, 0, 0),), b=float("nan"))),
    ]


def random_cases(count, seed=0xC2B2AE3D27D4EB4F):
    source = lcg(seed)

    def pick(limit):
        return next(source) % limit

    def asset():
        return (pick(10000), pick(10000) + 10000, 110000 + pick(1 << 26), pick(1 << 32), ASSET_CUTS[1 + pick(3)] - pick(2))[pick(5)]

    def duration():
        kind = pick(6)
        if kind == 0:
            return 0.0
        if kind == 1:
            return float(pick(1000)) / 8.0
        if kind == 2:
            return to_float(next(source))
        return float(pick(100000)) / 1000.0

    rows = []
    for serial in range(count):
        size = pick(14)
        honest = pick(2)
        items = []
        for _ in range(size):
            if honest:
                items.append(((pick(10000), 110000 + pick(1 << 26))[pick(2)], 1, 2) if pick(30) else (asset(), pick(3), pick(4)))
            else:
                items.append((asset(), pick(3), pick(4)))
        priority = (0, 1, pick(1 << 27), 100000000, pick(1 << 32))[pick(5)]
        a, b = duration(), duration()
        if pick(4) and b < a:
            a, b = b, a
        d = (1.0, 0.5, 0.001, float(pick(100)) / 7.0, to_float(next(source)))[pick(5)]
        rows.append(("random %d" % serial, Case(priority, tuple(items), a, b, d, 1 if size > LEAF_CAPACITY or (size > 3 and pick(2)) else 0)))
    return rows


def same(left, right):
    return left == right


def run_all(harness, sets):
    for name, case in sets:
        try:
            got = harness.run_case(case)
        except (Halt, EvidenceError) as error:
            return "stopped: %s" % str(error)[:60]
        if got != spec(case):
            return "differs: %s" % name
    return None


# ---- whole-domain passes ----

FLOAT_SEEDS = ((0, 0x3FF0000000000000), (0x3FF0000000000001, 0x7FEFFFFFFFFFFFFF), (0x7FF0000000000000, 0x7FF0000000000000),
               (0x7FF0000000000001, (1 << 63) - 1), (1 << 63, 1 << 63), ((1 << 63) + 1, (1 << 63) | 0x000FFFFFFFFFFFFF),
               ((1 << 63) | 0x0010000000000000, (1 << 63) | 0x7FEFFFFFFFFFFFFF), ((1 << 63) | 0x7FF0000000000000, (1 << 63) | 0x7FF0000000000000),
               ((1 << 63) | 0x7FF0000000000001, MASK[8]))


def interior(lo, hi):
    return [lo + (hi - lo) * index // 257 for index in range(1, 257)]


def weight_table(harness):
    """The weight test over all 2^64 patterns; each seed is one class of the bit tests and the compare."""
    rows = []
    runs = 0
    for lo, hi in FLOAT_SEEDS:
        points = [lo, hi] + (interior(lo, hi) if hi > lo else [])
        results = {harness.decide(bits) for bits in points}
        runs += len(points)
        if len(results) != 1:
            raise EvidenceError("seed is not one class: %#x" % lo)
        result = results.pop()
        if result != in_unit_range(to_float(lo)) or result != in_unit_range(to_float(hi)):
            raise EvidenceError("weight class differs from the closed form: %#x" % lo)
        rows.append((lo, hi, int(result)))
    return rows, runs


def asset_table(harness):
    """Outcome of one element in each piece between the cut points read from the code."""
    rows = []
    for low, high in zip(ASSET_CUTS, ASSET_CUTS[1:]):
        points = [low, high - 1] + interior(low, high - 1)
        admitted, classes = set(), set()
        for asset in points:
            admitted.add(harness.run_case(Case(5000000, ((asset, 1, 2),)))[0] == "ok")
            got = harness.run_case(Case(0, ((asset, 1, 0),)))
            classes.add("second" if got[1] else "first")
            want = spec(Case(0, ((asset, 1, 0),)))
            if got != want:
                raise EvidenceError("class differs at %d" % asset)
        if len(admitted) != 1 or len(classes) != 1:
            raise EvidenceError("asset piece is not uniform: %d" % low)
        rows.append((low, high - 1, int(admitted.pop()), classes.pop()))
    return rows


def asset_compares(image):
    """The only reads of the element id word in the priority walk, by exact bytes."""
    low = GATE
    rows = decode_range(image, low, BODY_END)
    load = next(row for row in rows if row.va == GATE + 0x222)
    if load.op != "mov" or load.a != ("r", RCX) or load.width != 4:
        raise EvidenceError("element id load moved")
    window = [row for row in rows if GATE + 0x222 <= row.va < GATE + 0x241]
    shape = [(row.op, row.b[1] & MASK[4] if row.b and row.b[0] == "i" else None) for row in window]
    want = [("mov", None), ("mov", 0xB5), ("cmp", 0x5F5E0FF), ("jcc", None), ("add", 0xFFFFD8F0), ("cmp", 0x186A0), ("jcc", None)]
    if shape != want:
        raise EvidenceError("element id window changed: %r" % shape)
    return shape


def priority_edges(harness):
    """Largest admitted priority word for chosen d: the weight is monotone in the word and read by one test."""
    rows = []
    for d in (1.0, 0.5, 0.25, 0.001, 2.0, 100.0):
        def admitted(value):
            return harness.run_case(Case(value, (GOOD,), d=d))[0] == "ok"

        low, high = 1, MASK[4]
        runs = 2
        if admitted(high):
            rows.append((d, high, "", runs))
            continue
        while high - low > 1:
            middle = (low + high) // 2
            runs += 1
            if admitted(middle):
                low = middle
            else:
                high = middle
        rows.append((d, low, high, runs))
    return rows


# ---- static facts ----

def tag_text(image, tag):
    table = struct.unpack_from("<i", image.blob, image.offset(SPLIT_TABLE + 4 * tag))[0]
    arm = (SPLIT_TABLE + table) & MASK[8]
    code = bytes(image.blob[image.offset(arm):image.offset(arm) + 32])
    prefix = bytes.fromhex("488b3e488b4608488b4018488d35")
    if not code.startswith(prefix) or code[18] != 0xBA:
        raise EvidenceError("unexpected Display arm for tag %#x" % tag)
    start = arm + 18 + struct.unpack_from("<i", code, 14)[0]
    size = struct.unpack_from("<I", code, 19)[0]
    return arm, start, bytes(image.blob[image.offset(start):image.offset(start) + size]).decode("ascii")


def direct_calls(image, target):
    base, text = image.text_bytes()
    found = []
    at = text.find(b"\xe8")
    while 0 <= at <= len(text) - 5:
        if base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            found.append(base + at)
        at = text.find(b"\xe8", at + 1)
    return found


SELECT_FORMS = (
    (bytes.fromhex("31f64183fc030f44f5"), "word 3 selects, register r12d"),
    (bytes.fromhex("31f683fb030f44f5"), "word 3 selects, register ebx"),
    (bytes.fromhex("31f64183fd03410f44f7"), "word 3 selects, register r13d"),
)


def caller_forms(image):
    """How each call site makes the priority argument, from fixed bytes before the call."""
    rows = []
    for site in CALL_SITES:
        before = bytes(image.blob[image.offset(site - 40):image.offset(site)])
        start, _ = image.fde(site)
        form = None
        for pattern, name in SELECT_FORMS:
            if pattern in before:
                form = name
        if form is None and before.endswith(bytes.fromhex("4889df31f64c89fa4c89f1")) or before.endswith(bytes.fromhex("4889e24889df31f64c89f1")):
            form = "constant 0"
        if form is None and before.endswith(bytes.fromhex("4889df89ee4c89fa4c89f1")):
            head = bytes(image.blob[image.offset(start):image.offset(site)])
            if bytes.fromhex("83 7e 40 03 75 03 8b 6e 44") in head:
                form = "word 3 selects, direct load"
        if form is None:
            raise EvidenceError("unknown caller form at %#x" % site)
        rows.append((site, start, form))
    return rows


def handler_guards(image):
    """In each order handler, the compare of the priority word with 1e8 + 1 and the tag 0xb4 write."""
    rows = []
    for entry in ORDER_HANDLERS:
        low, high = image.exact_fde(entry)
        code = bytes(image.blob[image.offset(low):image.offset(low) + high - low])
        compare = code.find(bytes.fromhex("01e1f505"))
        tags = [at for at in range(len(code) - 3) if code[at] == 0x66 and 0xB8 <= code[at + 1] <= 0xBF and code[at + 2:at + 4] == b"\xb4\x00"]
        if compare < 0 or code.find(bytes.fromhex("01e1f505"), compare + 1) >= 0 or len(tags) != 1:
            raise EvidenceError("guard shape changed in %#x" % entry)
        rows.append((entry, low + compare, low + tags[0]))
    return rows


def constant_rows(image):
    rows = []
    for name, at in (("divisor", SCALE_AT), ("one", ONE_AT)):
        bits = struct.unpack_from("<Q", image.blob, image.offset(at))[0]
        rows.append((name, at, bits, to_float(bits)))
    return rows


EXPECTED_SURVIVORS = {
    0xD5: "compares the height with 8 to enter the unrolled descent, and no tree here is that tall",
    0x1B9: "compares the height with 8 to enter the unrolled descent, and no tree here is that tall",
}
TALL = "the leftmost descent is unrolled by 8 and only a tree of height 8 or more enters this row"
UNCOVERED = {
    "0x6e:True": "the walk state is set after the first element, so only a length word above the tree size stops here (navigate.rs:161:36)",
    "0xaf:True": TALL, "0xd9:True": TALL, "0xe9:True": TALL, "0xe9:False": TALL, "0x12c:True": TALL, "0x12c:False": TALL,
    "0x18f:True": TALL, "0x1bd:False": TALL, "0x200:True": TALL, "0x200:False": TALL, "0x277:True": TALL, "0x277:False": TALL,
    "0x13e:False": "a B-tree leaf on the leftmost edge is empty only in a tree with no elements, and that tree has no root",
    "0x156:True": "walking above the root needs a length word above the tree size (navigate.rs:534:47)",
    "0x284:True": "both error paths that reach this test follow an element, so the root is not null",
}


def mutation_targets(image, seen):
    edits = []
    for row in decode_range(image, GATE, BODY_END):
        if row.va not in seen:
            continue
        data = image.blob[image.offset(row.va):image.offset(row.va) + row.size]
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
        elif row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
        elif row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
    return edits


def run_mutants(image, sets, seen):
    rows = []
    for va, kind, patch in mutation_targets(image, seen):
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        reason = run_all(harness, sets)
        if reason is None:
            try:
                weight_table(harness)
            except (Halt, EvidenceError) as error:
                reason = "whole-domain weight: %s" % str(error)[:50]
        if reason is None:
            rows.append((va, kind, "survived", EXPECTED_SURVIVORS.get(va - GATE, "")))
        else:
            rows.append((va, kind, "killed", reason))
    survivors = sorted(row[0] - GATE for row in rows if row[2] == "survived")
    if survivors != sorted(EXPECTED_SURVIVORS):
        raise EvidenceError("survivor list changed: %s" % " ".join("%#x" % offset for offset in survivors))
    return rows


def constant_controls(image, sets):
    rows = []
    for name, at, value in (("divisor becomes -1e7", SCALE_AT, to_bits(-1e7)), ("divisor becomes +1e8", SCALE_AT, to_bits(1e8))):
        harness = Harness(image, None, {at: value})
        reason = run_all(harness, sets)
        rows.append((at, name, "survived" if reason is None else "killed", "" if reason is None else reason))
    return rows


WORKED = (
    ("plain perp order", Case(0, (GOOD,), a=0.25, b=2.0, d=0.1)),
    ("priority 0.01 of d 0.1", Case(1000000, (GOOD,), a=0.25, b=2.0, d=0.1)),
    ("priority 0.05 of d 0.1", Case(5000000, (GOOD,), a=0.25, b=2.0, d=0.1)),
    ("priority equal to d", Case(10000000, (GOOD,), a=0.25, b=2.0, d=0.1)),
    ("priority above d", Case(10000001, (GOOD,), a=0.25, b=2.0, d=0.1)),
)


# ---- analysis ----

def analyse(image, full=True, vectors=5000):
    harness = Harness(image)
    named = named_cases()
    randoms = random_cases(vectors)
    counts = collections.Counter()
    outcome_rows = []
    for name, case in named + randoms:
        got = harness.run_case(case)
        want = spec(case)
        if got != want:
            raise EvidenceError("%s: %r != %r" % (name, got, want))
        counts["%s %#x" % (got[0], got[1]) if got[0] in ("tag", "assert", "panic") else "ok priority" if case.priority else "ok plain"] += 1
    for name, case in named:
        got = spec(case)
        kind = "ok" if got[0] == "ok" else got[0]
        outcome_rows.append((name, kind, "%#x" % got[1] if got[0] != "ok" else to_float(got[1]).hex(), got[3] if got[0] == "ok" else "", got[4][2] if got[0] == "ok" and not case.priority else ""))
    edges = harness.machine.edges
    branch_rows, missing = [], []
    for row in decode_range(image, GATE, BODY_END):
        if row.op in ("jcc", "cmov"):
            taken, skipped = edges[(row.va, True)], edges[(row.va, False)]
            branch_rows.append((row.va, row.va - GATE, row.op, taken, skipped))
            for direction, count in ((True, taken), (False, skipped)):
                if not count:
                    missing.append("%#x:%s" % (row.va - GATE, direction))
    if vectors >= 2000 and set(missing) != set(UNCOVERED):
        raise EvidenceError("uncovered directions changed: %s" % " ".join(sorted(set(missing) ^ set(UNCOVERED))))
    weights, weight_runs = weight_table(harness)
    worked = []
    for name, case in WORKED:
        got = harness.run_case(case)
        if got != spec(case):
            raise EvidenceError("worked case differs: %s" % name)
        worked.append((name, got[0], to_float(got[1]) if got[0] == "ok" else "%#x" % got[1]))
    relative = harness.relative
    result = {
        "named": len(named), "random": len(randoms), "counts": counts, "outcomes": outcome_rows, "branches": branch_rows, "missing": missing,
        "weights": weights, "weight_runs": weight_runs, "assets": asset_table(harness), "asset_compares": asset_compares(image),
        "edges": priority_edges(harness), "worked": worked, "fde": image.exact_fde(GATE),
        "sites": direct_calls(image, GATE), "callers": caller_forms(image), "guards": handler_guards(image),
        "tags": [(tag,) + tag_text(image, tag) for tag in TAG_TEXTS], "constants": constant_rows(image),
        "locations": {va: image.location(va, relative) for va in (LOCATION_ORDERED, LOCATION_POSITIVE)},
        "asserts": [bytes(image.blob[image.offset(at):image.offset(at) + size]).decode("ascii") for at, size in (TEXT_ORDERED, TEXT_POSITIVE)],
    }
    if full:
        seen = set(harness.machine.seen)
        sets = named + randoms[:1200]
        result["mutations"] = run_mutants(image, sets, seen) + constant_controls(image, sets)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("outcomes.tsv", ("case", "outcome", "value_or_tag", "first_set_size", "second_set_size"), result["outcomes"])
    tsv("branches.tsv", ("address", "offset", "op", "taken", "not_taken"),
        [("%#x" % va, "%#x" % off, op, a, b) for va, off, op, a, b in result["branches"]])
    tsv("weight-classes.tsv", ("bits_lo", "bits_hi", "admitted"), [("%#x" % lo, "%#x" % hi, ok) for lo, hi, ok in result["weights"]])
    tsv("asset-classes.tsv", ("id_lo", "id_hi", "admitted_for_priority", "plain_set"), result["assets"])
    tsv("priority-edges.tsv", ("d", "last_admitted", "first_refused", "real_runs"), result["edges"])
    tsv("examples.tsv", ("case", "outcome", "value"), result["worked"])
    tsv("tags.tsv", ("tag", "display_arm", "text_at", "text"), [("%#x" % t, "%#x" % a, "%#x" % s, x) for t, a, s, x in result["tags"]])
    tsv("callers.tsv", ("call_site", "function", "priority_argument"), [("%#x" % s, "%#x" % f, n) for s, f, n in result["callers"]])
    tsv("handler-guards.tsv", ("function", "immediate_1e8_plus_1_at", "tag_0xb4_write"), [("%#x" % a, "%#x" % b, "%#x" % c) for a, b, c in result["guards"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"),
            [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "function": "%#x" % GATE,
        "fde": ["%#x" % result["fde"][0], "%#x" % result["fde"][1], result["fde"][1] - result["fde"][0]],
        "call_sites": ["%#x" % s for s in result["sites"]],
        "named_cases": result["named"], "random_cases": result["random"], "cases": dict(sorted(result["counts"].items())),
        "uncovered_directions": {key: UNCOVERED.get(key, "") for key in result["missing"]}, "weight_runs": result["weight_runs"],
        "constants": [{"name": n, "address": "%#x" % a, "bits": "%#x" % b, "value": repr(v)} for n, a, b, v in result["constants"]],
        "locations": {"%#x" % k: "%s:%d:%d" % v for k, v in result["locations"].items()},
        "assert_texts": result["asserts"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"),
                                "survived": sum(1 for r in rows if r[2] == "survived")}
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
