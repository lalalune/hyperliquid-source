#!/usr/bin/env python3
"""Pin the node #94 priority order native cost from ELF bytes.

Functions 0x24f84c0, 0x4ae0df0 and 0x4ae1210 turn a price and size into an amount of the native
token, then multiply it by a u32 factor over 1e8. The real bytes run in a Python evaluator with
only panic slots stubbed, and a separately written specification predicts every outcome. The cast
after the factor product is refined over all 2^64 f64 bit patterns and the factor limit over all
2^32 words. No objdump or readelf output is parsed, and the binary is never executed. Standard
library only.

    python3 tools/priority_native_cost.py --out <dir>
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

COPIES = (0x24F84C0, 0x4AE0DF0, 0x4AE1210)
DROP = {0x24F84C0: 0x2506640, 0x4AE0DF0: 0x4B10BB0, 0x4AE1210: 0x4B10BB0}
LOCATION_PAIR = {0x24F84C0: 0x56BB188, 0x4AE0DF0: 0x573DFC8, 0x4AE1210: 0x573DFC8}
SLOT_ONE_PRICE = 0x5774548
SLOT_UNIT = 0x5774550
SLOT_DIVIDE = 0x576E1A8
SLOT_PANIC = 0x576E470
SLOT_SUB_PANIC = 0x576E150
SLOT_BOUNDS = 0x576DFC8
ONE_PRICE = 0x375FB50
UNIT = 0x3760790
DIVIDE = 0x565F5A0
LOCATION_TABLE = 0x56F21F0
LOCATION_POWER = 0x56F2240
LOCATION_SUB = 0x56F2258
LOCATION_UNIT = 0x56F2270
SPLIT_TABLE = 0x59A8D0
SCALE_AT = 0x20A180
LIMIT_AT = 0x20A528
INFINITY_AT = 0x20A4B0
TWO_64_AT = 0x20A510
TWO_63_AT = 0x20A7F0
CAST_TOP_AT = 0x20A218
LOW_MASK_AT = 0x203E80
LOW_BIAS_AT = 0x202EA0
PRODUCT_LIMIT = 0x7FFFFFFFFFFFFFFE
GATE = 0x28F5C28F5C28F5C
FACTOR_ONE = 100000000.0
FACTOR_LIMIT = 1.01
TAG_OK = 0x186
TAG_NO_NATIVE = 0xFB
TAG_PRODUCT = 0x13F
TAG_PRIORITY = 0xB2
TAG_ORDER = 0x69
TAG_TEXTS = (0x69, 0xB2, 0xB3, 0xB4, 0xB5, 0xFB, 0x13F)
OFFSET_TAIL = 0x35A
OFFSET_STORE = 0x3CA
OFFSET_FACTOR = 0x316
OFFSET_LOAD_U64 = 0x335

HEAP_USED = 0x8000
OUT = HEAP_BASE + 0x800
CONTEXT = HEAP_BASE + 0x1000
TOKENS = HEAP_BASE + 0x2000
PAIRS = HEAP_BASE + 0x5000
NODES = HEAP_BASE + 0x6000
OUT_SIZE = 0x60
TOKEN_STRIDE = 0xE8
PAIR_STRIDE = 0x20
NODE_SIZE = 0xC0
INNER_SIZE = 0x120
NODE_LEN = 0xBA
NODE_CAPACITY = 11


class Case:
    __slots__ = ("flag", "native", "tokens", "pairs", "tree", "factor", "index", "a", "b")

    def __init__(self, factor=100000000, index=0, a=1000, b=1000, native=1, tokens=((8, 8), (2, 8), (0, 6)), pairs=(1,), tree=None, flag=1):
        self.flag, self.native, self.tokens, self.pairs, self.tree = flag, native, tokens, pairs, tree
        self.factor, self.index, self.a, self.b = factor, index, a, b


def one_price(case, token):
    """10^(token 0 wei decimals - token sz decimals), the helper behind slot 0x5774548."""
    if not case.tokens or token >= len(case.tokens):
        return ("panic", LOCATION_TABLE)
    power = case.tokens[0][1] - case.tokens[token][0]
    if power < 0:
        return ("panic", LOCATION_SUB)
    if power > 19:
        return ("panic", LOCATION_POWER)
    return 10 ** power


def unit_ratio(case, token):
    """10^(wei decimals - sz decimals) of one token, the helper behind slot 0x5774550."""
    power = case.tokens[token][1] - case.tokens[token][0]
    if power < 0 or power > 19:
        return ("panic", LOCATION_UNIT)
    return 10 ** power


def priced(case, token):
    if case.tree and token in case.tree:
        return case.tree[token]
    return one_price(case, token)


def factor_value(factor):
    return float(factor) / FACTOR_ONE


def spec_cast(value):
    """The saturating cast after the product, for any f64."""
    if value != value or value == float("inf"):
        return 0
    if value > 18446744073709549568.0:
        return MASK[8]
    if value <= 0.0:
        return 0
    return int(value)


def spec(case, entry=COPIES[0]):
    """The closed form, written from the claim and not from the evaluator."""
    if case.flag != 1:
        return ("tag", TAG_NO_NATIVE)
    native_price = priced(case, case.native)
    if isinstance(native_price, tuple):
        return native_price
    product = case.a * case.b
    if product > PRODUCT_LIMIT:
        return ("tag", TAG_PRODUCT)
    if case.index >= len(case.pairs):
        return ("bounds", LOCATION_PAIR[entry])
    quote = case.pairs[case.index]
    quote_price = priced(case, quote)
    if isinstance(quote_price, tuple):
        return quote_price
    divisor = 1
    if quote != 0:
        if quote >= len(case.tokens):
            return ("panic", LOCATION_TABLE)
        divisor = unit_ratio(case, quote)
        if isinstance(divisor, tuple):
            return divisor
    wide = product * quote_price
    if wide <= MASK[8]:
        value, exact = wide // divisor, True
    else:
        value = (product // divisor) * quote_price
        exact = value <= MASK[8]
        value &= MASK[8]
    if case.native >= len(case.tokens):
        return ("panic", LOCATION_TABLE)
    if not exact or value >= GATE:
        value = product
    native_unit = unit_ratio(case, case.native)
    if isinstance(native_unit, tuple):
        return native_unit
    quotient, remainder = divmod(value * native_unit, native_price)
    amount = quotient + (1 if remainder else 0)
    if amount > MASK[8]:
        return ("tag", TAG_PRIORITY)
    factor = factor_value(case.factor)
    if factor > FACTOR_LIMIT:
        return ("tag", TAG_PRIORITY)
    return ("ok", spec_cast(factor * float(amount)))


def lcg(seed):
    state = seed
    while True:
        state = (state * 0xD1342543DE82EF95 + 1) & MASK[8]
        yield state >> 11 ^ state


class Traced(Machine):
    """Counts each direction of every conditional branch and cmov inside the targets."""

    def __init__(self, image, patches=None):
        super().__init__(image, patches)
        self.edges = collections.Counter()

    def step(self, row):
        if row.op in ("jcc", "cmov"):
            self.edges[(row.va, self.condition(row.cc))] += 1
        return super().step(row)


class Harness:
    def __init__(self, image, patches=None, statics=None):
        self.image = image
        self.machine = Traced(image, patches)
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        memory = self.machine.memory
        for slot in (SLOT_ONE_PRICE, SLOT_UNIT, SLOT_DIVIDE, SLOT_PANIC, SLOT_SUB_PANIC, SLOT_BOUNDS):
            memory.statics[slot] = self.relative[slot]
        if statics:
            memory.statics.update(statics)
        self.machine.real = frozenset((ONE_PRICE, UNIT, DIVIDE, DROP[COPIES[0]], DROP[COPIES[1]]))
        self.machine.slots = {self.relative[SLOT_PANIC]: self.on_panic, self.relative[SLOT_SUB_PANIC]: self.on_panic,
                              self.relative[SLOT_BOUNDS]: self.on_bounds}
        self.tail_trace = []

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_bounds(self, machine):
        raise Panicked(("bounds", machine.regs[RDX]))

    def carve(self, size):
        at = self.next_node
        self.next_node += size
        return at

    def leaf(self, keys, tree, inner=False):
        memory = self.machine.memory
        node = self.carve(INNER_SIZE if inner else NODE_SIZE)
        memory.write(node + NODE_LEN, 2, len(keys))
        for index, key in enumerate(keys):
            memory.write(node + 8 + 8 * index, 8, key)
            memory.write(node + 0x60 + 8 * index, 8, tree[key])
        # Stale copies in unused slots show that the length word bounds the scan.
        for index in range(len(keys), NODE_CAPACITY):
            stale = keys[-1] + 1 + index if keys else index
            memory.write(node + 8 + 8 * index, 8, stale)
            memory.write(node + 0x60 + 8 * index, 8, 0x5151515151515151)
        return node

    def install_tree(self, tree):
        memory = self.machine.memory
        self.next_node = NODES
        keys = sorted(tree)
        if len(keys) <= NODE_CAPACITY:
            return self.leaf(keys, tree), 0
        chunks = [keys[start:start + 5] for start in range(0, len(keys), 6)]
        separators = [keys[start + 5] for start in range(0, len(keys), 6) if start + 5 < len(keys) and chunks[-1] != keys[start:start + 5]]
        children = [self.leaf(chunk, tree) for chunk in chunks]
        root = self.leaf(separators, tree, inner=True)
        for index, child in enumerate(children):
            memory.write(root + 0xC0 + 8 * index, 8, child)
        return root, 1

    def install(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_USED)
        memory.write(CONTEXT + 0x80, 4, case.flag)
        memory.write(CONTEXT + 0x88, 8, case.native)
        memory.write(CONTEXT + 0x1F8, 8, PAIRS)
        memory.write(CONTEXT + 0x200, 8, len(case.pairs))
        memory.write(CONTEXT + 0x210, 8, TOKENS)
        memory.write(CONTEXT + 0x218, 8, len(case.tokens))
        for index, (sz, wei) in enumerate(case.tokens):
            memory.write(TOKENS + index * TOKEN_STRIDE + 0x48, 1, sz)
            memory.write(TOKENS + index * TOKEN_STRIDE + 0x49, 1, wei)
        for index, quote in enumerate(case.pairs):
            memory.write(PAIRS + index * PAIR_STRIDE + 8, 8, quote)
        root, height = (0, 0) if case.tree is None else self.install_tree(case.tree)
        memory.write(CONTEXT + 0x250, 8, root)
        memory.write(CONTEXT + 0x258, 8, height)

    def run_case(self, entry, case):
        self.install(case)
        machine = self.machine
        memory = machine.memory
        before = bytes(memory.heap[:HEAP_USED])
        args = {RDI: OUT, RSI: case.factor | 0xA5A5A5A500000000, RDX: case.index, RCX: case.a, R8: case.b, R9: CONTEXT}
        try:
            result = machine.run(entry, args)
        except Panicked as stop:
            return stop.args[0]
        if result != OUT:
            raise Halt("rax is not the out pointer")
        if bytes(memory.heap[:OUT - HEAP_BASE]) != before[:OUT - HEAP_BASE] or \
                bytes(memory.heap[OUT - HEAP_BASE + OUT_SIZE:HEAP_USED]) != before[OUT - HEAP_BASE + OUT_SIZE:HEAP_USED]:
            raise Halt("state outside the result changed")
        tag = memory.read(OUT, 2)
        if memory.bytes_at(OUT + 2, 6) != bytes([STACK_MARK]) * 6 or memory.bytes_at(OUT + 16, OUT_SIZE - 16) != bytes([STACK_MARK]) * (OUT_SIZE - 16):
            raise Halt("result bytes beyond the tag and value changed")
        if tag == TAG_OK:
            return ("ok", memory.read(OUT + 8, 8))
        if memory.bytes_at(OUT + 8, 8) != bytes([STACK_MARK]) * 8:
            raise Halt("error result wrote a value")
        return ("tag", tag)

    def tail_value(self, entry, bits):
        """Run from the instruction after the factor product to the store of the tag."""
        machine = self.machine
        machine.memory.reset(0x1000)
        machine.regs = [POISON] * 16
        machine.regs[RSP] = STACK_TOP - 0x400
        machine.regs[RBX] = OUT
        machine.regs[RDI] = OUT
        machine.xmm = [POISON | POISON << 64] * 16
        machine.xmm[0] = bits
        pc = entry + OFFSET_TAIL
        stop = entry + OFFSET_STORE
        trace = []
        for _ in range(100):
            if pc == stop:
                return tuple(trace), machine.memory.read(OUT + 8, 8), machine.regs[RAX] & MASK[2]
            row = machine.cache.get(pc) or decode(machine.read_code, pc)
            machine.cache[pc] = row
            if row.op in ("jcc", "cmov"):
                trace.append((row.va - entry, machine.condition(row.cc)))
            pc = machine.step(row)
        raise Halt("tail did not reach the store")


# ---- vectors ----

SMALL = (0, 1, 2, 3, 9, 10, 11, 99, 100, 1000, 12345, 10 ** 6, 10 ** 8, 123456789, 1 << 31, 1 << 32, (1 << 32) + 1, 10 ** 12,
         1 << 45, 10 ** 15, 10 ** 16, GATE - 1, GATE, GATE + 1, 1 << 62, PRODUCT_LIMIT - 1, PRODUCT_LIMIT, PRODUCT_LIMIT + 1,
         (1 << 63) + 5, MASK[8] - 1, MASK[8])
TOKEN_SETS = (((8, 8), (2, 8), (0, 6), (5, 11), (3, 3)), ((6, 6), (1, 7), (4, 6), (2, 18), (0, 8)),
              ((8, 10), (0, 2), (8, 8), (3, 5), (1, 1)))


def ceiling_edge():
    """Inputs where the floor is 2^64 - 1 with a remainder, so only the carry of the +1 reaches the high word."""
    unit = 10 ** 4
    for price in range(3000, 5000):
        value = ((MASK[8] * price) + unit - 1) // unit
        wide = value * unit
        if wide // price == MASK[8] and wide % price:
            return value, price
    raise EvidenceError("no ceiling edge")


def named_cases():
    plain = ((8, 8), (2, 8), (0, 6))
    value, price = ceiling_edge()
    quote_w0 = ((8, 8), (4, 4))
    edge_tokens = ((8, 8), (4, 8), (0, 6))
    cases = [
        ("native flag zero", Case(flag=0)),
        ("native flag two", Case(flag=2)),
        ("flag beats a bad native id", Case(flag=0, native=99)),
        ("no tree, one price of token 1", Case()),
        ("tree holds native only", Case(tree={1: 3050000})),
        ("tree holds quote only", Case(native=2, tree={1: 3050000})),
        ("tree holds both", Case(native=2, pairs=(1,), tree={1: 3050000, 2: 77})),
        ("tree empty leaf", Case(tree={})),
        ("tree with 30 keys, hit in a child", Case(native=2, tree={i * 3: i + 1 for i in range(30)}, tokens=((8, 8),) * 90, pairs=(9,))),
        ("tree with 30 keys, hit in the root", Case(native=5, tree={i: i + 1 for i in range(30)}, tokens=((8, 8),) * 32, pairs=(0,))),
        ("tree with 30 keys, miss", Case(native=2, tree={i * 3: i + 1 for i in range(1, 31)}, tokens=((8, 8),) * 8, pairs=(0,))),
        ("key just above the last leaf key", Case(native=2, tree={1: 5}, tokens=((8, 8),) * 12, pairs=(0,))),
        ("key equals a stale slot", Case(native=5, tree={3: 7}, tokens=((8, 8),) * 12, pairs=(0,))),
        ("native id out of range, not in tree", Case(native=3)),
        ("no tokens", Case(tokens=(), pairs=(0,))),
        ("native sz above token 0 wei", Case(tokens=((8, 2), (5, 5)))),
        ("native one price power 19", Case(tokens=((0, 19), (0, 8)), pairs=(0,))),
        ("native one price power 20", Case(tokens=((0, 20), (0, 8)), pairs=(0,))),
        ("native one price power 32", Case(tokens=((0, 32), (0, 8)), pairs=(0,))),
        ("native one price power 48", Case(tokens=((0, 48), (0, 8)), pairs=(0,))),
        ("product over the limit", Case(a=1 << 62, b=2)),
        ("product at the limit", Case(a=PRODUCT_LIMIT, b=1, pairs=(0,), native=0, tokens=((8, 8),))),
        ("product one above the limit", Case(a=PRODUCT_LIMIT + 1, b=1)),
        ("product wraps", Case(a=1 << 32, b=1 << 32)),
        ("product wraps to a small value", Case(a=(1 << 32) + 1, b=(1 << 32) - 1)),
        ("product beats a bad pair", Case(a=1 << 62, b=2, index=5)),
        ("pair index out of range", Case(index=1)),
        ("pair index in range", Case(index=2, pairs=(0, 0, 1))),
        ("quote zero uses divisor one", Case(pairs=(0,))),
        ("quote zero with a tree entry", Case(pairs=(0,), tree={0: 9})),
        ("quote id out of range, no tree", Case(pairs=(7,))),
        ("quote id out of range, in tree", Case(pairs=(7,), tree={7: 5})),
        ("quote wei below sz, in tree", Case(tokens=((8, 8), (2, 8), (9, 6)), pairs=(2,), native=1, tree={2: 5})),
        ("quote wei minus sz 19", Case(tokens=((8, 8), (2, 8), (0, 19)), pairs=(2,), tree={2: 5})),
        ("quote wei minus sz 20", Case(tokens=((8, 8), (2, 8), (0, 20)), pairs=(2,), tree={2: 5})),
        ("quote divide floors", Case(tokens=edge_tokens, pairs=(2,), tree={2: 7, 1: 3}, a=999, b=1)),
        ("native id out of range, in tree", Case(native=9, tree={9: 5})),
        ("native id out of range, overflow path", Case(native=9, tree={9: 5, 1: 1 << 40}, a=1 << 30, b=1 << 30)),
        ("native id out of range, 32-bit divide", Case(native=9, tree={9: 5}, tokens=((8, 8), (2, 8), (0, 6)), pairs=(2,), a=7, b=9)),
        ("native wei below sz, in tree", Case(tokens=((8, 8), (9, 8), (0, 6)), native=1, tree={1: 5}, pairs=(0,))),
        ("quote price zero", Case(native=2, tree={1: 0})),
        ("gate one below", Case(native=0, tokens=quote_w0, pairs=(1,), tree={1: 5, 0: 1 << 40}, a=(GATE - 1) // 5, b=1)),
        ("gate exact", Case(native=0, tokens=quote_w0, pairs=(1,), tree={1: 2, 0: 1 << 40}, a=GATE // 2, b=1)),
        ("gate one above", Case(native=0, tokens=quote_w0, pairs=(1,), tree={1: 2, 0: 1 << 40}, a=GATE // 2 + 1, b=1)),
        ("gate keeps the product", Case(native=0, tokens=((8, 8), (0, 0)), pairs=(1,), tree={1: 3, 0: 1 << 45}, a=GATE - 5, b=1)),
        ("wide product, quotient stays below the gate", Case(native=0, tokens=((8, 8), (0, 6)), pairs=(1,), tree={1: 100, 0: 1 << 45}, a=(1 << 61) + 999999, b=1)),
        ("wide product, quotient at the gate", Case(native=0, tokens=((8, 8), (0, 0)), pairs=(1,), tree={1: 3, 0: 1 << 45}, a=1 << 62, b=1)),
        ("wide product, second multiply overflows", Case(native=0, tokens=((8, 8), (0, 0)), pairs=(1,), tree={1: 1 << 20, 0: 1 << 45}, a=1 << 62, b=1)),
        ("wide product, quote zero", Case(native=0, tokens=((8, 8),), pairs=(0,), tree={0: 1 << 40}, a=1 << 40, b=1)),
        ("wide product, product just above 2^32", Case(native=0, tokens=((8, 8), (0, 2)), pairs=(1,), tree={1: 1 << 33, 0: 1 << 40}, a=(1 << 32) + 5, b=1)),
        ("wide product, small words divide", Case(native=0, tokens=((8, 8), (0, 2)), pairs=(1,), tree={1: 1 << 32, 0: 1 << 40}, a=(1 << 32) - 1, b=1)),
        ("exact amount needs no ceiling", Case(native=0, tokens=((8, 8),), pairs=(0,), tree={0: 100}, a=4000, b=1)),
        ("ceiling adds one", Case(native=0, tokens=((8, 8),), pairs=(0,), tree={0: 100}, a=4001, b=1)),
        ("amount at 2^64 - 1", Case(native=0, tokens=((0, 0),), pairs=(0,), tree={0: 1}, a=1, b=1)),
        ("amount high word set", Case(native=0, tokens=((0, 1),), pairs=(0,), tree={0: 1}, a=1844674407370955162, b=1)),
        ("amount just below 2^64", Case(native=0, tokens=((0, 1),), pairs=(0,), tree={0: 1}, a=1844674407370955161, b=1)),
        ("ceiling carries into the high word", Case(native=0, tokens=((0, 4),), pairs=(0,), tree={0: price}, a=value, b=1)),
        ("ceiling carry beats a bad factor word", Case(native=0, tokens=((0, 4),), pairs=(0,), tree={0: price}, a=value, b=1, factor=MASK[4])),
        ("factor zero", Case(factor=0)),
        ("factor one", Case(factor=1)),
        ("factor 1.0", Case(factor=100000000)),
        ("factor at the limit", Case(factor=101000000)),
        ("factor one above the limit", Case(factor=101000001)),
        ("factor top word", Case(factor=MASK[4])),
        ("factor bit 31", Case(factor=1 << 31)),
        ("amount above 2^53 rounds", Case(native=0, tokens=((8, 8),), pairs=(0,), tree={0: 1}, a=(1 << 53) + 1, b=1)),
        ("amount 2^63 at 1.0", Case(native=0, tokens=((0, 1),), pairs=(0,), tree={0: 10}, a=PRODUCT_LIMIT + 1 - 1, b=1)),
        ("amount near 2^64 at 1.01", Case(native=0, tokens=((0, 1),), pairs=(0,), tree={0: 1}, a=1844674407370955161, b=1, factor=101000000)),
        ("high bits of the amount at 1.0", Case(native=0, tokens=((0, 1),), pairs=(0,), tree={0: 1}, a=1844674407370955161, b=1)),
    ]
    return cases


def random_cases(count, seed=0x9E3779B97F4A7C15):
    source = lcg(seed)
    rows = []

    def pick(limit):
        return next(source) % limit

    def magnitude():
        kind = pick(5)
        if kind == 0:
            return SMALL[pick(len(SMALL))]
        if kind == 1:
            return next(source) >> pick(64)
        if kind == 2:
            return 10 ** pick(19)
        if kind == 3:
            return (10 ** pick(19)) * pick(1000)
        return next(source) >> 32

    for serial in range(count):
        tokens = TOKEN_SETS[pick(len(TOKEN_SETS))]
        native = pick(5) if pick(32) else pick(9)
        quote = pick(5)
        tree = None
        if pick(3):
            tree = {}
            for key in (native, quote, pick(5), pick(40)):
                if pick(3):
                    tree[key] = max(1, magnitude() & MASK[8])
        a, b = magnitude() & MASK[8], magnitude() & MASK[8]
        if pick(2):
            b = pick(1 << 20)
            a = a >> 20
        factor = (0, 1, 50000000, 100000000, 101000000, 101000001, pick(1 << 27), pick(1 << 32))[pick(8)]
        pairs = (quote, pick(5))
        rows.append(("random %d" % serial, Case(factor, pick(2), a, b, native, tokens, pairs, tree, 1 if pick(40) else 0)))
    return rows


def run_all(harness, entry, sets):
    """None when every case matches, else a short reason."""
    for name, case in sets:
        try:
            got = harness.run_case(entry, case)
        except (Halt, EvidenceError) as error:
            return "stopped: %s" % str(error)[:60]
        if got != spec(case, entry):
            return "differs: %s" % name
    return None


# ---- whole-domain passes ----

FLOAT_SEEDS = ((0, 0x7FEFFFFFFFFFFFFF), (0x7FF0000000000000, 0x7FF0000000000000), (0x7FF0000000000001, (1 << 63) - 1),
               (1 << 63, (1 << 63) | 0x7FEFFFFFFFFFFFFF), ((1 << 63) | 0x7FF0000000000000, (1 << 63) | 0x7FF0000000000000),
               ((1 << 63) | 0x7FF0000000000001, MASK[8]))


def interior(lo, hi):
    """256 fixed points of one piece, evenly spread and independent of the run order."""
    return [lo + (hi - lo) * index // 257 for index in range(1, 257)]


def refine_tail(harness, entry):
    """Split the f64 bit patterns until each piece has one decision record; check the closed form."""
    pieces = []
    runs = 0
    for seed in FLOAT_SEEDS:
        stack = [seed]
        found = []
        while stack:
            lo, hi = stack.pop()
            first = harness.tail_value(entry, lo)
            last = harness.tail_value(entry, hi) if hi != lo else first
            runs += 2
            if first[0] == last[0]:
                found.append((lo, hi, first[0]))
                continue
            middle = (lo + hi) // 2
            stack.append((middle + 1, hi))
            stack.append((lo, middle))
        found.sort(key=lambda row: row[0])
        merged = []
        for lo, hi, trace in found:
            if merged and merged[-1][2] == trace and merged[-1][1] + 1 == lo:
                merged[-1] = (merged[-1][0], hi, trace)
            else:
                merged.append((lo, hi, trace))
        pieces.extend(merged)
    rows = []
    for lo, hi, trace in pieces:
        points = [lo, hi] + (interior(lo, hi) if hi > lo else [])
        for bits in points:
            out = harness.tail_value(entry, bits)
            if out[0] != trace:
                raise EvidenceError("interior point left its piece: %#x" % bits)
            if out[1] != spec_cast(to_float(bits)) or out[2] != TAG_OK:
                raise EvidenceError("tail mismatch at %#x: %#x" % (bits, out[1]))
        rows.append((lo, hi, harness.tail_value(entry, lo)[1], harness.tail_value(entry, hi)[1], len(trace)))
    return rows, runs


def helper_domains(harness):
    """Both power helpers over all 65536 pairs of their two decimals bytes."""
    machine = harness.machine
    memory = machine.memory
    memory.reset(HEAP_USED)
    memory.write(CONTEXT + 0x90 + 0x180, 8, TOKENS)
    memory.write(CONTEXT + 0x90 + 0x188, 8, 2)
    second = TOKENS + TOKEN_STRIDE
    counts = collections.Counter()

    def outcome(entry, args):
        try:
            return machine.run(entry, args)
        except Panicked as stop:
            return stop.args[0]

    for first in range(256):
        for other in range(256):
            memory.write(TOKENS + 0x49, 1, first)
            memory.write(second + 0x48, 1, other)
            case = Case(tokens=((0, first), (other, 0)))
            got = outcome(ONE_PRICE, {RDI: CONTEXT + 0x90, RSI: 1})
            if got != one_price(case, 1):
                raise EvidenceError("one price differs at %d %d" % (first, other))
            counts["one price panic %#x" % got[1] if isinstance(got, tuple) else "one price value"] += 1
            memory.write(second + 0x49, 1, first)
            case = Case(tokens=((0, 0), (other, first)))
            got = outcome(UNIT, {RDI: second + 0x30})
            if got != unit_ratio(case, 1):
                raise EvidenceError("unit ratio differs at %d %d" % (first, other))
            counts["unit ratio panic %#x" % got[1] if isinstance(got, tuple) else "unit ratio value"] += 1
    return counts


def factor_edge(harness, entry):
    """Largest admitted factor word: fl(u32)/1e8 is monotone and one compare reads it, so one edge holds for all 2^32."""
    def admitted(value):
        return harness.run_case(entry, Case(factor=value))[0] == "ok"

    low, high = 0, MASK[4]
    if not admitted(low) or admitted(high):
        raise EvidenceError("factor ends are not on opposite sides")
    runs = 2
    while high - low > 1:
        middle = (low + high) // 2
        runs += 1
        if admitted(middle):
            low = middle
        else:
            high = middle
    return low, high, runs


# ---- static facts ----

def direct_calls(image, targets):
    base, text = image.text_bytes()
    found = collections.defaultdict(list)
    at = text.find(b"\xe8")
    while 0 <= at <= len(text) - 5:
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in targets:
            found[target].append(base + at)
        at = text.find(b"\xe8", at + 1)
    return found


def operand_text(operand):
    if operand is None:
        return ""
    kind = operand[0]
    if kind == "r":
        return "r%d" % operand[1]
    if kind == "x":
        return "x%d" % operand[1]
    if kind == "i":
        return "%#x" % (operand[1] & MASK[8])
    _, base, index, scale, disp, _ = operand
    parts = []
    if base is not None:
        parts.append("r%d" % base)
    if index is not None:
        parts.append("r%d*%d" % (index, scale))
    parts.append("%#x" % (disp & MASK[8]))
    return "[" + "+".join(parts) + "]"


def row_shape(row, start, end):
    target = row.target
    if target is not None and row.op in ("jcc", "jmp", "call") and start <= target < end:
        target = "+%#x" % (target - start)
    elif target is not None:
        target = "%#x" % (target & MASK[8])
    return (row.op, row.width, row.cc, operand_text(row.a), operand_text(row.b), target)


def copy_differences(image, first, second):
    low, end = image.exact_fde(first)
    other, other_end = image.exact_fde(second)
    if end - low != other_end - other:
        raise EvidenceError("copies differ in size: %#x %#x" % (first, second))
    rows = decode_range(image, low, end)
    others = decode_range(image, other, other_end)
    if [row.va - low for row in rows] != [row.va - other for row in others]:
        raise EvidenceError("copies differ in instruction boundaries")
    found = []
    for row, peer in zip(rows, others):
        left, right = row_shape(row, low, end), row_shape(peer, other, other_end)
        if left != right:
            found.append((row.va - low, " ".join(map(str, left)), " ".join(map(str, right))))
    return len(rows), found


def tag_text(image, tag):
    """Text of one error tag, read from the Display jump table and the arm's exact bytes."""
    table = struct.unpack_from("<i", image.blob, image.offset(SPLIT_TABLE + 4 * tag))[0]
    arm = (SPLIT_TABLE + table) & MASK[8]
    code = bytes(image.blob[image.offset(arm):image.offset(arm) + 32])
    prefix = bytes.fromhex("488b3e488b4608488b40184 88d35".replace(" ", ""))
    if not code.startswith(prefix) or code[18] != 0xBA:
        raise EvidenceError("unexpected Display arm for tag %#x" % tag)
    start = arm + 18 + struct.unpack_from("<i", code, 14)[0]
    size = struct.unpack_from("<I", code, 19)[0]
    return arm, start, bytes(image.blob[image.offset(start):image.offset(start) + size]).decode("ascii")


def tag_sites(image, entry):
    low, end = image.exact_fde(entry)
    found = []
    for row in decode_range(image, low, end):
        if row.op == "mov" and row.width == 2 and row.b and row.b[0] == "i":
            found.append((row.va, row.b[1]))
    return found


def constant_rows(image):
    rows = []
    for name, at in (("factor scale", SCALE_AT), ("factor limit", LIMIT_AT), ("infinity test", INFINITY_AT), ("clamp 2^64", TWO_64_AT),
                     ("cast bias 2^63", TWO_63_AT), ("cast top", CAST_TOP_AT)):
        bits = struct.unpack_from("<Q", image.blob, image.offset(at))[0]
        rows.append((name, at, bits, to_float(bits)))
    return rows


# Directions no input of the function reaches, each with the reason.
UNREACHED = {
    (0x36A, True): "the je tests for infinity or NaN, and a finite factor times a u64 is neither",
    (0x3AB, False): "the cmovae falls through only for a negative value, and the product of two non-negative values is not negative",
}
# Mutations no input can see, each with the reason.
EXPECTED_SURVIVORS = {
    0x127: "the word is an error value built only to be dropped, and the drop helper returns without effect for 0x13f and 0x13e",
    0x138: "the word is an error value built only to be dropped, and the drop helper returns without effect for 0x69 and 0x68",
    0x39B: "sar 62 gives -2 instead of -1 only for values at or above 2^63, whose low bits are already zero",
}


def mutation_targets(image, entry, seen):
    """Reached rows with a condition or an immediate."""
    low, end = image.exact_fde(entry)
    edits = []
    for row in decode_range(image, low, end):
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


def run_mutants(image, entry, sets, seen):
    rows = []
    for va, kind, patch in mutation_targets(image, entry, seen):
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        reason = run_all(harness, entry, sets)
        if reason is None and va >= entry + OFFSET_TAIL:
            try:
                refine_tail(Harness(image, patch), entry)
            except (Halt, EvidenceError) as error:
                reason = "whole-domain tail: %s" % str(error)[:50]
        if reason is None:
            rows.append((va, kind, "survived", EXPECTED_SURVIVORS.get(va - entry, "")))
        else:
            rows.append((va, kind, "killed", reason))
    survivors = sorted(row[0] - entry for row in rows if row[2] == "survived")
    if survivors != sorted(EXPECTED_SURVIVORS):
        raise EvidenceError("survivor list changed: %s" % " ".join("%#x" % offset for offset in survivors))
    return rows


def constant_controls(image, entry, sets):
    rows = []
    for name, at, value in (("factor scale becomes 1e7", SCALE_AT, to_bits(1e7)), ("limit becomes 1.02", LIMIT_AT, to_bits(1.02)),
                            ("limit becomes 1.0", LIMIT_AT, to_bits(1.0)), ("cast bias becomes 2^62", TWO_63_AT, to_bits(2.0 ** 62))):
        harness = Harness(image, None, {at: value})
        reason = run_all(harness, entry, sets)
        rows.append((at, name, "survived" if reason is None else "killed", "" if reason is None else reason))
    return rows


def helper_slots(image, relative, entry):
    low, end = image.exact_fde(entry)
    rows = decode_range(image, low, end)
    direct = sorted({row.target for row in rows if row.op == "call"})
    slots = sorted({row.a[4] for row in rows if row.op == "calli"})
    return direct, [(slot, relative[slot]) for slot in slots]


WORKED = (
    ("quote is token 0, native priced 30.5, factor 1.0", Case(native=1, pairs=(0,), tokens=((8, 8), (2, 8)), tree={1: 3050000}, a=100000000, b=500, factor=100000000)),
    ("same at factor 0.0005", Case(native=1, pairs=(0,), tokens=((8, 8), (2, 8)), tree={1: 3050000}, a=100000000, b=500, factor=50000)),
    ("no price entry: decimal shift only", Case(native=1, pairs=(2,), tokens=((8, 8), (2, 8), (0, 6)), tree=None, a=100000000, b=500)),
    ("quote priced 0.5 with 6 wei decimals", Case(native=1, pairs=(2,), tokens=((8, 8), (2, 8), (0, 6)), tree={1: 3050000, 2: 50000000}, a=100000000, b=500)),
    ("gate keeps the raw product", Case(native=1, pairs=(2,), tokens=((8, 8), (2, 8), (0, 0)), tree={1: 3050000, 2: 3}, a=GATE - 1, b=1)),
    ("ceiling rounds 1 raw unit up", Case(native=1, pairs=(0,), tokens=((8, 8), (2, 8)), tree={1: 3050000}, a=1, b=1)),
)


# ---- analysis ----

def analyse(image, full=True, vectors=6000):
    harness = Harness(image)
    relative = harness.relative
    named = named_cases()
    randoms = random_cases(vectors)
    tables, outcome_rows = {}, []
    helpers = {}
    for entry in COPIES:
        counts = collections.Counter()
        for name, case in named + randoms:
            got = harness.run_case(entry, case)
            want = spec(case, entry)
            if got != want:
                raise EvidenceError("%#x %s: %r != %r" % (entry, name, got, want))
            counts["%s %#x" % (got[0], got[1]) if got[0] in ("tag", "panic", "bounds") else got[0]] += 1
        tables[entry] = counts
        helpers[entry] = helper_slots(image, relative, entry)
        if helpers[entry][0] != [DROP[entry]]:
            raise EvidenceError("unexpected direct callee of %#x" % entry)
    for name, case in named:
        got = spec(case)
        outcome_rows.append((name, got[0], got[1] if len(got) > 1 else ""))
    edges = harness.machine.edges
    branch_rows = []
    missing = []
    for entry in COPIES:
        low, end = image.exact_fde(entry)
        for row in decode_range(image, low, end):
            if row.op in ("jcc", "cmov"):
                taken, skipped = edges[(row.va, True)], edges[(row.va, False)]
                branch_rows.append((row.va, row.va - low, row.op, taken, skipped))
                for direction, count in ((True, taken), (False, skipped)):
                    if not count:
                        missing.append((row.va - low, direction))
    unreached = {}
    for offset, direction in missing:
        unreached[(offset, direction)] = unreached.get((offset, direction), 0) + 1
    if set(unreached) != set(UNREACHED) and vectors >= 500:
        raise EvidenceError("uncovered directions changed: %r" % sorted(unreached))
    instructions = {}
    differences = []
    for other in COPIES[1:]:
        count, found = copy_differences(image, COPIES[0], other)
        instructions[other] = count
        differences.extend((other,) + row for row in found)
    tails, tail_runs = {}, 0
    for entry in COPIES:
        tails[entry], used = refine_tail(harness, entry)
        tail_runs += used
    factor = {entry: factor_edge(harness, entry) for entry in COPIES}
    domains = helper_domains(harness)
    sites = direct_calls(image, set(COPIES))
    worked = []
    for name, case in WORKED:
        got = [harness.run_case(entry, case) for entry in COPIES]
        if len(set(got)) != 1 or got[0] != spec(case):
            raise EvidenceError("worked case differs: %s" % name)
        worked.append((name, got[0][0], got[0][1]))
    result = {
        "named": len(named), "random": len(randoms), "tables": tables, "outcomes": outcome_rows, "branches": branch_rows,
        "unreached": sorted(unreached.items()), "instructions": instructions, "differences": differences, "tails": tails,
        "tail_runs": tail_runs, "factor": factor, "sites": {entry: sites.get(entry, []) for entry in COPIES}, "worked": worked,
        "helpers": helpers, "tags": [(tag,) + tag_text(image, tag) for tag in TAG_TEXTS],
        "tag_sites": {entry: tag_sites(image, entry) for entry in COPIES}, "constants": constant_rows(image),
        "fde": {entry: image.exact_fde(entry) for entry in COPIES + (ONE_PRICE, UNIT, DIVIDE)},
        "locations": {va: image.location(va, relative) for va in (LOCATION_TABLE, LOCATION_POWER, LOCATION_SUB, LOCATION_UNIT, 0x56BB188, 0x573DFC8)},
        "ceiling_edge": ceiling_edge(), "domains": domains,
        "relocated": sorted(va for va in COPIES if va in set(relative.values())),
    }
    if full:
        seen = set(harness.machine.seen)
        sets = named + randoms[:1500]
        result["mutations"] = run_mutants(image, COPIES[0], sets, seen) + constant_controls(image, COPIES[0], sets)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("outcomes.tsv", ("case", "outcome", "value_tag_or_location"),
        [(n, o, "%#x" % v if v != "" else "") for n, o, v in result["outcomes"]])
    tsv("branches.tsv", ("address", "offset", "op", "taken", "not_taken"),
        [("%#x" % va, "%#x" % off, op, a, b) for va, off, op, a, b in result["branches"]])
    tsv("copy-differences.tsv", ("copy", "offset", "first", "this_copy"),
        [("%#x" % c, "%#x" % o, a, b) for c, o, a, b in result["differences"]])
    tsv("tail-pieces.tsv", ("function", "bits_lo", "bits_hi", "out_at_lo", "out_at_hi", "decisions"),
        [("%#x" % entry, "%#x" % lo, "%#x" % hi, "%#x" % a, "%#x" % b, n)
         for entry, rows in sorted(result["tails"].items()) for lo, hi, a, b, n in rows])
    tsv("factor-edge.tsv", ("function", "last_admitted", "first_refused", "real_runs"),
        [("%#x" % entry, low, high, runs) for entry, (low, high, runs) in sorted(result["factor"].items())])
    tsv("examples.tsv", ("case", "outcome", "value"), [(n, o, v) for n, o, v in result["worked"]])
    tsv("tags.tsv", ("tag", "display_arm", "text_at", "text"),
        [("%#x" % t, "%#x" % a, "%#x" % s, x) for t, a, s, x in result["tags"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"),
            [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": ["%#x" % e for e in COPIES],
        "fde": {"%#x" % k: ["%#x" % v[0], "%#x" % v[1], v[1] - v[0]] for k, v in result["fde"].items()},
        "instructions": {"%#x" % k: v for k, v in result["instructions"].items()},
        "copy_differences": len(result["differences"]),
        "call_sites": {"%#x" % k: ["%#x" % s for s in v] for k, v in result["sites"].items()},
        "helpers": {"%#x" % k: {"direct": ["%#x" % d for d in v[0]], "slots": {"%#x" % s: "%#x" % t for s, t in v[1]}} for k, v in result["helpers"].items()},
        "tag_writes": {"%#x" % k: ["%#x:%#x" % row for row in v] for k, v in result["tag_sites"].items()},
        "locations": {"%#x" % k: "%s:%d:%d" % v for k, v in result["locations"].items()},
        "constants": [{"name": n, "address": "%#x" % a, "bits": "%#x" % b, "value": repr(v)} for n, a, b, v in result["constants"]],
        "named_cases": result["named"], "random_cases": result["random"],
        "cases_per_copy": {"%#x" % k: dict(sorted(v.items())) for k, v in result["tables"].items()},
        "unreached_directions": [{"offset": "%#x" % k[0], "taken": k[1], "copies": v, "reason": UNREACHED.get(k, "")} for k, v in result["unreached"]],
        "tail_pieces": {"%#x" % k: len(v) for k, v in result["tails"].items()}, "tail_runs": result["tail_runs"],
        "ceiling_edge": {"value": result["ceiling_edge"][0], "price": result["ceiling_edge"][1]},
        "helper_domains": dict(sorted(result["domains"].items())),
        "functions_with_a_relocated_pointer": ["%#x" % va for va in result["relocated"]],
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
