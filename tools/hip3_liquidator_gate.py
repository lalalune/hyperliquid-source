#!/usr/bin/env python3
"""Pin the node #94 hip3LiquidatorTransfer amount gate from ELF bytes.

Functions 0x27551e0, 0x4d77dc0 and 0x4d77fe0 check the dex name length and the ntl word before the
transfer runs: below i64::MAX / 10, not zero, an exact multiple of 1e9. The real bytes run in a
Python evaluator with only the free, lookup and runner calls stubbed, and a separately written
specification predicts every outcome. The rotate test is shown exact for all 2^64 inputs from its
constants. No objdump or readelf output is parsed, and the binary is never executed. Standard
library only.

    python3 tools/hip3_liquidator_gate.py --out <dir>
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
        elif op == "ror":
            value = self.get(row.a, row.width)
            bits = row.width * 8
            count = self.get(row.b, 1) & (bits - 1)
            value = (value >> count | value << (bits - count)) & MASK[row.width]
            self.put(row.a, row.width, value)
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

COPIES = (
    {"gate": 0x27551E0, "runner": 0x2731870, "wrapper": 0x1E641E0, "registry": 0x5B8},
    {"gate": 0x4D77DC0, "runner": 0x4D3D0F0, "wrapper": 0x46BD030, "registry": 0x1038},
    {"gate": 0x4D77FE0, "runner": 0x4D401D0, "wrapper": 0x46BCF30, "registry": 0x5B8},
)
SLOT_FREE = 0x576E010
SLOT_LOOKUP = 0x5774708
SLOT_ALLOC = 0x576DFD8
SLOT_COPY = 0x576DFE0
SPLIT_TABLE = 0x59A8D0
TAG_OK = 0x186
TAG_DEPOSIT_ZERO = 0x2F
TAG_WITHDRAW_ZERO = 0x30
TAG_BAD_DEX = 0x141
TAG_BAD_NUMBER = 0x13F
TAG_BAD_LENGTH = 0x143
TAG_MULTIPLE = 0x185
TAG_TEXTS = (TAG_DEPOSIT_ZERO, TAG_WITHDRAW_ZERO, TAG_BAD_NUMBER, TAG_BAD_DEX, TAG_BAD_LENGTH, TAG_MULTIPLE)
NAME_LIMIT = 101
CAP = 0x0CCCCCCCCCCCCCCC
INVERSE = 0x8E47CE423A2E9C6D
ROTATE = 9
BOUND = 0x44B82FA0A
STEP = 1000000000
ODD_PART = 5 ** 9
RESULT_SIZE = 0x60
CLOSURE_TAG = 4
LANDING_BRANCH = 0x200
WRAPPER_OK = 0xD
WRAPPER_ERROR = 0xE
ACTION_STRINGS = (b"struct Hip3LiquidatorTransferAction with 3 elements", b"hip3LiquidatorTransfer")

HEAP_USED = 0x4000
OUT = HEAP_BASE + 0x800
USER = HEAP_BASE + 0x900
ACTION = HEAP_BASE + 0x940
RECORD = HEAP_BASE + 0x980
NAME = HEAP_BASE + 0xA00
CLONE = HEAP_BASE + 0xC00
STATE = HEAP_BASE + 0x1000
USER_BYTES = bytes(range(0x31, 0x45))
FREE_MARK = 0xD0000001
ALLOC_MARK = 0xD0000002
COPY_MARK = 0xD0000003


class Case:
    __slots__ = ("size", "capacity", "ntl", "flag", "lookup", "dex")

    def __init__(self, ntl=STEP, flag=1, size=3, capacity=3, lookup=True, dex=1):
        self.size, self.capacity, self.ntl, self.flag = size, capacity, ntl, flag
        self.lookup, self.dex = lookup, dex


def spec(case):
    """Outcome as (kind, tag, word at +8 or None, freed name bytes capacity)."""
    freed = case.capacity
    if case.size >= NAME_LIMIT:
        return ("tag", TAG_BAD_LENGTH, None, freed)
    if case.ntl >= CAP:
        return ("tag", TAG_BAD_NUMBER, case.ntl, freed)
    if case.ntl == 0:
        return ("tag", TAG_DEPOSIT_ZERO if case.flag else TAG_WITHDRAW_ZERO, None, freed)
    if case.ntl % STEP:
        return ("tag", TAG_MULTIPLE, None, freed)
    if not case.lookup:
        return ("passed", None, None, freed)
    if case.dex == 0:
        return ("tag", TAG_BAD_DEX, None, freed)
    return ("runner", TAG_OK, None, 0)


def lookup_error_bytes():
    return bytes((index * 37 + 11) & 0xFF for index in range(RESULT_SIZE))


class Harness:
    def __init__(self, image, copy, patches=None, statics=None):
        self.image = image
        self.copy = copy
        self.machine = Traced(image, patches)
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        memory = self.machine.memory
        marks = {}
        for slot, mark, hook in ((SLOT_FREE, FREE_MARK, self.on_free), (SLOT_LOOKUP, None, self.on_lookup),
                                 (SLOT_ALLOC, ALLOC_MARK, self.on_alloc), (SLOT_COPY, COPY_MARK, self.on_copy)):
            target = relative.get(slot, mark)
            if target is None:
                raise EvidenceError("slot without a relocation: %#x" % slot)
            memory.statics[slot] = target
            marks[target] = hook
        if statics:
            memory.statics.update(statics)
        self.lookup_target = relative[SLOT_LOOKUP]
        self.machine.slots = marks
        self.machine.calls = {copy["runner"]: self.on_runner}
        self.case = None
        self.freed = []
        self.runner_calls = 0
        self.lookup_calls = 0

    def on_free(self, machine):
        self.freed.append((machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_lookup(self, machine):
        self.lookup_calls += 1
        regs = machine.regs
        memory = machine.memory
        if regs[RSI] != STATE + self.copy["registry"] or regs[RDX] != self.name or regs[RCX] != self.case.size:
            raise Halt("lookup arguments differ")
        if self.case.lookup:
            memory.write(regs[RDI], 2, TAG_OK)
            memory.write(regs[RDI] + 8, 8, RECORD)
        else:
            memory.put_bytes(regs[RDI], lookup_error_bytes())

    def on_runner(self, machine):
        """The only success exit: read the whole argument set the closure later takes apart."""
        self.runner_calls += 1
        regs = machine.regs
        memory = machine.memory
        case = self.case
        if regs[RDI] != OUT or regs[RSI] != STATE or regs[RCX] != case.dex:
            raise Halt("runner state or dex arguments differ")
        if memory.bytes_at(regs[RDX], 20) != USER_BYTES:
            raise Halt("runner user copy differs")
        if memory.read(regs[R8], 8) != CLOSURE_TAG:
            raise Halt("runner tag word differs")
        words = [memory.read(regs[R9] + 8 * index, 8) for index in range(7)]
        if words[:3] != [case.capacity, self.name, case.size] or words[4] != USER:
            raise Halt("closure name or user words differ")
        if memory.read(words[3], 8) != case.dex or memory.read(words[5], 8) != case.ntl or memory.read(words[6], 1) != case.flag:
            raise Halt("closure value pointers differ")
        memory.write(OUT, 2, TAG_OK)

    def on_alloc(self, machine):
        if machine.regs[RDI] != self.case.size:
            raise Halt("clone size differs")
        machine.regs[RAX] = CLONE

    def on_copy(self, machine):
        regs = machine.regs
        if regs[RSI] != self.name or regs[RDX] != self.case.size:
            raise Halt("clone source differs")
        self.copied = (regs[RDI], regs[RDX])

    def on_gate(self, machine):
        regs = machine.regs
        memory = machine.memory
        case = self.case
        if regs[RSI] != STATE or regs[RDX] != USER:
            raise Halt("wrapper gate arguments differ")
        owned = [memory.read(regs[RCX] + 8 * index, 8) for index in range(3)]
        if owned != [case.size, CLONE if case.size else 1, case.size]:
            raise Halt("wrapper name copy differs: %r" % (owned,))
        if memory.read(regs[RCX] + 0x18, 8) != case.ntl or memory.read(regs[RCX] + 0x20, 1) != case.flag:
            raise Halt("wrapper ntl or flag differs")
        if self.gate_result is None:
            memory.write(regs[RDI], 2, TAG_OK)
        else:
            memory.put_bytes(regs[RDI], self.gate_result)

    def prepare(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_USED)
        memory.put_bytes(USER, USER_BYTES)
        memory.write(RECORD + 0x30, 8, case.dex)
        self.case = case
        self.name = NAME if case.size or case.capacity else 1
        self.freed = []
        self.runner_calls = self.lookup_calls = 0

    def run_case(self, case):
        self.prepare(case)
        machine = self.machine
        memory = machine.memory
        memory.write(ACTION, 8, case.capacity)
        memory.write(ACTION + 8, 8, self.name)
        memory.write(ACTION + 0x10, 8, case.size)
        memory.write(ACTION + 0x18, 8, case.ntl)
        memory.write(ACTION + 0x20, 1, case.flag)
        result = machine.run(self.copy["gate"], {RDI: OUT, RSI: STATE, RDX: USER, RCX: ACTION})
        if result != OUT:
            raise Halt("rax is not the out pointer")
        tag = memory.read(OUT, 2)
        freed = 0
        if self.freed:
            if len(self.freed) != 1 or self.freed[0] != (self.name, case.capacity, 0):
                raise Halt("name free differs: %r" % (self.freed,))
            freed = case.capacity
        elif case.capacity and not self.runner_calls:
            raise Halt("name leaked on an error path")
        if self.runner_calls:
            if self.runner_calls != 1 or self.lookup_calls != 1 or self.freed:
                raise Halt("runner path differs")
            return ("runner", tag, None, 0)
        if self.lookup_calls and memory.bytes_at(OUT, RESULT_SIZE) == lookup_error_bytes():
            return ("passed", None, None, freed)
        word = None
        rest = memory.bytes_at(OUT + 2, RESULT_SIZE - 2)
        if tag == TAG_BAD_NUMBER:
            word = memory.read(OUT + 8, 8)
            rest = rest[:6] + rest[14:]
        if rest != bytes([STACK_MARK]) * len(rest):
            raise Halt("error result wrote more than its fields")
        return ("tag", tag, word, freed)

    def run_wrapper(self, case, gate_result):
        """The action wrapper: clone the name, call the gate, wrap the result."""
        self.prepare(case)
        self.gate_result = gate_result
        self.copied = None
        machine = self.machine
        memory = machine.memory
        memory.write(ACTION + 8, 8, self.name)
        memory.write(ACTION + 0x10, 8, case.size)
        memory.write(ACTION + 0x18, 8, case.ntl)
        memory.write(ACTION + 0x20, 1, case.flag)
        saved = dict(machine.calls)
        machine.calls = {self.copy["gate"]: self.on_gate}
        try:
            result = machine.run(self.copy["wrapper"], {RDI: OUT, RSI: ACTION, RDX: USER, RCX: STATE})
        finally:
            machine.calls = saved
        if result != OUT or self.copied != (CLONE if case.size else 1, case.size):
            raise Halt("wrapper clone or result differs")
        kind = memory.read(OUT, 1)
        if gate_result is None:
            if kind != WRAPPER_OK or memory.bytes_at(OUT + 1, RESULT_SIZE + 7) != bytes([STACK_MARK]) * (RESULT_SIZE + 7):
                raise Halt("wrapper ok result differs")
        elif kind != WRAPPER_ERROR or memory.bytes_at(OUT + 8, RESULT_SIZE) != gate_result:
            raise Halt("wrapper error result differs")
        return kind


class Traced(Machine):
    def __init__(self, image, patches=None):
        super().__init__(image, patches)
        self.edges = collections.Counter()

    def step(self, row):
        if row.op in ("jcc", "cmov"):
            self.edges[(row.va, self.condition(row.cc))] += 1
        return super().step(row)


# ---- vectors ----

FIRST_ESCAPE = STEP * BOUND & MASK[8]
TOP_MULTIPLE = (CAP - 1) // STEP * STEP


def named_cases():
    return [
        ("one multiple, deposit flag", Case(STEP, 1)),
        ("one multiple, withdraw flag", Case(STEP, 0)),
        ("two multiples", Case(2 * STEP)),
        ("largest admitted multiple", Case(TOP_MULTIPLE)),
        ("zero, deposit flag", Case(0, 1)),
        ("zero, withdraw flag", Case(0, 0)),
        ("one raw unit", Case(1)),
        ("step minus one", Case(STEP - 1)),
        ("step plus one", Case(STEP + 1)),
        ("half a step", Case(STEP // 2)),
        ("power of two below the step", Case(512)),
        ("multiple of 5^9, not of 2^9", Case(ODD_PART)),
        ("multiple of 2^9, not of 5^9", Case(1 << 20)),
        ("first value past the bound after the rotate", Case(FIRST_ESCAPE)),
        ("cap minus one", Case(CAP - 1)),
        ("cap", Case(CAP)),
        ("cap plus one", Case(CAP + 1)),
        ("first multiple at or past the cap", Case(TOP_MULTIPLE + STEP)),
        ("largest u64 multiple of the step", Case(((1 << 64) - 1) // STEP * STEP)),
        ("top bit set", Case(1 << 63)),
        ("u64 maximum", Case(MASK[8])),
        ("empty name", Case(STEP, 1, 0, 0)),
        ("name length 100", Case(STEP, 1, 100, 100)),
        ("name length 101", Case(STEP, 1, 101, 101)),
        ("name length 101, no capacity", Case(STEP, 1, 101, 0)),
        ("name length 200, bad ntl", Case(1, 1, 200, 200)),
        ("name length 101 beats cap", Case(CAP, 1, 101, 101)),
        ("name length 101 beats zero", Case(0, 1, 101, 101)),
        ("empty name, zero ntl", Case(0, 0, 0, 0)),
        ("cap beats a failed lookup", Case(CAP, 1, 3, 3, False)),
        ("zero beats a failed lookup", Case(0, 1, 3, 3, False)),
        ("non-multiple beats a failed lookup", Case(1, 1, 3, 3, False)),
        ("failed lookup", Case(STEP, 1, 3, 3, False)),
        ("failed lookup, no capacity", Case(STEP, 1, 0, 0, False)),
        ("dex 0", Case(STEP, 1, 3, 3, True, 0)),
        ("dex 0, no capacity", Case(STEP, 1, 0, 0, True, 0)),
        ("dex 0, withdraw flag", Case(STEP, 0, 3, 3, True, 0)),
        ("dex 1", Case(STEP, 1, 3, 3, True, 1)),
        ("dex large", Case(STEP, 0, 3, 3, True, 1 << 40)),
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
        multiple = (1 + pick(TOP_MULTIPLE // STEP)) * STEP
        ntl = (multiple, multiple, multiple + 1, multiple - 1, multiple + pick(STEP), pick(STEP), next(source), CAP + pick(1 << 20), CAP - pick(1 << 20),
               0)[pick(10)]
        size = (3, pick(101), 100 + pick(4), pick(300))[pick(4)]
        capacity = (size, size, size + pick(9), 0)[pick(4)]
        rows.append(("random %d" % serial, Case(ntl, pick(2), size, capacity, bool(pick(5)), (0, 1, 2 + pick(9), next(source))[pick(4)])))
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

def multiple_proof():
    """Why the rotate test is exact for every u64, from the constants alone."""
    if STEP != ODD_PART << ROTATE:
        raise EvidenceError("step is not 5^9 times 2^9")
    if INVERSE * ODD_PART & MASK[8] != 1:
        raise EvidenceError("multiplier is not the inverse of 5^9")
    if BOUND != MASK[8] // STEP + 1:
        raise EvidenceError("bound is not the count of multiples")
    if BOUND >= 1 << (64 - ROTATE):
        raise EvidenceError("rotate would wrap a quotient")
    return {"step": STEP, "odd_part": ODD_PART, "rotate": ROTATE, "multiplier": "%#x" % INVERSE, "bound": BOUND,
            "multiples_in_u64": MASK[8] // STEP + 1}


def rotated(value):
    product = value * INVERSE & MASK[8]
    return (product >> ROTATE | product << (64 - ROTATE)) & MASK[8]


def preimage(value):
    """Inverse of `rotated`, so the bijection claim is checked in both directions."""
    product = (value << ROTATE | value >> (64 - ROTATE)) & MASK[8]
    return product * ODD_PART & MASK[8]


def bijection_samples():
    source = lcg(0xA0761D6478BD642F)
    rows = 0
    for _ in range(20000):
        value = next(source)
        if preimage(rotated(value)) != value or rotated(preimage(value)) != value:
            raise EvidenceError("rotate map is not inverted at %#x" % value)
        rows += 1
    for quotient in (0, 1, 2, BOUND // 2, BOUND - 1):
        if rotated(quotient * STEP) != quotient:
            raise EvidenceError("multiple does not map to its quotient: %d" % quotient)
        rows += 1
    if rotated(FIRST_ESCAPE) != BOUND:
        raise EvidenceError("first value past the bound differs")
    return rows + 1


def amount_classes():
    above = (1 << 64) - CAP
    admitted = (CAP - 1) // STEP
    plain = CAP - 1 - admitted
    if 1 + admitted + plain + above != 1 << 64:
        raise EvidenceError("classes do not cover u64")
    return [
        ("zero", 0, 0, 1, "tag 0x2f or 0x30 by flag"),
        ("below the cap, not a multiple", 1, CAP - 1, plain, "tag 0x185"),
        ("below the cap, a multiple", STEP, TOP_MULTIPLE, admitted, "lookup, then runner"),
        ("cap and above", CAP, MASK[8], above, "tag 0x13f with the value"),
    ]


def class_runs(harness):
    """Real bytes at the ends of each class and at spread interior points."""
    runs = 0
    for lo, hi in ((1, STEP - 1), (STEP + 1, 2 * STEP - 1), (TOP_MULTIPLE + 1, CAP - 1)):
        for value in [lo, hi] + [lo + (hi - lo) * index // 65 for index in range(1, 65)]:
            case = Case(value)
            if harness.run_case(case) != spec(case):
                raise EvidenceError("non-multiple class differs at %#x" % value)
            runs += 1
    for quotient in [1, 2, TOP_MULTIPLE // STEP] + [1 + (TOP_MULTIPLE // STEP - 1) * index // 65 for index in range(1, 65)]:
        case = Case(quotient * STEP)
        if harness.run_case(case) != spec(case):
            raise EvidenceError("multiple class differs at %d" % quotient)
        runs += 1
    for value in [CAP, MASK[8]] + [CAP + (MASK[8] - CAP) * index // 65 for index in range(1, 65)]:
        case = Case(value)
        if harness.run_case(case) != spec(case):
            raise EvidenceError("top class differs at %#x" % value)
        runs += 1
    return runs


AMOUNT_READS = (
    (0x0, "push"), (0x14, "mov"), (0x59, "cmp"), (0x5E, "test"), (0x6D, "imul2"), (0x90, "mov"), (0x115, "mov"), (0xB7, "pop"),
)


def uses(row, register):
    for operand in (row.a, row.b):
        if not operand:
            continue
        if operand[0] == "r" and operand[1] == register:
            return True
        if operand[0] == "m" and register in (operand[1], operand[2]):
            return True
    return False


def amount_uses(image, gate):
    """Every instruction that names rbp in one copy: the ntl word has no other reader."""
    low, high = image.exact_fde(gate)
    rows = decode_range(image, low, high)
    found = []
    for row in rows:
        if uses(row, RBP) or (row.op in ("push", "pop") and row.a == ("r", RBP)):
            found.append((row.va - gate, row.op))
    return found, len(rows)


def state_reads(image, gate):
    """Memory operands based on the state pointer (r15 after entry) other than lea: the gate reads none."""
    low, high = image.exact_fde(gate)
    found = []
    for row in decode_range(image, low, high):
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and R15 in (operand[1], operand[2]) and row.op != "lea":
                found.append(row.va)
    return found


def constants_of(image, gate):
    """The three 64-bit immediates of a copy, in code order, with the rotate count."""
    low, high = image.exact_fde(gate)
    rows = decode_range(image, low, high)
    wide = [row.b[1] & MASK[8] for row in rows if row.op == "mov" and row.b and row.b[0] == "i" and row.imm_size == 8]
    turns = [row.b[1] for row in rows if row.op == "ror"]
    names = [row.b[1] & MASK[4] for row in rows if row.op == "cmp" and row.b and row.b[0] == "i" and row.a == ("r", R12)]
    if wide != [CAP, INVERSE, BOUND] or turns != [ROTATE] or names != [NAME_LIMIT]:
        raise EvidenceError("constants changed in %#x: %r %r %r" % (gate, wide, turns, names))
    return wide, turns[0], names[0]


def copy_differences(image):
    """Row by row against the first copy: only the registry offset and the runner call may differ."""
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
        for left, right in zip(base_rows, other):
            shift = low - base_low
            if left.va + shift != right.va or left.op != right.op or left.size != right.size:
                raise EvidenceError("copy shape differs at %#x" % right.va)
            if left.op in ("jcc", "jmp") or (left.op == "call" and left.target != first["runner"] and left.target - base_low < base_high - base_low):
                if left.target + shift != right.target:
                    raise EvidenceError("copy branch differs at %#x" % right.va)
                continue
            if left.op == "call" and left.target == first["runner"]:
                if right.target != copy["runner"]:
                    raise EvidenceError("copy runner differs at %#x" % right.va)
                differing.append((right.va, "runner call"))
                continue
            if left.rip_at is not None:
                if rip_target(image, left) != rip_target(image, right):
                    raise EvidenceError("copy slot differs at %#x" % right.va)
                continue
            if (left.a, left.b, left.width, left.cc) != (right.a, right.b, right.width, right.cc):
                if left.op == "lea" and left.b[4] == first["registry"] and right.b[4] == copy["registry"]:
                    differing.append((right.va, "registry offset %#x" % copy["registry"]))
                    continue
                raise EvidenceError("copy operand differs at %#x" % right.va)
        rows.append((copy["gate"], first["gate"], len(other), differing))
    return rows


def rip_target(image, row):
    return row.next + struct.unpack_from("<i", image.blob, image.offset(row.va + row.rip_at))[0]


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


def indirect_targets(image, targets):
    """Pointers to these functions in .rela.dyn, and any `call [rip+x]` through them."""
    slots = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8 and addend in targets}
    if not slots:
        return []
    base, text = image.text_bytes()
    found = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] in slots:
            found.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return found


def tag_writes(image, tag):
    """Fixed 16-bit tag writes in .text: `mov $imm16, r16` and `movw $imm16, mem`, by byte shape."""
    base, text = image.text_bytes()
    word = re.escape(struct.pack("<H", tag))
    shapes = rb"\x66[\xb8-\xbf]" + word + rb"|\x66\x41[\xb8-\xbf]" + word + rb"|\x66(?:\x41)?\xc7[\x00-\xff]{1,3}" + word
    return sorted(base + match.start() for match in re.finditer(shapes, text))


def string_rows(image):
    rows = []
    for want in ACTION_STRINGS:
        at = image.blob.find(want)
        if at < 0 or image.offset(at) != at:
            raise EvidenceError("string missing: %r" % want)
        rows.append((at, want.decode("ascii")))
    return rows


def field_list(image):
    """The serde field list: three (pointer, length) rows starting with dex then ntl."""
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    lists = []

    def text_of(slot):
        size = struct.unpack_from("<Q", image.blob, image.offset(slot + 8))[0]
        if size > 64:
            return None
        start = image.offset(relative[slot])
        return bytes(image.blob[start:start + size])

    for slot in sorted(relative):
        if slot + 16 not in relative or relative[slot] < 0x1000:
            continue
        try:
            head = image.offset(relative[slot])
        except EvidenceError:
            continue
        if image.blob[head:head + 3] != b"dex":
            continue
        try:
            if text_of(slot) != b"dex" or text_of(slot + 16) != b"ntl":
                continue
            lists.append((slot, [text_of(slot + 16 * index).decode("ascii") for index in range(3)]))
        except (EvidenceError, KeyError, struct.error):
            continue
    return lists


# ---- mutation controls ----

EXPECTED_SURVIVORS = {}


def mutation_targets(image, gate, seen):
    low, high = image.exact_fde(gate)
    edits = []
    for row in decode_range(image, low, high):
        if row.va not in seen:
            continue
        data = image.blob[image.offset(row.va):image.offset(row.va) + row.size]
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
        elif row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        elif row.op == "ror":
            edits.append((row.va, "rotate", {row.va + row.size - 1: data[row.size - 1] ^ 1}))
    return edits


def run_mutants(image, sets, seen):
    rows = []
    for copy in COPIES:
        for va, kind, patch in mutation_targets(image, copy["gate"], seen):
            harness = Harness(image, copy, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            reason = run_all(harness, sets)
            offset = va - copy["gate"]
            if reason is None:
                rows.append((va, offset, kind, "survived", EXPECTED_SURVIVORS.get(offset, "")))
            else:
                rows.append((va, offset, kind, "killed", reason))
    survivors = sorted({row[1] for row in rows if row[3] == "survived"})
    if survivors != sorted(EXPECTED_SURVIVORS):
        raise EvidenceError("survivor list changed: %s" % " ".join("%#x" % offset for offset in survivors))
    return rows


# ---- analysis ----

WRAPPER_CASES = (
    ("gate success", Case(STEP), None),
    ("gate error", Case(STEP), bytes((index * 11 + 3) & 0xFF for index in range(RESULT_SIZE))),
    ("empty name", Case(STEP, 0, 0, 0), None),
)


def analyse(image, full=True, vectors=4000):
    named = named_cases()
    randoms = random_cases(vectors)
    counts = collections.Counter()
    seen = set()
    branch_rows, missing = [], []
    copies = []
    runs = 0
    wrappers = []
    for copy in COPIES:
        harness = Harness(image, copy)
        for name, case in named + randoms:
            got = harness.run_case(case)
            want = spec(case)
            if got != want:
                raise EvidenceError("%#x %s: %r != %r" % (copy["gate"], name, got, want))
            counts["%#x %s" % (got[1], got[0]) if got[1] is not None else got[0]] += 1
        runs += class_runs(harness)
        seen |= harness.machine.seen
        edges = harness.machine.edges
        low, high = image.exact_fde(copy["gate"])
        for row in decode_range(image, low, high):
            if row.op == "jcc":
                taken, skipped = edges[(row.va, True)], edges[(row.va, False)]
                branch_rows.append((row.va, row.va - low, taken, skipped))
                for direction, count in ((True, taken), (False, skipped)):
                    if not count:
                        missing.append("%#x:%s" % (row.va, direction))
        for name, case, result in WRAPPER_CASES:
            kind = harness.run_wrapper(case, result)
            wrappers.append(("%#x" % copy["wrapper"], name, "%#x" % kind))
        reads, count = amount_uses(image, copy["gate"])
        if tuple(sorted(reads)) != tuple(sorted(AMOUNT_READS)):
            raise EvidenceError("ntl readers changed in %#x: %r" % (copy["gate"], reads))
        if state_reads(image, copy["gate"]):
            raise EvidenceError("state read in %#x" % copy["gate"])
        wide, rotate, limit = constants_of(image, copy["gate"])
        sites = direct_calls(image, copy["gate"])
        if len(sites) != 1 or image.fde(sites[0])[0] != copy["wrapper"]:
            raise EvidenceError("caller changed: %#x" % copy["gate"])
        copies.append((copy["gate"], low, high, high - low, count, "%#x" % copy["registry"], copy["runner"], copy["wrapper"], sites[0]))
    lists = field_list(image)
    if not lists or any(names != ["dex", "ntl", "isDeposit"] for _, names in lists):
        raise EvidenceError("field lists changed: %r" % (lists,))
    named_rows = [(name,) + tuple("" if cell is None else "%#x" % cell if isinstance(cell, int) else cell for cell in spec(case)) for name, case in named]
    result = {
        "named": len(named), "random": len(randoms), "counts": counts, "outcomes": named_rows, "branches": branch_rows, "missing": missing,
        "copies": copies, "differences": copy_differences(image), "proof": multiple_proof(), "bijection": bijection_samples(),
        "classes": amount_classes(), "class_runs": runs, "wrappers": wrappers, "reads": AMOUNT_READS,
        "tag_sites": tag_writes(image, TAG_MULTIPLE), "tags": [(tag,) + tag_text(image, tag) for tag in TAG_TEXTS], "strings": string_rows(image), "fields": lists,
        "indirect": indirect_targets(image, {copy["gate"] for copy in COPIES}), "lookup": Harness(image, COPIES[0]).lookup_target,
    }
    if [image.fde(at)[0] for at in result["tag_sites"]] != sorted(copy["gate"] for copy in COPIES):
        raise EvidenceError("tag 0x185 writers changed: %r" % (result["tag_sites"],))
    if result["indirect"]:
        raise EvidenceError("gate reached through a pointer: %r" % (result["indirect"],))
    if sorted(missing) != sorted("%#x:%s" % (copy["gate"] + LANDING_BRANCH, way) for copy in COPIES for way in (True, False)):
        raise EvidenceError("uncovered branch directions changed: %s" % " ".join(missing))
    if full:
        sets = named + randoms[:600]
        result["mutations"] = run_mutants(image, sets, seen)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("gate-copies.tsv", ("gate", "fde_start", "fde_end", "bytes", "instructions", "registry_offset", "runner", "wrapper", "call_site"),
        [("%#x" % a, "%#x" % b, "%#x" % c, d, e, f, "%#x" % g, "%#x" % h, "%#x" % i) for a, b, c, d, e, f, g, h, i in result["copies"]])
    tsv("copy-differences.tsv", ("copy", "compared_with", "instructions", "address", "difference"),
        [("%#x" % a, "%#x" % b, n, "%#x" % va, what) for a, b, n, rows in result["differences"] for va, what in rows])
    tsv("outcomes.tsv", ("case", "outcome", "tag", "word_at_8", "freed_capacity"), result["outcomes"])
    tsv("amount-classes.tsv", ("class", "lowest", "highest", "values", "result"), result["classes"])
    tsv("branches.tsv", ("address", "offset", "taken", "not_taken"), [("%#x" % va, "%#x" % off, a, b) for va, off, a, b in result["branches"]])
    tsv("wrappers.tsv", ("wrapper", "case", "first_result_byte"), result["wrappers"])
    tsv("tags.tsv", ("tag", "display_arm", "text_at", "text"), [("%#x" % t, "%#x" % a, "%#x" % s, x) for t, a, s, x in result["tags"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "offset", "kind", "outcome", "detail"),
            [("%#x" % va, "%#x" % off, kind, outcome, detail) for va, off, kind, outcome, detail in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "named_cases": result["named"], "random_cases": result["random"],
        "runs_per_outcome": dict(sorted(result["counts"].items())), "class_runs": result["class_runs"],
        "rotate_proof": result["proof"], "rotate_samples": result["bijection"], "ntl_cap": "%#x" % CAP, "ntl_cap_decimal": CAP,
        "lookup_slot": "%#x" % SLOT_LOOKUP, "lookup_target": "%#x" % result["lookup"], "state_memory_reads": 0,
        "largest_admitted_ntl": TOP_MULTIPLE, "admitted_values": (CAP - 1) // STEP, "first_value_past_bound": FIRST_ESCAPE,
        "uncovered_directions": sorted(result["missing"]), "name_limit_exclusive": NAME_LIMIT, "ntl_readers_by_offset": ["%#x %s" % row for row in sorted(result["reads"])],
        "strings": [{"at": "%#x" % a, "text": t} for a, t in result["strings"]], "tag_0x185_writes": ["%#x" % at for at in result["tag_sites"]],
        "field_lists": {"at": ["%#x" % slot for slot, _ in result["fields"]], "names": result["fields"][0][1]},
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[3] == "killed"),
                                "survived": sum(1 for r in rows if r[3] == "survived")}
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
