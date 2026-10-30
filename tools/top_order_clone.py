#!/usr/bin/env python3
"""Pin the node #94 top-order clone from ELF bytes.

`0x49e3930` picks one side tree of a book, walks to its first level, reads the slab index of the
level's head and clones that 0xf8-byte slab slot. `0x4a06f70` does this for both sides. The real
bytes of both functions run in a Python evaluator with only the allocator, memcpy and the panic
entry stubbed, and a separately written specification predicts every output byte. Every condition
and immediate is then flipped to show the run can tell. No objdump or readelf output is parsed,
and the binary is never executed. Standard library only.
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

CLONE = 0x49E3930
PAIR = 0x4A06F70
CHECKS = (0x42FC790, 0x42FD530)
GOT_MALLOC = 0x576DFD8
GOT_MEMCPY = 0x576DFE0
GOT_ALLOC_ERROR = 0x576DFB8
GOT_PANIC = 0x576E470
LOCATION_EMPTY = 0x5736298
LOCATION_LEVEL = 0x57362B0
LOCATION_SLOT = 0x57362C8
LOCATION_NO_PARENT = 0x5733F50
SIDE_NONZERO = 0x80
SIDE_ZERO = 0x98
SLOT_STRIDE = 0xF8
SLOT_SIZE = 0xF8
VACANT = 2
VALUE_STRIDE = 0x20
NODE_PARENT = 0x160
NODE_PARENT_INDEX = 0x1C0
NODE_LEN = 0x1C2
NODE_EDGES = 0x1C8
VECTOR_LIMIT = 0x7FFFFFFFFFFFFFF8
# Bytes the function never writes keep this marker; bytes it takes from its own stack keep POISON's.
OUTPUT_MARK = 0x5A
STACK_MARK = 0xA5
EMPTY_VECTOR = 8

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x100000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 5000


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
        value = immediate(8 if wide else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
    if byte == 0x69:
        reg, rm = modrm()
        value = immediate(4)
        return finish("imul3", ("r", reg), rm, width, target=value)
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
        if kind in (2, 3, 4):
            return finish({2: "not", 3: "neg", 4: "mul"}[kind], rm, w=w)
        raise EvidenceError("unsupported group 3 opcode at %#x" % va)
    if byte in (0xFE, 0xFF):
        reg, rm = modrm()
        kind = reg & 7
        w = 1 if byte == 0xFE else width
        if kind in (0, 1):
            return finish("inc" if kind == 0 else "dec", rm, w=w)
        if byte == 0xFF and kind == 2:
            return finish("calli", rm, w=8)
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
        vector = {(0x14, False): "unpcklps", (0x57, False): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd", (0x74, True): "pcmpeqb",
                  (0xDB, True): "pand"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x5E) and repne:
            reg, rm = modrm(True)
            return finish("addsd" if two == 0x58 else "divsd", ("x", reg), rm, 8)
        if two == 0x6E and opsize:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 8 if wide else 4)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
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
        self.xmm = [0] * 16
        self.cf = self.zf = self.sf = self.of = False
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
            5: None, 6: self.sf != self.of, 7: self.zf or self.sf != self.of,
        }[code >> 1]
        if result is None:
            raise Halt("parity condition is not modelled")
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
        self.xmm = [POISON] * 16

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
        elif op == "calli":
            hook = self.slots.get(self.get(row.a, 8))
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
            count = row.b[1] & (63 if width == 8 else 31)
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
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))
        return row.next

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# Why a mutant row no case reached stays unreached: (first va, last va inclusive, reason).
UNREACHED_GROUPS = (
    (0x4303D8B, 0x4303D94, "unwind cleanup"),
    (0x44515CF, 0x44515CF, "empty vector with capacity"),
    (0x4451671, 0x4451673, "unwind cleanup"),
    (0x4451F2B, 0x4451F2B, "empty vector with capacity"),
    (0x4451FCB, 0x4451FCD, "unwind cleanup"),
    (0x48865B3, 0x4886633, "leaf set up at the loop head"),
    (0x4886A17, 0x4886A17, "allocation failure"),
    (0x4886A34, 0x4886A3B, "unwind cleanup"),
    (0x4871543, 0x48715C2, "leaf set up at the loop head"),
    (0x487173F, 0x4871744, "allocation failure"),
    (0x487175C, 0x4871763, "unwind cleanup"),
)


def lcg(variant):
    state = variant & MASK[8]
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK[8]
        yield state >> 32


# ---- slot clone map: (offset, size, rule) ----

SLOT_MAP = (
    (0x00, 8, "copy"), (0x08, 8, "copy"), (0x10, 8, "copy"), (0x18, 8, "copy"), (0x20, 8, "copy"), (0x28, 8, "copy"),
    (0x30, 8, "copy"), (0x38, 8, "copy"), (0x40, 8, "copy"), (0x48, 8, "copy"),
    (0x50, 8, "capacity rebuilt from length"), (0x58, 8, "pointer to a new buffer"), (0x60, 8, "copy"),
    (0x68, 8, "tag rebuilt: 1 if low 32 bits equal 1, else 0"), (0x70, 0x20, "copied only when tag +0x68 is 1"),
    (0x90, 0x10, "copy"), (0xA0, 8, "copy"), (0xA8, 8, "copy"), (0xB0, 1, "copy"),
    (0xB1, 1, "tag rebuilt: 1 if byte equals 1, else 0"), (0xB2, 0x10, "copied only when tag +0xb1 is 1"),
    (0xC2, 1, "copy"), (0xC3, 5, "not written"), (0xC8, 0x10, "copy"), (0xD8, 8, "copy"), (0xE0, 0x10, "copy"),
    (0xF0, 4, "copy"), (0xF4, 1, "copy"), (0xF5, 1, "copy"), (0xF6, 2, "not written"),
)


class Tree:
    """The leftmost path of one side tree, leaf first: node lengths and parent indexes per level."""
    __slots__ = ("root", "field", "height", "lens", "parents", "level_flag", "index")

    def __init__(self, height=0, lens=None, parents=None, level_flag=1, index=1, root=True, field=1):
        self.root, self.field, self.height = root, field, height
        self.lens = list(lens) if lens else [1] * (height + 1)
        self.parents = list(parents) if parents else [0] * (height + 1)
        self.level_flag, self.index = level_flag, index


class Case:
    __slots__ = ("label", "flag", "tree", "other", "slab_len", "tag", "children", "tag68", "tagb1", "salt")

    def __init__(self, label, flag=1, tree=None, **fields):
        self.label, self.flag = label, flag
        self.tree = tree or Tree()
        self.other = Tree(index=2)
        self.slab_len = 4
        self.tag, self.children, self.tag68, self.tagb1, self.salt = 0, 3, 1, 1, 7
        for name, value in fields.items():
            setattr(self, name, value)


def slot_bytes(index, case):
    """Source bytes, all different per offset and per slot; the fields under test are set after."""
    body = bytearray((offset * 13 + case.salt + index * 29) & 0xFF for offset in range(SLOT_SIZE))
    struct.pack_into("<Q", body, 0x00, case.tag)
    struct.pack_into("<Q", body, 0x60, case.children)
    struct.pack_into("<Q", body, 0x68, case.tag68)
    body[0xB1] = case.tagb1
    return bytes(body)


CHILD_FILL = 0x1122334455667700
SLAB = HEAP_BASE + 0x1000
SLAB_ROOM = 8
OUTPUT = HEAP_BASE + 0x200
OUTPUT_ROOM = 0x400
BOOK = HEAP_BASE
NODE_SIZE = NODE_EDGES + 12 * 8


class Harness:
    """Lay one case out, stub the allocator, memcpy and panics, and run the real bytes."""

    def __init__(self, image, patches=None):
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((CLONE,))
        machine.slots = {GOT_MALLOC: self.on_malloc, GOT_MEMCPY: self.on_copy, GOT_ALLOC_ERROR: self.on_alloc_error,
                         GOT_PANIC: self.on_panic}
        machine.memory.statics = {slot: slot for slot in machine.slots}
        self.brk = HEAP_BASE + HEAP_SIZE
        self.allocated = []
        self.sources = {}

    def carve(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise EvidenceError("case does not fit the heap")
        return at

    def build_tree(self, at, tree):
        memory = self.machine.memory
        memory.write(at + 8, 8, tree.height)
        memory.write(at + 16, 8, tree.field)
        if not tree.root:
            memory.write(at, 8, 0)
            return
        child, nodes = 0, []
        for level in range(tree.height + 1):
            node = self.carve(NODE_SIZE)
            nodes.append(node)
            for position in range(11):
                memory.write(node + position * VALUE_STRIDE, 1, 0)
                memory.write(node + position * VALUE_STRIDE + 8, 8, SLAB_ROOM - 1)
            memory.write(node + NODE_LEN, 2, tree.lens[level])
            memory.write(node + NODE_PARENT_INDEX, 2, tree.parents[level])
            memory.write(node + NODE_PARENT, 8, 0)
            if child:
                memory.write(child + NODE_PARENT, 8, node)
                memory.write(node + NODE_EDGES, 8, child)
            child = node
        memory.write(at, 8, child)
        place = find_level(tree)
        if place:
            value = nodes[place[0]] + place[1] * VALUE_STRIDE
            memory.write(value, 1, tree.level_flag)
            memory.write(value + 8, 8, tree.index)

    def install(self, case):
        memory = self.machine.memory
        memory.reset(self.brk - HEAP_BASE)
        self.brk = SLAB + SLOT_STRIDE * SLAB_ROOM
        self.allocated = []
        memory.write(BOOK + 0x8, 8, SLAB)
        memory.write(BOOK + 0x10, 8, case.slab_len)
        self.sources = {}
        for index in range(SLAB_ROOM):
            body = slot_bytes(index, case)
            memory.put_bytes(SLAB + index * SLOT_STRIDE, body)
            self.sources[index] = body
            if 0 < case.children <= 64:
                pointer = self.carve(case.children * 8)
                memory.write(SLAB + index * SLOT_STRIDE + 0x58, 8, pointer)
                for at in range(case.children):
                    memory.write(pointer + at * 8, 8, CHILD_FILL + index * 0x100 + at)
        chosen, other = (SIDE_NONZERO, SIDE_ZERO) if case.flag & MASK[4] else (SIDE_ZERO, SIDE_NONZERO)
        self.build_tree(BOOK + chosen, case.tree)
        self.build_tree(BOOK + other, case.other)
        memory.put_bytes(OUTPUT, bytes([OUTPUT_MARK]) * OUTPUT_ROOM)

    def run(self, case):
        self.install(case)
        before = self.machine.memory.bytes_at(SLAB, SLOT_STRIDE * SLAB_ROOM)
        try:
            self.machine.run(CLONE, {RDI: OUTPUT, RSI: BOOK, RDX: case.flag})
        except Panicked as stop:
            return {"stop": stop.args[0]}
        memory = self.machine.memory
        if memory.bytes_at(SLAB, SLOT_STRIDE * SLAB_ROOM) != before:
            raise Halt("the slab changed")
        if memory.bytes_at(OUTPUT + SLOT_SIZE, 8) != bytes([OUTPUT_MARK]) * 8:
            raise Halt("write past the record")
        return self.read_record(OUTPUT)

    def read_record(self, at):
        memory = self.machine.memory
        record = bytearray(memory.bytes_at(at, SLOT_SIZE))
        pointer = struct.unpack_from("<Q", record, 0x58)[0]
        length = struct.unpack_from("<Q", record, 0x60)[0]
        children = memory.bytes_at(pointer, length * 8) if pointer != EMPTY_VECTOR else b""
        if pointer != EMPTY_VECTOR and (pointer, length * 8) not in self.allocated:
            raise Halt("the vector buffer is not a fresh allocation of its length")
        struct.pack_into("<Q", record, 0x58, 0)
        return {"record": bytes(record), "children": children, "pointer_empty": pointer == EMPTY_VECTOR}

    def on_malloc(self, machine):
        size = machine.regs[RDI]
        if size > 0x10000:
            machine.regs[RAX] = 0
            return
        machine.regs[RAX] = self.carve(size)
        self.allocated.append((machine.regs[RAX], size))

    def on_copy(self, machine):
        regs = machine.regs
        if regs[RDX]:
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_alloc_error(self, machine):
        raise Panicked(("allocation", machine.regs[RDI] & MASK[4], machine.regs[RSI]))

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))


# ---- specification, written from the claim and not from the evaluator ----

def find_level(tree):
    """(level, position) of the first value, walking up from an empty first leaf; None past the root."""
    if tree.lens[0]:
        return 0, 0
    level = 0
    while level < tree.height:
        position = tree.parents[level]
        level += 1
        if position < tree.lens[level]:
            return level, position
    return None


def expected_record(case, source):
    body = bytearray([OUTPUT_MARK]) * SLOT_SIZE
    present = {0x70: case.tag68 & MASK[4] == 1, 0xB2: case.tagb1 == 1}
    for offset, size, rule in SLOT_MAP:
        if rule == "not written":
            continue
        if rule.startswith("copied only"):
            body[offset:offset + size] = source[offset:offset + size] if present[offset] else bytes([STACK_MARK]) * size
        elif rule.startswith("capacity"):
            struct.pack_into("<Q", body, offset, case.children)
        elif rule.startswith("pointer"):
            struct.pack_into("<Q", body, offset, 0)
        elif offset == 0x68:
            struct.pack_into("<Q", body, offset, 1 if present[0x70] else 0)
        elif offset == 0xB1:
            body[offset] = 1 if present[0xB2] else 0
        else:
            body[offset:offset + size] = source[offset:offset + size]
    return bytes(body)


def spec(case):
    tree = case.tree
    if not tree.root or tree.field == 0:
        return {"stop": ("panic", LOCATION_EMPTY)}
    place = find_level(tree)
    if place is None:
        return {"stop": ("panic", LOCATION_NO_PARENT)}
    if tree.level_flag == 0:
        return {"stop": ("panic", LOCATION_LEVEL)}
    if tree.index >= case.slab_len or case.tag == VACANT:
        return {"stop": ("panic", LOCATION_SLOT)}
    bytes_needed = (case.children * 8) & MASK[8]
    if case.children >> 61 or bytes_needed > VECTOR_LIMIT:
        return {"stop": ("allocation", 0, bytes_needed)}
    if bytes_needed > 0x10000:
        return {"stop": ("allocation", 8, bytes_needed)}
    children = b"".join((CHILD_FILL + tree.index * 0x100 + at).to_bytes(8, "little") for at in range(case.children))
    return {"record": expected_record(case, slot_bytes(tree.index, case)), "children": children,
            "pointer_empty": case.children == 0}


# ---- cases ----

def height_cases():
    rows = []
    for flag in (0, 1, 2, 0x80000000, 0x100000000, 0x100000001):
        for height in range(10):
            rows.append(Case("flag %#x height %d" % (flag, height), flag, Tree(height)))
    return rows


def empty_cases():
    rows = []
    for flag in (0, 1):
        for height in (0, 3):
            rows.append(Case("no root flag %d height %d" % (flag, height), flag, Tree(height, root=False)))
            rows.append(Case("root with length 0 flag %d height %d" % (flag, height), flag, Tree(height, field=0)))
            rows.append(Case("no root stale length flag %d height %d" % (flag, height), flag,
                             Tree(height, root=False, field=5)))
    return rows


def climb_cases():
    """The first leaf is empty: the walk climbs until a parent index is below that parent's length."""
    rows = []
    for flag in (0, 1):
        rows.append(Case("climb root leaf flag %d" % flag, flag, Tree(0, lens=[0])))
        rows.append(Case("climb one level flag %d" % flag, flag, Tree(1, lens=[0, 3], parents=[2, 0])))
        rows.append(Case("climb past length flag %d" % flag, flag, Tree(1, lens=[0, 3], parents=[3, 0])))
        rows.append(Case("climb two levels flag %d" % flag, flag, Tree(2, lens=[0, 2, 5], parents=[2, 4, 0])))
        rows.append(Case("climb stops low flag %d" % flag, flag, Tree(2, lens=[0, 2, 5], parents=[1, 4, 0])))
        rows.append(Case("climb past root flag %d" % flag, flag, Tree(2, lens=[0, 2, 5], parents=[2, 5, 0])))
        rows.append(Case("climb inner empty flag %d" % flag, flag, Tree(2, lens=[0, 0, 1], parents=[0, 0, 0])))
    return rows


def level_cases():
    rows = []
    for flag in (0, 1):
        for value in (0, 1, 2, 0x80, 0xFF):
            rows.append(Case("level byte %#x flag %d" % (value, flag), flag, Tree(level_flag=value)))
        for index, length in ((0, 1), (0, 0), (1, 1), (1, 2), (3, 4), (3, 3), (7, 8), (7, 7)):
            rows.append(Case("index %d of %d flag %d" % (index, length, flag), flag, Tree(index=index), slab_len=length))
    return rows


def tag_cases():
    rows = []
    for tag in (0, 1, 2, 3, 0x100000002, 0x200000000, MASK[8]):
        rows.append(Case("tag %#x" % tag, tag=tag))
    for tag in (0, 1, 2, 0x100000000, 0x100000001, 0x200000001, 0xFFFFFFFF):
        rows.append(Case("tag68 %#x" % tag, tag68=tag))
    for tag in (0, 1, 2, 0xFF):
        rows.append(Case("tagb1 %#x" % tag, tagb1=tag))
    return rows


def vector_cases():
    rows = []
    for length in (0, 1, 2, 3, 8, 64):
        rows.append(Case("children %d" % length, children=length))
    for length in (0x2001, 0x0FFFFFFFFFFFFFFF, 1 << 60, (1 << 60) + 1, 1 << 61, (1 << 61) + 1, 1 << 62, 1 << 63, MASK[8]):
        rows.append(Case("children %#x" % length, children=length))
    return rows


def random_cases(count):
    draw = lcg(0x301720)
    rows = []
    for number in range(count):
        height = next(draw) % 10
        lens = [next(draw) % 4 for _ in range(height + 1)]
        parents = [next(draw) % 4 for _ in range(height + 1)]
        tree = Tree(height, lens, parents, next(draw) % 3, next(draw) % SLAB_ROOM, next(draw) % 8 != 0, next(draw) % 4)
        other = Tree(next(draw) % 3, index=next(draw) % SLAB_ROOM)
        rows.append(Case("random %d" % number, next(draw) % 3, tree, other=other, slab_len=next(draw) % (SLAB_ROOM + 1),
                         tag=next(draw) % 4, children=next(draw) % 9, tag68=next(draw) % 3, tagb1=next(draw) % 3,
                         salt=next(draw) % 256))
    return rows


def all_cases():
    return height_cases() + empty_cases() + climb_cases() + level_cases() + tag_cases() + vector_cases() + random_cases(200)


def compare(harness, case):
    predicted = spec(case)
    try:
        actual = harness.run(case)
    except (Halt, EvidenceError, IndexError, OverflowError, struct.error, ValueError) as error:
        return "%s: machine stopped: %s" % (case.label, error)
    if actual != predicted:
        return "%s: differs" % case.label
    return None


# ---- the pair function ----

def pair_cases():
    rows = []
    for number, (left, right) in enumerate(((Tree(index=1), Tree(index=2)), (Tree(2, index=3), Tree(4, index=0)))):
        rows.append(("both %d" % number, left, right))
    rows.append(("first empty", Tree(root=False), Tree(index=2)))
    rows.append(("second empty", Tree(index=2), Tree(root=False)))
    rows.append(("both empty", Tree(root=False), Tree(root=False)))
    return rows


def run_pair(harness, label, zero_side, nonzero_side):
    """Returns the stop, or the two record texts of a clone with edx 0 then edx 1."""
    case = Case(label, 0, zero_side, other=nonzero_side, children=2)
    harness.install(case)
    try:
        harness.machine.run(PAIR, {RDI: OUTPUT, RSI: BOOK})
    except Panicked as stop:
        return {"stop": stop.args[0]}
    if harness.machine.regs[RAX] != OUTPUT:
        raise Halt("the result pointer was not returned")
    memory = harness.machine.memory
    if memory.bytes_at(OUTPUT + 2 * SLOT_SIZE, 8) != bytes([OUTPUT_MARK]) * 8:
        raise Halt("write past the pair")
    return {"first": harness.read_record(OUTPUT), "second": harness.read_record(OUTPUT + SLOT_SIZE)}


def spec_pair(zero_side, nonzero_side):
    if not zero_side.root or not nonzero_side.root:
        return {"stop": ("panic", LOCATION_EMPTY)}
    rows = []
    for tree in (zero_side, nonzero_side):
        row = spec(Case("x", 0, tree, children=2))
        # The clones land in stack buffers before the copy out, so unwritten bytes show the stack.
        body = bytearray(row["record"])
        for offset, size, rule in SLOT_MAP:
            if rule == "not written":
                body[offset:offset + size] = bytes([STACK_MARK]) * size
        row["record"] = bytes(body)
        rows.append(row)
    return {"first": rows[0], "second": rows[1]}


def compare_pair(harness, row):
    label, zero_side, nonzero_side = row
    try:
        actual = run_pair(harness, label, zero_side, nonzero_side)
    except (Halt, EvidenceError, IndexError, OverflowError, struct.error, ValueError) as error:
        return "%s: machine stopped: %s" % (label, error)
    return None if actual == spec_pair(zero_side, nonzero_side) else "%s: differs" % label


# ---- static census ----

def direct_sites(image, targets):
    """Every E8/E9 rel32 byte pattern in .text that lands on a target."""
    base, text = image.text_bytes()
    found = {target: [] for target in targets}
    for opcode in (b"\xe8", b"\xe9"):
        at = text.find(opcode)
        while 0 <= at <= len(text) - 5:
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in found:
                found[target].append((base + at, opcode[0]))
            at = text.find(opcode, at + 1)
    return found


def rip_references(image, targets):
    """Count lea reg,[rip+disp32] byte patterns and relocation addends that name a target."""
    base, text = image.text_bytes()
    counts = {target: 0 for target in targets}
    wanted = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
    at = text.find(b"\x8d", 1)
    while 0 < at < len(text) - 5:
        if text[at - 1] in (0x48, 0x4C) and text[at + 1] in wanted:
            target = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
            if target in counts:
                counts[target] += 1
        at = text.find(b"\x8d", at + 1)
    for _, kind, addend, _ in image.relocations():
        if addend in counts and kind == 8:
            counts[addend] += 1
    return counts


def linear_chain(image, start, stop):
    base = image.offset(start)
    code = bytes(image.blob[base:base + (stop - start) + 16])

    def read(va, count):
        return code[va - start:va - start + count]

    rows, va = [], start
    while va < stop:
        try:
            row = decode(read, va)
        except (EvidenceError, IndexError, struct.error):
            return None
        if row.op in ("jmp", "ret", "ud2"):
            return None
        rows.append(row)
        va = row.next
    return rows if va == stop else None


def writes_register(row, register):
    return row.a is not None and row.a == ("r", register) and row.op not in ("cmp", "test", "push")


def last_writer(image, site, register):
    """Nearest aligned instruction before site that writes register, with its constant if it has one."""
    for back in range(2, 0x80):
        rows = linear_chain(image, site - back, site)
        if not rows or not writes_register(rows[0], register):
            continue
        if any(writes_register(row, register) for row in rows[1:]):
            continue
        row = rows[0]
        if row.op == "mov" and row.b[0] == "i":
            return row.va, row.b[1]
        if row.op == "xor" and row.a == row.b:
            return row.va, 0
        return row.va, None
    return None, None


def entry_gate(image, start):
    """The self-check's only test of esi: the row, its jump and the epilogue it lands on."""
    image.exact_fde(start)

    def read(va, count):
        at = image.offset(va)
        return bytes(image.blob[at:at + count])

    rows, va = [], start
    for _ in range(12):
        rows.append(decode(read, va))
        va = rows[-1].next
    for index, row in enumerate(rows[:-1]):
        if row.op == "test" and row.a == ("r", RSI) and row.b == ("r", RSI) and row.width == 4:
            jump = rows[index + 1]
            if jump.op != "jcc" or jump.cc != 4:
                raise EvidenceError("self-check gate has another shape at %#x" % row.va)
            landing = decode(read, jump.target)
            if landing.op != "add" or landing.a != ("r", RSP):
                raise EvidenceError("self-check gate has another shape at %#x" % row.va)
            return {"function": start, "test": row.va, "jump": jump.va, "landing": jump.target}
    raise EvidenceError("no esi gate at the entry of %#x" % start)


def census(image):
    sites = direct_sites(image, (CLONE, PAIR) + CHECKS)
    refs = rip_references(image, (CLONE, PAIR) + CHECKS)
    rows = []
    for target, register, role in ((CLONE, RDX, "clone"), (PAIR, None, "pair"), (CHECKS[0], RSI, "self-check"),
                                   (CHECKS[1], RSI, "self-check")):
        for site, opcode in sorted(sites[target]):
            write_at, value = last_writer(image, site, register) if register is not None else (None, None)
            rows.append({"target": target, "role": role, "site": site, "opcode": opcode, "fde": image.fde(site)[0],
                         "argument_at": write_at, "argument": value})
    return rows, refs


# ---- mutation pass ----

MUTATED = (CLONE, PAIR)
# Flips that cannot change any defined result, by address, with the reason.
EQUIVALENT = {
    0x49E39A5: "rcx has nonzero low 3 bits here, so it is never 8 and 9 splits the same way",
    0x49E3A6E: "the limit test already rejects bit 60, so shifting by 60 rejects the same lengths",
    0x49E3A75: "the compared byte count is a multiple of 8, so bit 0 of the limit changes nothing",
    0x4A06FB3: "the extra byte of the first copy is overwritten by the second copy",
}


def mutation_targets(rows):
    """Yield (va, offset in instruction, kind) for every conditional and every immediate."""
    for row in rows:
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, "immediate"


def mutate_patch(image, row_va, at):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ 1}


def run_mutants(image, seen):
    cases = all_cases()
    pairs = pair_cases()
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.real = frozenset((CLONE, PAIR))
    machine.step_limit = MUTANT_STEP_LIMIT
    for start in MUTATED:
        rows = decode_range(image, *image.exact_fde(start))
        for va, at, kind in mutation_targets(rows):
            if va not in seen:
                results.append({"va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at)
            machine.cache.pop(va, None)
            harness.brk = HEAP_BASE + HEAP_SIZE
            failed = None
            for index, case in enumerate(cases):
                failed = compare(harness, case)
                if failed:
                    cases.insert(0, cases.pop(index))
                    break
            if not failed:
                for row in pairs:
                    failed = compare_pair(harness, row)
                    if failed:
                        break
            machine.patches = {}
            machine.cache.pop(va, None)
            harness.brk = HEAP_BASE + HEAP_SIZE
            results.append({"va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed.split(":")[0] if failed else ""})
    return results


def outcome_name(result):
    stop = result.get("stop")
    if stop is None:
        return "record"
    if stop[0] == "allocation":
        return "allocation error, align %d" % stop[1]
    return "panic %#x" % stop[1]


def analyse(image, full=True):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    harness = Harness(image)
    cases = all_cases()
    stops = collections.Counter()
    for case in cases:
        failure = compare(harness, case)
        if failure:
            raise EvidenceError("clone: " + failure)
        stops[outcome_name(spec(case))] += 1
    pair = Harness(image)
    pair.machine.real = frozenset((CLONE, PAIR))
    for row in pair_cases():
        failure = compare_pair(pair, row)
        if failure:
            raise EvidenceError("pair: " + failure)
    seen = harness.machine.seen | pair.machine.seen
    functions = []
    for start, role in ((CLONE, "clone one side"), (PAIR, "clone both sides")):
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        at = image.offset(begin)
        functions.append({"role": role, "start": begin, "end": end, "size": end - begin, "instructions": len(rows),
                          "executed": sum(1 for row in rows if row.va in seen),
                          "sha256": hashlib.sha256(bytes(image.blob[at:at + end - begin])).hexdigest()})
    mutations = run_mutants(image, seen) if full else []
    calls, refs = census(image)
    locations = {"%#x" % slot: "%s:%d:%d" % image.location(slot, relative)
                 for slot in (LOCATION_EMPTY, LOCATION_LEVEL, LOCATION_SLOT, LOCATION_NO_PARENT)}
    return {"functions": functions, "calls": calls, "refs": refs, "mutations": mutations, "locations": locations,
            "gates": [entry_gate(image, start) for start in CHECKS], "cases": len(cases), "stops": stops,
            "pair_cases": len(pair_cases()), "steps": harness.machine.steps + pair.machine.steps}


def hex_or_blank(value):
    return "" if value is None else "%#x" % value


def render(evidence):
    files = {}
    rows = ["role\tstart\tend\tsize\tinstructions\texecuted\tsha256"]
    for item in evidence["functions"]:
        rows.append("\t".join((item["role"], "%#x" % item["start"], "%#x" % item["end"], str(item["size"]),
                               str(item["instructions"]), str(item["executed"]), item["sha256"])))
    files["functions.tsv"] = "\n".join(rows) + "\n"
    rows = ["target\trole\tcall_site\topcode\tcaller_fde\targument_write_at\targument"]
    for item in evidence["calls"]:
        rows.append("\t".join(("%#x" % item["target"], item["role"], "%#x" % item["site"], "%#x" % item["opcode"],
                               "%#x" % item["fde"], hex_or_blank(item["argument_at"]), hex_or_blank(item["argument"]))))
    files["callers.tsv"] = "\n".join(rows) + "\n"
    rows = ["offset\tsize\trule"]
    for offset, size, rule in SLOT_MAP:
        rows.append("%#x\t%#x\t%s" % (offset, size, rule))
    files["slot_clone_map.tsv"] = "\n".join(rows) + "\n"
    rows = ["va\tkind\tresult\tfirst_detecting_case\tnote"]
    for item in evidence["mutations"]:
        note = EQUIVALENT.get(item["va"], "") if item["result"] == "survived" else ""
        rows.append("\t".join(("%#x" % item["va"], item["kind"], item["result"], item["by"], note)))
    files["mutations.tsv"] = "\n".join(rows) + "\n"
    summary = {key: 0 for key in ("killed", "survived", "unreached")}
    for item in evidence["mutations"]:
        summary[item["result"]] += 1
    document = {
        "target": {"path": "artifacts/node/94/hl-node", "sha256": SHA256},
        "cases": evidence["cases"],
        "pair_cases": evidence["pair_cases"],
        "outcomes": dict(sorted(evidence["stops"].items())),
        "instructions_stepped": evidence["steps"],
        "mismatches": 0,
        "mutations": summary,
        "locations": evidence["locations"],
        "address_references": {"%#x" % key: value for key, value in sorted(evidence["refs"].items())},
        "self_check_gates": [{key: "%#x" % value for key, value in item.items()} for item in evidence["gates"]],
        "side_offsets": {"flag_nonzero": "%#x" % SIDE_NONZERO, "flag_zero": "%#x" % SIDE_ZERO},
        "level_node": {"value_stride": "%#x" % VALUE_STRIDE, "parent": "%#x" % NODE_PARENT,
                       "parent_index": "%#x" % NODE_PARENT_INDEX, "length": "%#x" % NODE_LEN, "edges": "%#x" % NODE_EDGES},
    }
    files["evidence.json"] = json.dumps(document, indent=2, sort_keys=True) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (folder / name).write_text(text, encoding="ascii", newline="\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output folder")
    options = parser.parse_args(argv)
    files = render(analyse(load_image()))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
