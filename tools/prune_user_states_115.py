#!/usr/bin/env python3
"""Recover the node #115 per-book user_states prune closure from ELF bytes: which entries of a book's user_states map go.

The block step named prune_book_empty_user_states walks every book twice through a per-book closure. Two closures exist,
`0x2425d20` for the books of the dex rows and `0x2425870` for the book list. Each collects the users whose `b` and `u` length
words are both zero into a B-tree set, takes out of the set every user that still sits in an occupied slab slot, and removes what
is left from the book's `user_states` map, which is either a B-tree behind a niche word or a sorted ring buffer. The real bytes
of both closures and their whole callee tree run in a Python evaluator with only allocator, memcmp, growth and thread pool
edges stubbed. A separately written specification predicts every result, and every condition, immediate and field offset is
flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SHT_NOBITS = 8

ROW_CLOSURE = 0x2425D20
LIST_CLOSURE = 0x2425870
THREAD_WORD = 0x5BBD780
STEP_NAME_TEXT = "prune_book_empty_user_states"
STEP_NAME_AT = (0x60E21E, 0x929E38)
STEP_NAME_LEAS = (0x2BE191A, 0x54ABD99, 0x54B8710)

SLOT_REGISTRY = 0x64E4E70
SLOT_GROW = 0x64E4D18
SLOT_MEMCMP = 0x64DFB50
SLOT_MALLOC = 0x64DF480
SLOT_FREE = 0x64DF4A0
SLOT_MEMCPY = 0x64DF508
SLOT_MEMMOVE = 0x64DF568
SLOT_PANIC = (0x64DF4C0, 0x64DF830, 0x64DF730, 0x64DF520, 0x64DF6B8)
SLOT_ALLOC_ERROR = (0x64DF498,)

BOOK_STRIDE = 0x120
SLAB_STRIDE = 0x110
MAP_AT = 0xE8
SLAB_PTR_AT = 0x88
SLAB_LEN_AT = 0x90
SLAB_KEY_AT = 0xF8
ENTRY_SIZE = 0x70
VALUE_SIZE = 0x58
ENTRY_VALUE_AT = 0x18
USER_SIZE = 20
VACANT = 2
NICHE = 0x8000000000000000

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
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 300000

REGISTRY_CELL = HEAP_BASE + 0x80
REGISTRY = HEAP_BASE + 0x100
WORKER = HEAP_BASE + 0x400
TLS_CELL = HEAP_BASE + 0x600
FS_BASE = TLS_CELL + 0x488
BOOKS = HEAP_BASE + 0x8000
SLABS = HEAP_BASE + 0x10000
HEAP_FREE = HEAP_BASE + 0x40000

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
SHIFTS = {0: "rol", 4: "shl", 5: "shr", 7: "sar"}


def decode(read, va):
    """Decode one instruction at va; read(va, n) returns n code bytes."""
    window = read(va, 16)
    pos, rex, opsize, rep, repne = 0, 0, False, False, False
    fs = 0
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
        elif byte == 0xF2:
            repne = True
        elif byte == 0x64:
            fs = FS_BASE
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
                return reg, ("m", base, index, scale, disp + fs, False)
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
        return reg, ("m", base, index, scale, disp + fs, rip)

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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
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
        if byte == 0xFF and kind == 6:
            return finish("pushi", rm, w=8)
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
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
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
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
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
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.jump_low = self.jump_high = 0
        self.hist = collections.deque(maxlen=400)
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
            self.last = pc
            self.hist.append(pc)
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
        elif op == "pushi":
            self.push(self.get(row.a, 8))
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
            self.call_site = row.va
            self.call_target = target
            self.stub(hook)
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            if not self.jump_low <= target < self.jump_high:
                raise Halt("indirect jump out of the function at %#x" % row.va)
            return target
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (self.regs[row.b[1]] & (8 * width - 1)) & 1)
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
        elif op in ("shl", "shr", "sar", "rol"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "rol":
                result = (value << count | value >> (8 * width - count)) & MASK[width]
            elif op == "shl":
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
            left, right = self.get(row.a, width), self.get(row.b, width)
            left = left - (1 << (8 * width)) if left & SIGN[width] else left
            right = right - (1 << (8 * width)) if right & SIGN[width] else right
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
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
        elif op == "unpcklpd":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> (8 * at)) & 0xFF) | ((right >> (8 * at)) & 0xFF) << 8) << (16 * at) for at in range(8))
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = sum(((source >> (16 * ((row.target >> (2 * at)) & 3))) & 0xFFFF) << (16 * at) for at in range(4))
            self.xmm[row.a[1]] = (source >> 64) << 64 | words
        elif op == "pshufd":
            source = self.vector(row.b)
            self.xmm[row.a[1]] = sum(((source >> (32 * ((row.target >> (2 * at)) & 3))) & MASK[4]) << (32 * at) for at in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            bits = 8 * size
            self.xmm[row.a[1]] = sum((MASK[size] if (left >> at) & MASK[size] == (right >> at) & MASK[size] else 0) << at for at in range(0, 128, bits))
        elif op == "pmovmskb":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, sum(((source >> (8 * at + 7)) & 1) << at for at in range(16)))
        elif op == "tzcnt":
            value = self.get(row.b, row.width)
            result = 8 * row.width if value == 0 else (value & -value).bit_length() - 1
            self.cf = value == 0
            self.zf = result == 0
            self.put(row.a, row.width, result)
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


# ---- specification, written from the disassembly and independent of the evaluator ----

def user_id(number):
    """A 20 byte key with a non-periodic ramp; the whole key takes part in the order."""
    out = bytearray(USER_SIZE)
    value = number * 2654435761 + 0x1234567
    for index in range(USER_SIZE):
        value = (value * 31 + index * 17 + 11) & MASK[8]
        out[index] = (value >> 13) & 0xFF
    return bytes(out)


def candidates(entries):
    """Rule 1: the `b` length word (value +0x38 as seen from the entry) and the `u` length word are both zero. The `r` vector plays no part."""
    return {entry["user"] for entry in entries if entry["b"] == 0 and entry["u"] == 0}


def held(slab, count):
    """Rule 2: a slot in the first `count` rows with a state dword other than 2 holds its user."""
    return {slot["user"] for slot in slab[:count] if slot["state"] & MASK[4] != VACANT}


def removed(book):
    return candidates(book["entries"]) - held(book["slab"], book["slab_len"])


def spec_run(case):
    book = case.world
    gone = removed(book)
    kept = sorted(entry["user"] for entry in book["entries"] if entry["user"] not in gone)
    return {"users": [user.hex() for user in kept], "length": len(kept), "leaked": 0, "intact": True, "stop": None}


# ---- harness: real bytes; allocator, memcmp, growth and thread pool edges are stubbed ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Case:
    def __init__(self, label, world, closure):
        self.label = label
        self.world = world
        self.closure = closure


Shape = collections.namedtuple("Shape", "parent keys key_size value_size parent_index length edges")
USER_SHAPE = Shape(0x0, 0x3D0, USER_SIZE, VALUE_SIZE, 0x4AC, 0x4AE, 0x4B0)
FANOUT = 12
VALUES_AT = 8
VALUE_R = 0x00
VALUE_B = 0x20
VALUE_U = 0x40
WALK_LIMIT = 4000


def ramp(count, start):
    return bytes((start + index * 7) & 0xFF or 1 for index in range(count))


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_REGISTRY: self.on_registry, SLOT_GROW: self.on_grow, SLOT_MEMCMP: self.on_memcmp, SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free,
                 SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy}
        for slot in SLOT_PANIC + SLOT_ALLOC_ERROR:
            table[slot] = self.on_panic
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        self.real.stubs = frozenset(machine.slots) | frozenset((THREAD_WORD,))
        machine.calls = {THREAD_WORD: self.on_thread}
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.owned = {}

    # ---- stubs ----

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_thread(self, m):
        if m.regs[RDI] & MASK[4]:
            raise Halt("thread word argument")
        m.regs[RAX] = TLS_CELL

    def on_registry(self, m):
        m.regs[RAX] = REGISTRY_CELL

    def on_memcmp(self, m):
        regs = m.regs
        count = regs[RDX]
        if count > 0x100:
            raise Halt("memcmp size")
        left, right = m.memory.bytes_at(regs[RDI], count), m.memory.bytes_at(regs[RSI], count)
        regs[RAX] = 0
        for one, two in zip(left, right):
            if one != two:
                regs[RAX] = (one - two) & MASK[4]
                break

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        if m.regs[RDI] > 0x40000:
            raise Halt("allocation size")
        m.regs[RAX] = self.allocate(m.regs[RDI])

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x40000:
            raise Halt("copy size")
        m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_grow(self, m):
        """The RawVec one-step growth at slot 0x64e4d18, element size 20, alignment 1."""
        memory = m.memory
        vector = m.regs[RDI]
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        if capacity > 0x1000:
            raise Halt("vector size")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * USER_SIZE)
        if capacity:
            memory.copy(fresh, old, capacity * USER_SIZE)
            if self.live.pop(old, None) != capacity * USER_SIZE:
                raise Halt("vector buffer")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    # ---- worlds ----

    def place(self, keys, parent, index, height, owner):
        """A user tree of uniform depth, keys in order; `keys` holds (key bytes, entry)."""
        memory = self.machine.memory
        own, kids = list(keys), []
        if height:
            fan = 3 if height >= 2 or len(keys) < (FANOUT - 1) * 3 + 2 else min(FANOUT, (len(keys) + 11) // 11)
            base, extra = divmod(len(keys) - (fan - 1), fan)
            own, at = [], 0
            for child in range(fan):
                size = base + (1 if child < extra else 0)
                kids.append(keys[at:at + size])
                at += size
                if child < fan - 1:
                    own.append(keys[at])
                    at += 1
        node = self.allocate(USER_SHAPE.edges + (FANOUT * 8 if kids else 0))
        memory.put_bytes(node, ramp(USER_SHAPE.edges, 0x2B))
        memory.write(node + USER_SHAPE.parent, 8, parent)
        memory.write(node + USER_SHAPE.parent_index, 2, index)
        memory.write(node + USER_SHAPE.length, 2, len(own))
        for at, (key, entry) in enumerate(own):
            memory.put_bytes(node + USER_SHAPE.keys + at * USER_SIZE, key)
            self.fill_value(node + VALUES_AT + at * VALUE_SIZE, entry, owner)
        for at in range(len(own), FANOUT - 1):
            memory.put_bytes(node + USER_SHAPE.keys + at * USER_SIZE, b"\xfd" * USER_SIZE)
        for at, kid in enumerate(kids):
            memory.write(node + USER_SHAPE.edges + at * 8, 8, self.place(kid, node, at, height - 1, owner))
        return node

    def fill_value(self, at, entry, owner):
        """The 0x58 byte value: r vector at +0, b map at +0x20 (niche word, then three words), u map at +0x40 (root, height, length)."""
        memory = self.machine.memory
        held_by = owner.setdefault(entry["user"], [])
        memory.put_bytes(at, ramp(VALUE_SIZE, 0x51))
        capacity = entry.get("r_cap", entry["r"])
        memory.write(at + VALUE_R, 8, capacity)
        if capacity:
            buffer = self.allocate(capacity * 8)
            held_by.append(buffer)
            memory.write(at + VALUE_R + 8, 8, buffer)
        else:
            memory.write(at + VALUE_R + 8, 8, 8)
        memory.write(at + VALUE_R + 16, 8, entry["r"])
        if entry["b"]:
            memory.write(at + VALUE_B, 8, 0x10)
            memory.write(at + VALUE_B + 8, 8, 0x7777)
            memory.write(at + VALUE_B + 16, 8, 0)
            memory.write(at + VALUE_B + 24, 8, entry["b"])
        elif entry.get("b_tree"):
            memory.write(at + VALUE_B, 8, NICHE)
            memory.write(at + VALUE_B + 8, 8, 0)
            memory.write(at + VALUE_B + 16, 8, 0)
            memory.write(at + VALUE_B + 24, 8, 0)
        else:
            cap = entry.get("b_cap", 0)
            if cap:
                buffer = self.allocate(cap * 0xE0)
                held_by.append(buffer)
            memory.write(at + VALUE_B, 8, cap)
            memory.write(at + VALUE_B + 8, 8, buffer if cap else 8)
            memory.write(at + VALUE_B + 16, 8, 0)
            memory.write(at + VALUE_B + 24, 8, 0)
        if entry["u"]:
            memory.write(at + VALUE_U, 8, 0x10)
            memory.write(at + VALUE_U + 8, 8, 0)
            memory.write(at + VALUE_U + 16, 8, entry["u"])
        else:
            memory.write(at + VALUE_U, 8, 0)
            memory.write(at + VALUE_U + 8, 8, 0x55)
            memory.write(at + VALUE_U + 16, 8, 0)

    def book_world(self, base, slab_base, book):
        memory = self.machine.memory
        memory.put_bytes(base, ramp(BOOK_STRIDE, 0x2F))
        memory.write(base + SLAB_PTR_AT, 8, slab_base)
        memory.write(base + SLAB_LEN_AT, 8, book["slab_len"])
        for index, slot in enumerate(book["slab"]):
            at = slab_base + index * SLAB_STRIDE
            memory.put_bytes(at, ramp(SLAB_STRIDE, 0x41 + index))
            memory.write(at, 8, slot["state"])
            memory.put_bytes(at + SLAB_KEY_AT, slot["user"])
        owner = {}
        rows = [(entry["user"], entry) for entry in sorted(book["entries"], key=lambda item: item["user"])]
        if book["form"] == "tree":
            memory.write(base + MAP_AT, 8, NICHE)
            memory.write(base + MAP_AT + 8, 8, self.place(rows, 0, 0xFFFF, book["height"], owner) if rows else 0)
            memory.write(base + MAP_AT + 16, 8, book["height"] if rows else 0)
            memory.write(base + MAP_AT + 24, 8, len(rows))
        else:
            cap = len(rows) + book["spare"]
            buffer = self.allocate(cap * ENTRY_SIZE) if cap else 8
            for position, (key, entry) in enumerate(rows):
                at = buffer + ((book["head"] + position) % cap) * ENTRY_SIZE
                memory.put_bytes(at, ramp(ENTRY_SIZE, 0x33 + position))
                memory.put_bytes(at, key)
                self.fill_value(at + ENTRY_VALUE_AT, entry, owner)
            memory.write(base + MAP_AT, 8, cap)
            memory.write(base + MAP_AT + 8, 8, buffer)
            memory.write(base + MAP_AT + 16, 8, book["head"] % cap if cap else 0)
            memory.write(base + MAP_AT + 24, 8, len(rows))
        self.owned[base] = owner
        outside = memory.bytes_at(base, MAP_AT) + memory.bytes_at(base + MAP_AT + 32, BOOK_STRIDE - MAP_AT - 32)
        return memory.bytes_at(slab_base, len(book["slab"]) * SLAB_STRIDE), outside

    def read_map(self, base, values):
        """Walk the user map; every step is bounded because a mutant can corrupt it."""
        memory = self.machine.memory
        first = memory.read(base + MAP_AT, 8)
        users, nodes = [], set()
        if first == NICHE:
            root, height = memory.read(base + MAP_AT + 8, 8), memory.read(base + MAP_AT + 16, 8)

            def walk(node, depth):
                if len(nodes) > WALK_LIMIT or depth > 8:
                    raise Halt("tree walk")
                if node in nodes:
                    raise Halt("tree cycle")
                nodes.add(node)
                count = memory.read(node + USER_SHAPE.length, 2)
                if count > FANOUT - 1:
                    raise Halt("node length")
                for at in range(count + 1):
                    if depth:
                        kid = memory.read(node + USER_SHAPE.edges + at * 8, 8)
                        if memory.read(kid + USER_SHAPE.parent, 8) != node or memory.read(kid + USER_SHAPE.parent_index, 2) != at:
                            raise Halt("parent link")
                        walk(kid, depth - 1)
                    if at < count:
                        users.append(memory.bytes_at(node + USER_SHAPE.keys + at * USER_SIZE, USER_SIZE))
                        values.append((users[-1], memory.bytes_at(node + VALUES_AT + at * VALUE_SIZE, VALUE_SIZE)))
            if root:
                walk(root, height)
        else:
            cap, buffer, head, length = (memory.read(base + MAP_AT + 8 * index, 8) for index in range(4))
            if cap > 4096 or length > cap or (cap and head >= cap):
                raise Halt("ring words")
            if cap:
                nodes.add(buffer)
            for position in range(length):
                at = buffer + ((head + position) % cap) * ENTRY_SIZE
                users.append(memory.bytes_at(at, USER_SIZE))
                values.append((users[-1], memory.bytes_at(at + ENTRY_VALUE_AT, VALUE_SIZE)))
        return {"users": [user.hex() for user in users], "length": memory.read(base + MAP_AT + 24, 8)}, nodes

    def reachable(self, base, nodes, kept):
        out = set(nodes)
        for user in kept:
            out.update(self.owned[base].get(bytes.fromhex(user), ()))
        return out

    def set_threads(self, w):
        memory = self.machine.memory
        memory.write(REGISTRY_CELL, 8, REGISTRY)
        memory.write(REGISTRY + 0x208, 8, w.get("threads", 0))
        memory.write(WORKER + 0x110, 8, REGISTRY)
        memory.write(TLS_CELL, 8, WORKER if w.get("worker", True) else 0)

    def run(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.w = w
        self.live = {}
        self.owned = {}
        memory.reset(self.brk - HEAP_BASE)
        self.brk = HEAP_FREE
        answer = {"stop": None}
        self.set_threads(w)
        try:
            slab, outside = self.book_world(BOOKS, SLABS, w)
            before = {}
            self.read_map(BOOKS, [])
            values_before = []
            self.read_map(BOOKS, values_before)
            before = dict(values_before)
            entry = LIST_CLOSURE if case.closure == "list" else ROW_CLOSURE
            machine.run(entry, {RDI: POISON, RSI: BOOKS})
            values = []
            row, nodes = self.read_map(BOOKS, values)
            answer.update(row)
            intact = memory.bytes_at(SLABS, len(slab)) == slab
            intact = intact and memory.bytes_at(BOOKS, MAP_AT) + memory.bytes_at(BOOKS + MAP_AT + 32, BOOK_STRIDE - MAP_AT - 32) == outside
            intact = intact and all(before.get(user) == value for user, value in values)
            answer["intact"] = intact
            answer["leaked"] = len(set(self.live) - self.reachable(BOOKS, nodes, row["users"]))
        except Panicked as stop:
            answer["stop"] = stop.args[0]
        return answer


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError)


def compare_run(harness, case, spec=None):
    """Empty when the bytes and the specification agree, else one line."""
    wanted = (spec or spec_run)(case)
    try:
        found = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.label, type(error).__name__, error)
    if found != wanted:
        keys = sorted(key for key in set(wanted) | set(found) if found.get(key) != wanted.get(key))
        detail = ""
        if keys:
            left, right = found.get(keys[0]), wanted.get(keys[0])
            detail = "%s found %s wanted %s" % (keys[0], str(left)[:300], str(right)[:300])
        return "%s: differs: %s" % (case.label, detail)
    return ""


# ---- cases ----

def entry(number, r=0, b=0, u=0, **more):
    row = {"user": user_id(number), "r": r, "b": b, "u": u}
    row.update(more)
    return row


def slot(number, state=0):
    return {"user": user_id(number) if isinstance(number, int) else number, "state": state}


def book(entries=(), slab=(), slab_len=None, height=None, **more):
    entries = list(entries)
    slab = list(slab)
    if height is None:
        height = 0 if len(entries) <= FANOUT - 1 else 1
    row = {"entries": entries, "slab": slab, "slab_len": len(slab) if slab_len is None else slab_len, "height": height, "form": "tree", "spare": 0, "head": 0}
    row.update(more)
    return row


class Lcg:
    """A small fixed generator so the case list is the same on every run."""

    def __init__(self, start):
        self.value = start

    def next(self, top):
        self.value = (self.value * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (self.value >> 33) % top


def single_cases():
    rows = []
    for r in (0, 3):
        for b in (0, 1):
            for u in (0, 2):
                for slab, label in (([], "no slot"), ([slot(7)], "occupied"), ([slot(7, VACANT)], "vacant"), ([slot(9)], "other user"), ([slot(9), slot(11, 1), slot(7, 1)], "third slot")):
                    rows.append(("one entry r %d b %d u %d %s" % (r, b, u, label), book([entry(7, r, b, u)], slab)))
    return rows


def field_cases():
    near = user_id(20)
    variants = [bytes((near[0] ^ 1,)) + near[1:], near[:-1] + bytes((near[-1] ^ 1,)), near[:16] + bytes((near[16] ^ 0x40,)) + near[17:], near[:8] + bytes((near[8] ^ 2,)) + near[9:]]
    rows = []
    for index, other in enumerate(variants):
        users = [dict(entry(20), user=near), dict(entry(21), user=other)]
        rows.append(("near keys %d, slot on the first" % index, book(users, [{"user": near, "state": 0}])))
        rows.append(("near keys %d, slot on the second" % index, book(users, [{"user": other, "state": 0}])))
        rows.append(("near keys %d, slot equal to neither" % index, book(users, [{"user": near[:-2] + b"\x00\x00", "state": 0}])))
        rows.append(("near keys %d, slot differs in byte 0" % index, book([dict(entry(20), user=near)], [{"user": other, "state": 0}])))
    rows.append(("state word 3 counts as held", book([entry(1)], [slot(1, 3)])))
    rows.append(("state high bits ignored: dword 2 is vacant", book([entry(1)], [slot(1, 0x500000002)])))
    rows.append(("state 0x200000000 low dword 0 is held", book([entry(1)], [slot(1, 0x200000000)])))
    rows.append(("state 0x102 is held", book([entry(1)], [slot(1, 0x102)])))
    rows.append(("slot past the slab length is ignored", book([entry(1), entry(2)], [slot(1, VACANT), slot(2, 0)], 1)))
    rows.append(("empty slab, stale row", book([entry(1), entry(2)], [slot(1), slot(2)], 0)))
    rows.append(("map without a root", book()))
    rows.append(("map without a root, slab full", book(slab=[slot(1), slot(2)])))
    rows.append(("empty tree b dropped", book([entry(1, 2, 0, 0, b_tree=True), entry(2, 0, 0, 0, b_tree=True)])))
    rows.append(("empty tree b kept while a slot holds", book([entry(1, 2, 0, 0, b_tree=True)], [slot(1)])))
    rows.append(("b capacity without length dropped", book([entry(1, 0, 0, 0, b_cap=3)])))
    rows.append(("r capacity without length dropped", book([entry(1, 0, 0, 0, r_cap=4)])))
    rows.append(("r length under capacity dropped", book([entry(1, 2, 0, 0, r_cap=9)])))
    rows.append(("b length only keeps", book([entry(1, 0, 1, 0)])))
    rows.append(("u length only keeps", book([entry(1, 0, 0, 1)])))
    rows.append(("large length words keep", book([entry(1, 0, 1 << 40, 0), entry(2, 0, 0, 1 << 40), entry(3, 0, 1 << 63, 0)])))
    return rows


def mixed(random, count, height=None, chance=3):
    entries = []
    slab = []
    for number in range(1, count + 1):
        kind = random.next(chance)
        if kind == 0:
            entries.append(entry(number, random.next(3), b_cap=random.next(3) if random.next(2) else 0))
            if random.next(2):
                slab.append(slot(number))
        elif kind == 1:
            entries.append(entry(number, 1, random.next(3) + 1, random.next(2)))
        else:
            entries.append(entry(number, 0, 0, 0, b_tree=bool(random.next(2))))
    for at in range(random.next(4)):
        slab.append(slot(count + at + 1, random.next(2) * VACANT))
    return book(entries, slab, height=height)


def tree_cases():
    rows = []
    random = Lcg(0x5EED)
    for index in range(36):
        rows.append(("mixed leaf %d" % index, mixed(random, 2 + index % 10)))
    for index in range(24):
        rows.append(("mixed height 1 %d" % index, mixed(random, 12 + index, 1)))
    for count in (12, 14, 23, 40):
        rows.append(("all gone height 1, %d" % count, book([entry(number, 1) for number in range(1, count + 1)])))
        rows.append(("all kept height 1, %d" % count, book([entry(number, 1, 1) for number in range(1, count + 1)])))
        rows.append(("all held height 1, %d" % count, book([entry(number) for number in range(1, count + 1)], [slot(number) for number in range(1, count + 1)])))
        rows.append(("every second gone, %d" % count, book([entry(number, 0, number & 1) for number in range(1, count + 1)])))
    ordered = sorted(range(1, 41), key=user_id)
    rows.append(("only the lowest kept", book([entry(number, 0, int(number == ordered[0])) for number in ordered])))
    rows.append(("only the highest kept", book([entry(number, 0, int(number == ordered[-1])) for number in ordered])))
    rows.append(("only the lowest gone", book([entry(number, 0, int(number != ordered[0])) for number in ordered])))
    rows.append(("only the highest gone", book([entry(number, 0, int(number != ordered[-1])) for number in ordered])))
    for index in range(8):
        rows.append(("mixed height 2 %d" % index, mixed(random, 20 + index * 3, 2)))
    rows.append(("all gone height 2", book([entry(number, 2) for number in range(1, 31)], height=2)))
    rows.append(("mixed height 3", mixed(random, 61, 3)))
    rows.append(("all gone height 3", book([entry(number) for number in range(1, 62)], height=3)))
    rows.append(("set grows past one leaf", book([entry(number) for number in range(1, 61)], [slot(number) for number in range(1, 30)])))
    rows.append(("many slab rows, one user", book([entry(1), entry(2)], [slot(2)] * 12)))
    return rows


RANDOM_CASES = 5200


def random_cases(closure, seed):
    """Small random books: the bulk of the case list. Counts 1..11 give a leaf root, the rest height 1."""
    random = Lcg(seed)
    for index in range(RANDOM_CASES):
        count = 1 + random.next(11) if index % 8 else 12 + random.next(14)
        yield Case("%s random %d" % (closure, index), mixed(random, count, None, 2 + random.next(3)), closure)


def structured_cases():
    cases = []
    small = single_cases() + field_cases()
    trees = tree_cases()
    for closure in ("row", "list"):
        for label, world in small + trees:
            cases.append(Case("%s: %s" % (closure, label), world, closure))
    return cases


def all_cases():
    cases = structured_cases()
    cases.extend(random_cases("row", 0xA11CE))
    cases.extend(random_cases("list", 0xB0B))
    return cases


# ---- static reads ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def function_bytes(image, start):
    begin, end = image.exact_fde(start)
    return begin, code(image, begin, end - begin)


ANCHORS = (
    (ROW_CLOSURE, "cmp dword [rax], 2: a slab slot with state 2 is vacant", "833802"),
    (ROW_CLOSURE, "movups xmm0, [rax+0xf8]: first 16 bytes of the slot user", "0f1080f8000000"),
    (ROW_CLOSURE, "mov ecx, [rax+0x108]: last 4 bytes of the slot user", "8b8808010000"),
    (ROW_CLOSURE, "imul rcx, [r12+0x90], 0x110: slab length times the slot stride", "49698c24"),
    (ROW_CLOSURE, "movzx eax, word [rax+0xe6]: set node length", "0fb780e6000000"),
    (ROW_CLOSURE, "mov edx, 0x14: key compare size is the 20 byte user", "ba14000000"),
    (LIST_CLOSURE, "cmp dword [rax], 2: a slab slot with state 2 is vacant", "833802"),
    (LIST_CLOSURE, "movups xmm0, [rax+0xf8]: first 16 bytes of the slot user", "0f1080f8000000"),
    (LIST_CLOSURE, "mov ecx, [rax+0x108]: last 4 bytes of the slot user", "8b8808010000"),
    (LIST_CLOSURE, "mov edx, 0x14: key compare size is the 20 byte user", "ba14000000"),
    (0x29FA380, "mov rsi, [rdx+0x38]; or rsi, [rdx+0x50]: b and u length words", "488b7238480b7250"),
    (0x29FBE00, "mov rsi, [rdx+0x38]; or rsi, [rdx+0x50]: b and u length words", "488b7238480b7250"),
)
GROUPS = (
    (ROW_CLOSURE, "row closure", None),
    (LIST_CLOSURE, "list closure", None),
    (0x231E650, "collect into the set, row", None),
    (0x231E420, "collect into the set, list", None),
    (0x29FC620, "sequential collect, row", None),
    (0x29FC750, "sequential collect, list", None),
    (0x29FA380, "filter on b and u lengths, row", None),
    (0x29FBE00, "filter on b and u lengths, list", None),
    (0x234BEC0, "build the entry reference list", None),
    (0x2703060, "extend the set from a key list", None),
    (0x1D5D520, "remove a held user from the set", None),
    (0x2DCF030, "remove loop over user_states, row", None),
    (0x2DCF3D0, "remove loop over user_states, list", None),
)


def anchor_rows(image):
    rows = []
    for function, meaning, wanted in ANCHORS:
        begin, body = function_bytes(image, function)
        needle = bytes.fromhex(wanted)
        at = body.find(needle)
        if at < 0:
            raise EvidenceError("anchor bytes %s missing in function %#x" % (wanted, function))
        rows.append({"function": "%#x" % begin, "offset": "%#x" % at, "bytes": wanted, "meaning": meaning, "occurrences": body.count(needle)})
    return rows


def step_name_rows(image):
    rows = []
    for at in STEP_NAME_AT:
        if code(image, at, len(STEP_NAME_TEXT)).decode("ascii") != STEP_NAME_TEXT:
            raise EvidenceError("step name text at %#x" % at)
    for site in STEP_NAME_LEAS:
        window = code(image, site, 7)
        if window[:3] not in (b"\x48\x8d\x05", b"\x4c\x8d\x05"):
            raise EvidenceError("lea bytes at %#x" % site)
        target = site + 7 + struct.unpack_from("<i", window, 3)[0]
        if target not in STEP_NAME_AT:
            raise EvidenceError("lea target at %#x" % site)
        following = code(image, site + 7, 24)
        length = following.find(b"\x1c\x00\x00\x00")
        rows.append({"lea": "%#x" % site, "name": "%#x" % target, "length_word_at": length, "fde": "%#x" % image.fde(site)[0]})
    return rows


def copy_table(image):
    first, first_targets = masked(image, ROW_CLOSURE)
    second, second_targets = masked(image, LIST_CLOSURE)
    rows = []
    for closure, body, targets in ((ROW_CLOSURE, first, first_targets), (LIST_CLOSURE, second, second_targets)):
        rows.append({"closure": "%#x" % closure, "size": len(body), "masked_sha256": hashlib.sha256(body).hexdigest(), "callees": ["%#x" % target for target in targets]})
    return rows


def masked(image, start):
    """Function bytes with call, jump and rip displacements outside the function zeroed; (bytes, outer targets in order)."""
    begin, end = image.exact_fde(start)
    out = bytearray(code(image, begin, end - begin))
    targets = []
    for row in decode_range(image, begin, end):
        at = row.va - begin
        if row.op in ("call", "jmp") and row.target is not None and not begin <= row.target < end:
            out[at + row.size - 4:at + row.size] = bytes(4)
            targets.append(row.target)
        if row.rip_at is not None:
            out[at + row.rip_at:at + row.rip_at + 4] = bytes(4)
    return bytes(out), targets


def rule_table():
    rows = []
    for r in (0, 3):
        for b in (0, 1):
            for u in (0, 1):
                for occupied in (0, 1):
                    world = book([entry(1, r, b, u)], [slot(1, 0 if occupied else VACANT)])
                    rows.append({"r_length": r, "b_length": b, "u_length": u, "occupied_slot": occupied, "entry_removed": user_id(1) in removed(world)})
    return rows


# ---- mutation ----

def displacement_at(image, row):
    """Offset inside the instruction of a non-stack field displacement, or None."""
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4] and not operand[5]:
            disp = operand[4]
            if abs(disp) >= HEAP_BASE // 2:
                continue
            end = row.size - (row.imm_size or 0)
            data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, "immediate"


def mutate_patch(image, row_va, at, kind="branch"):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ (8 if kind == "offset" else 1)}


HEAVY_STEPS = 6000
LARGE_CASES = 3


def group_rows(image, start, stop):
    begin, end = image.exact_fde(start)
    return begin, begin + stop if stop else end, end


def mutated_groups(image):
    groups = []
    for start, role, stop in GROUPS:
        begin, limit, _ = group_rows(image, start, stop)
        groups.append((start, role, decode_range(image, begin, limit)))
    return groups


def run_mutants(image, cases, reached, sets, costs, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run; large trees run only for rows nothing smaller reaches."""
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    by_va = {}
    for index, which in enumerate(reached):
        for va in sets[which]:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for start, _, rows in mutated_groups(image):
        for va, at, kind in mutation_targets(image, rows):
            indices = by_va.get(va)
            if indices:
                light = [index for index in indices if costs[index] <= HEAVY_STEPS]
                large = sorted((index for index in indices if costs[index] > HEAVY_STEPS), key=lambda index: costs[index])
                indices = (light[:60] or large[:1]) + large[:LARGE_CASES]
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            wanted = set(indices)
            order = [index for index in first_kill if index in wanted] + indices
            for index in order:
                failed = compare_run(harness, cases[index])
                if failed:
                    if index in first_kill:
                        first_kill.remove(index)
                    first_kill.insert(0, index)
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
    return results


# ---- negative controls ----

def wrong_specs():
    """Deliberately wrong rules; each must disagree with the real bytes on some case."""
    def make(candidate=None, hold=None, keep=None, length=None):
        def spec(case):
            book_ = case.world
            entries = book_["entries"]
            cand = candidate(entries) if candidate else candidates(entries)
            hold_ = hold(book_["slab"], book_["slab_len"]) if hold else held(book_["slab"], book_["slab_len"])
            gone = cand - hold_
            if keep:
                gone = keep(gone)
            kept = sorted(row["user"] for row in entries if row["user"] not in gone)
            return {"users": [user.hex() for user in kept], "length": length(len(entries), len(gone), len(kept)) if length else len(kept), "leaked": 0, "intact": True, "stop": None}
        return spec

    both = lambda entries: {e["user"] for e in entries if e["b"] == 0 and e["u"] == 0}
    return [
        ("candidates ignore u", make(candidate=lambda es: {e["user"] for e in es if e["b"] == 0})),
        ("candidates ignore b", make(candidate=lambda es: {e["user"] for e in es if e["u"] == 0})),
        ("candidates also need r empty", make(candidate=lambda es: {e["user"] for e in es if e["b"] == 0 and e["u"] == 0 and e["r"] == 0})),
        ("candidates use or instead of and", make(candidate=lambda es: {e["user"] for e in es if e["b"] == 0 or e["u"] == 0})),
        ("b counts only above one", make(candidate=lambda es: {e["user"] for e in es if e["b"] <= 1 and e["u"] == 0})),
        ("u counts only above one", make(candidate=lambda es: {e["user"] for e in es if e["b"] == 0 and e["u"] <= 1})),
        ("every slot holds, vacant too", make(hold=lambda slab, count: {s["user"] for s in slab[:count]})),
        ("slab length ignored", make(hold=lambda slab, count: held(slab, len(slab)))),
        ("slab length minus one", make(hold=lambda slab, count: held(slab, max(count - 1, 0)))),
        ("only the first slot holds", make(hold=lambda slab, count: held(slab[:1], min(count, 1)))),
        ("state compared as 64 bits", make(hold=lambda slab, count: {s["user"] for s in slab[:count] if s["state"] != VACANT})),
        ("vacant state 3", make(hold=lambda slab, count: {s["user"] for s in slab[:count] if s["state"] & MASK[4] != 3})),
        ("held users still removed", make(hold=lambda slab, count: set())),
        ("nothing removed", make(keep=lambda gone: set())),
        ("everything removed", make(keep=lambda gone: {user_id(n) for n in range(1, 200)})),
        ("one removal skipped", make(keep=lambda gone: set(sorted(gone)[1:]))),
        ("last removal skipped", make(keep=lambda gone: set(sorted(gone)[:-1]))),
        ("only state zero holds", make(hold=lambda slab, count: {s["user"] for s in slab[:count] if s["state"] == 0})),
        ("length word left stale", make(length=lambda total, gone, kept: total)),
        ("length word counts one extra", make(length=lambda total, gone, kept: kept + 1)),
    ]


def corrupt_controls(image, cases, reached_rows):
    """Byte damage and out-of-range inputs: each entry returns True when the damage is detected."""
    outcomes = []
    blob = bytes(image.blob)

    def digest_detected(data):
        try:
            if hashlib.sha256(data).hexdigest() != SHA256:
                raise EvidenceError("binary SHA-256 mismatch")
        except EvidenceError:
            return True
        return False

    flipped = bytearray(blob[:4096])
    outcomes.append(("digest of a 4 KiB prefix is not the binary digest", digest_detected(bytes(flipped))))
    outcomes.append(("digest of the binary with a dropped last byte", digest_detected(blob[:-1])))
    tail = bytearray(blob[-64:])
    tail[-1] ^= 1
    outcomes.append(("digest of a binary with the last byte flipped", digest_detected(blob[:-64] + bytes(tail))))
    for name, bad in (("address 0x1 is outside every FDE", 0x1), ("middle of a closure is not an FDE start", ROW_CLOSURE + 4), ("address past the text is outside every FDE", 0x7FFFFFFF)):
        try:
            image.exact_fde(bad)
            outcomes.append((name, False))
        except EvidenceError:
            outcomes.append((name, True))
    try:
        image.offset(0x1)
        outcomes.append(("file offset of an unmapped address", False))
    except EvidenceError:
        outcomes.append(("file offset of an unmapped address", True))
    return outcomes


def patch_controls(image, cases):
    """Named single-byte patches of the real closure and filter; each must change some case."""
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    probe = cases[:700]
    picks = []
    for function, meaning, wanted in ANCHORS:
        begin, body = function_bytes(image, function)
        at = body.find(bytes.fromhex(wanted))
        picks.append((meaning + " at %#x" % (begin + at), begin + at, len(wanted) // 2))
    results = []
    for label, va, size in picks:
        found = False
        for tweak in range(size):
            byte = code(image, va + tweak, 1)[0]
            machine.patches = {va + tweak: byte ^ 1}
            machine.cache.clear()
            for case in probe:
                if compare_run(harness, case):
                    found = True
                    break
            if found:
                break
        machine.patches = {}
        machine.cache.clear()
        results.append(("flip a byte of: " + label, found))
    return results


def spec_controls(image, cases):
    harness = Harness(image)
    probe = cases[:900]
    found = []
    for case in probe:
        try:
            found.append(harness.run(case))
        except CRASHES as error:
            raise EvidenceError("probe case crashed: %s" % error)
    out = []
    for name, spec in wrong_specs():
        out.append(("wrong rule: " + name, any(spec(case) != answer for case, answer in zip(probe, found))))
    return out


# ---- evidence ----

def outcome_name(case):
    gone = len(removed(case.world))
    if not case.world["entries"]:
        return "map without a root"
    return "removes %s" % ("nothing" if not gone else "every entry" if gone == len(case.world["entries"]) else "some entries")


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    machine = harness.machine
    mismatches = []
    outcomes = {}
    sets, interned, reached, costs = [], {}, [], []
    seen = set()
    lines = []
    for case in cases:
        machine.seen = set()
        before = machine.steps
        trouble = compare_run(harness, case)
        costs.append(machine.steps - before)
        if trouble:
            mismatches.append(trouble)
        frozen = frozenset(machine.seen)
        which = interned.get(frozen)
        if which is None:
            which = interned[frozen] = len(sets)
            sets.append(frozen)
        reached.append(which)
        seen |= machine.seen
        name = outcome_name(case)
        outcomes[name] = outcomes.get(name, 0) + 1
        if len(lines) < SAMPLE_LINES:
            lines.append("%s\t%s\t%s" % (case.closure, case.label.replace(": ", "\t", 1) if ": " in case.label else case.label + "\t", name))
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    for start, role, stop in GROUPS:
        begin, limit, end = group_rows(image, start, stop)
        rows = decode_range(image, begin, limit)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    controls = []
    if full:
        controls = corrupt_controls(image, cases, None) + spec_controls(image, cases) + patch_controls(image, cases)
    results_rows = run_mutants(image, cases, reached, sets, costs, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/115/hl-node", "sha256": SHA256},
        "functions": functions,
        "step_name": step_name_rows(image),
        "anchors": anchor_rows(image),
        "closure_copies": copy_table(image),
        "layout": LAYOUT,
        "rule_table": rule_table(),
        "cases": {"total": len(cases), "structured": len(structured_cases()), "random_per_closure": RANDOM_CASES},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": machine.steps,
        "mutations": tally,
        "negative_controls": {"total": len(controls), "detected": sum(1 for _, ok in controls if ok), "undetected": [name for name, ok in controls if not ok]},
        "not_modelled": NOT_MODELLED,
        "_results": results_rows, "_lines": lines, "_controls": controls,
    }


SAMPLE_LINES = 600
LAYOUT = {
    "book": {"stride": "0x120", "+0x88/+0x90": "slab pointer and length", "+0xe8": "user_states map, an enum: niche word 0x8000000000000000 = B-tree (root +0xf0, height +0xf8, length +0x100), else sorted ring (capacity +0xe8, pointer +0xf0, head +0xf8, length +0x100, entries of 0x70)"},
    "slab_slot": {"stride": "0x110", "+0x00": "state dword, 2 = vacant", "+0xf8": "20 byte user"},
    "user_states_node": {"+0x000": "parent", "+0x008": "11 values of 0x58 bytes", "+0x3d0": "11 keys of 20 bytes", "+0x4ac": "parent index", "+0x4ae": "length", "+0x4b0": "12 edges, internal nodes only"},
    "user_state_value": {"+0x00": "field r, vector of 8 byte items: capacity, pointer, length", "+0x20": "field b, the same enum as user_states; length word at +0x38", "+0x40": "field u, B-tree root, height, length; length word at +0x50"},
    "set_node": {"+0x00": "parent", "+0x08": "11 keys of 20 bytes", "+0xe4": "parent index", "+0xe6": "length", "+0xe8": "12 edges", "size": "0x148 internal, 0xe8 leaf"},
}
NOT_MODELLED = [
    "ring buffer form of user_states: the collector 0x2e41e50 / 0x2e41cf0 enters the rayon join (work stealing deque, atomics, sleep counters), which this evaluator does not model",
    "the inlined step bodies in the three hosts (0x2bdf8f0, 0x54a9c70, 0x54b66b0): their loop around the closures is not run",
    "thread pool split arms: every run is the plain sequential path of a worker thread",
]

UNREACHED_REASON = "no case in the list reaches it: ring buffer form, thread pool split arms, tree height 4 or more, allocator failure, panic and unwind arms are not exercised"
SURVIVED_REASON = "not classified: no case in the list changes its result; it may be thread plumbing, a capacity or search start word, or an arm the list does not exercise"


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    controls = evidence.pop("_controls")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    files["cases.tsv"] = "\n".join(["closure\tlabel\toutcome"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    for row_ in results:
        if row_["result"] == "killed":
            continue
        lines.append("%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], UNREACHED_REASON if row_["result"] == "unreached" else SURVIVED_REASON))
    files["mutations_not_killed.tsv"] = "\n".join(lines) + "\n"
    files["controls.tsv"] = "\n".join(["control\tdetected"] + ["%s\t%d" % (name, int(ok)) for name, ok in controls]) + "\n"
    summary = {"cases": evidence["cases"]["total"], "negative_controls": evidence["negative_controls"]["total"], "negative_detected": evidence["negative_controls"]["detected"],
               "mutants": sum(evidence["mutations"].values()), "mutants_killed": evidence["mutations"]["killed"], "mutants_survived": evidence["mutations"]["survived"], "mutants_unreached": evidence["mutations"]["unreached"]}
    files["measure.json"] = json.dumps(summary, indent=2, sort_keys=True) + "\n"
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
