#!/usr/bin/env python3
"""Rebuild the node #115 book order peer link and parent detach bodies and prove them on the bytes.

Four bodies (link 0x58e4300 / 0x58e48e0, detach 0x58e4ec0 / 0x58e5510) take a book, a 20-byte user key and order ids.
Each one finds an order record either through the order-id hash map into the book's slab (0x110-byte slots) or through
the per-user store (a sorted ring or a B-tree of users, then a sorted ring or a B-tree of orders). The link bodies set the
peer option of two orders to each other; the detach bodies take the parent option of an order and drop that order id from the
parent's child list. The real bytes of each body run in a Python x86-64 evaluator with only the lookups below them stubbed
(the order-id map probe, the two sorted-ring searches, the 20-byte compare and the bounds panic). A separately written
specification of the book layout predicts every stub call and every byte the body writes. Branch conditions are then
flipped on the bytes to show that the comparison can fail. No disassembler or ELF dump text is parsed and the binary is
never executed. Standard library only.
"""

import argparse
import bisect
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

LINK = "link"
DETACH = "detach"
# entry, end, operation
BODIES = (
    dict(entry=0x58E4300, end=0x58E48D9, op=LINK),
    dict(entry=0x58E48E0, end=0x58E4EB9, op=LINK),
    dict(entry=0x58E4EC0, end=0x58E5504, op=DETACH),
    dict(entry=0x58E5510, end=0x58E5B54, op=DETACH),
)
OID_PROBE = 0x4EF4010
RING_USERS = 0x57F7BD0
RING_ORDERS = 0x57FBF50
GOT_COMPARE = 0x64DFB50
GOT_PANIC = 0x64DF620
PANIC_LOCATION = 0x649E918
FAKE_COMPARE = 0x7E000000
FAKE_PANIC = 0x7E000100

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
MUTANT_STEP_LIMIT = 6000

# book layout read by the bodies
BOOK_INDEX_PTR, BOOK_INDEX_LEN = 0x8, 0x10
BOOK_SLAB_PTR, BOOK_SLAB_LEN = 0x88, 0x90
USERS_CAP, USERS_PTR, USERS_HEAD, USERS_LEN = 0xE8, 0xF0, 0xF8, 0x100
INDEX_STRIDE, INDEX_SLOT = 24, 0x10
SLAB_STRIDE, SLAB_KEY, SLAB_BODY = 0x110, 0xF8, 0x20
USER_STRIDE, USER_BODY = 0x70, 0x18
USER_CAP, USER_PTR_OR_ROOT, USER_HEAD_OR_HEIGHT, USER_LEN = 0x20, 0x28, 0x30, 0x38
ORDER_RING_STRIDE, ORDER_RING_BODY = 0xE0, 8
UNIVERSAL_NICHE = 0x8000000000000000
VACANT = 2
KEY_BYTES = 20
# user B-tree node
UT_KEYS, UT_VALS, UT_VAL_STRIDE, UT_LEN, UT_EDGES = 0x3D0, 0x8, 0x58, 0x4AE, 0x4B0
# order B-tree node
OT_KEYS, OT_VALS, OT_VAL_STRIDE, OT_LEN, OT_EDGES = 0x8, 0x60, 0xD8, 0x9AA, 0x9B0
NODE_CAPACITY = 11
# order body
PARENT_TAG, PARENT_ID, PEER_TAG, PEER_ID, KIDS_PTR, KIDS_LEN = 0x10, 0x18, 0x20, 0x28, 0x38, 0x40
BODY_BYTES = 0x58

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
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x74 and opsize:
            reg, rm = modrm(True)
            return finish("pcmpeqb", ("x", reg), rm, 16)
        if two == 0xDB and opsize:
            reg, rm = modrm(True)
            return finish("pand", ("x", reg), rm, 16)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
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
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "pcmpeqb":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((0xFF if (left >> (8 * i)) & 0xFF == (right >> (8 * i)) & 0xFF else 0) << (8 * i) for i in range(16))
        elif op == "pand":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "pmovmskb":
            value = self.vector(row.b)
            self.regs[row.a[1]] = sum(((value >> (8 * i + 7)) & 1) << i for i in range(16))
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# ---- specification: the book layout the bodies read, written from the pinned loads and stores ----


def lcg(seed):
    state = (seed * 6364136223846793005 + 1442695040888963407) & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 33


class Rng:
    def __init__(self, seed):
        self.gen = lcg(seed)

    def below(self, count):
        return next(self.gen) % count

    def between(self, low, high):
        return low + self.below(high - low + 1)

    def chance(self, percent):
        return self.below(100) < percent

    def pick(self, items):
        return items[self.below(len(items))]

    def blob(self, count):
        gen = self.gen
        data = b"".join(((next(gen) << 31) ^ next(gen)).to_bytes(8, "little") for _ in range((count + 7) // 8))
        return data[:count]

    def key20(self):
        return self.blob(KEY_BYTES)


class Order:
    """One order record: tag dword, then the body (8 bytes on when the tag is the vacant niche)."""

    def __init__(self, oid, tag, parent, peer, kids, junk):
        self.oid, self.tag, self.parent, self.peer, self.kids = oid, tag, parent, peer, list(kids)
        self.junk = junk
        self.body = self.kids_at = self.kids_cap = None


class Node:
    def __init__(self, keys, vals, kids):
        self.keys, self.vals, self.kids = keys, vals, kids
        self.addr = None


class UserRec:
    def __init__(self, key, orders, mode, rng):
        self.key, self.mode = key, mode
        self.orders = orders  # sorted by oid
        self.root = None
        self.height = 0
        self.cap = self.head = 0
        self.ptr = None
        self.pos = {}
        self.body = None


class World:
    """Everything the body can reach for one call."""

    def __init__(self):
        self.users_mode = "ring"
        self.users = []
        self.users_root = None
        self.users_height = 0
        self.users_cap = self.users_head = 0
        self.users_ring = None
        self.user_pos = {}
        self.oid_map = {}
        self.index_len = 0
        self.index_slots = []
        self.slab = []
        self.slab_ptr = 0
        self.rings = {}
        self.book = self.key_at = 0
        self.liars = set()


def compare_value(left, right):
    if left == right:
        return 0
    for a, b in zip(left, right):
        if a != b:
            return a - b
    return 0


def shape(rng, height):
    if height == 0:
        return rng.between(1, NODE_CAPACITY)
    return [shape(rng, height - 1) for _ in range(rng.between(2, 4))]


def count_keys(plan):
    if isinstance(plan, int):
        return plan
    return sum(count_keys(child) for child in plan) + len(plan) - 1


def assemble(plan, items, at):
    if isinstance(plan, int):
        take = items[at[0]:at[0] + plan]
        at[0] += plan
        return Node([k for k, _ in take], [v for _, v in take], [])
    kids, keys, vals = [], [], []
    for number, child in enumerate(plan):
        kids.append(assemble(child, items, at))
        if number < len(plan) - 1:
            keys.append(items[at[0]][0])
            vals.append(items[at[0]][1])
            at[0] += 1
    return Node(keys, vals, kids)


class Builder:
    """Writes the world into the evaluator heap and records every address the specification needs."""

    def __init__(self, machine):
        self.machine = machine
        self.memory = machine.memory
        self.top = HEAP_BASE + 0x40

    def alloc(self, count, align=16):
        self.top = (self.top + align - 1) // align * align
        at = self.top
        self.top += count
        if self.top - HEAP_BASE > HEAP_SIZE - 0x2000:
            raise EvidenceError("world does not fit the heap")
        return at

    def put(self, addr, size, value):
        self.memory.write(addr, size, value)

    def fill(self, addr, count, rng):
        self.memory.put_bytes(addr, rng.blob(count))

    def write_order(self, order, value_at, rng, size, body=None):
        self.fill(value_at, size, rng)
        self.put(value_at, 4, order.tag)
        order.body = body if body is not None else value_at + (8 if order.tag == VACANT else 0)
        self.put(order.body + PARENT_TAG, 8, (1 if order.parent is not None else 0) | order.junk << 32)
        self.put(order.body + PARENT_ID, 8, order.parent if order.parent is not None else order.junk)
        self.put(order.body + PEER_TAG, 8, 1 if order.peer is not None else order.junk << 32)
        self.put(order.body + PEER_ID, 8, order.peer if order.peer is not None else order.junk)
        order.kids_cap = len(order.kids) + rng.below(3)
        order.kids_at = self.alloc(8 * max(order.kids_cap, 1), 8)
        for number, kid in enumerate(order.kids):
            self.put(order.kids_at + 8 * number, 8, kid)
        for number in range(len(order.kids), order.kids_cap):
            self.put(order.kids_at + 8 * number, 8, rng.below(1 << 30) | 1 << 40)
        self.put(order.body + 0x30, 8, order.kids_cap)
        self.put(order.body + KIDS_PTR, 8, order.kids_at)
        self.put(order.body + KIDS_LEN, 8, len(order.kids))

    def write_tree(self, node, user_kind, rng, writer):
        node.addr = self.alloc(0x520 if user_kind else 0xA20, 16)
        self.fill(node.addr, 0x520 if user_kind else 0xA20, rng)
        for number, child in enumerate(node.kids):
            self.write_tree(child, user_kind, rng, writer)
            self.put(node.addr + (UT_EDGES if user_kind else OT_EDGES) + 8 * number, 8, child.addr)
        self.put(node.addr + (UT_LEN if user_kind else OT_LEN), 2, len(node.keys))
        for number, (key, val) in enumerate(zip(node.keys, node.vals)):
            if user_kind:
                self.memory.put_bytes(node.addr + UT_KEYS + KEY_BYTES * number, key)
                writer(val, node.addr + UT_VALS + UT_VAL_STRIDE * number)
            else:
                self.put(node.addr + OT_KEYS + 8 * number, 8, key)
                writer(val, node.addr + OT_VALS + OT_VAL_STRIDE * number)
        if len(node.kids):
            self.put(node.addr + (UT_EDGES if user_kind else OT_EDGES) + 8 * len(node.kids), 8, 0)
        if not user_kind:
            for number in range(len(node.keys), NODE_CAPACITY):
                self.put(node.addr + OT_KEYS + 8 * number, 8, rng.below(5000))


def make_order(rng, oid, ids, tag_percent=20):
    tag = VACANT if rng.chance(tag_percent) else 0
    parent = rng.pick(ids) if ids and rng.chance(55) else None
    peer = rng.pick(ids) if ids and rng.chance(30) else None
    kids = []
    for _ in range(rng.between(0, 9) if rng.chance(70) else 0):
        kids.append(rng.pick(ids) if ids and rng.chance(75) else rng.between(1, 1 << 30))
    return Order(oid, tag, parent, peer, kids, rng.below(1 << 30))


def order_ids(rng, count):
    ids = set()
    while len(ids) < count:
        ids.add(rng.between(1, 1 << 40) if rng.chance(80) else rng.between(1, 200))
    return sorted(ids)


def build_world(machine, rng, plan):
    """Create one world from a plan dict (a few choices) and write it into the evaluator heap."""
    builder = Builder(machine)
    world = World()
    world.builder = builder
    book = builder.alloc(0x120)
    builder.fill(book, 0x120, rng)
    world.book = book
    # users
    user_count = plan["users"]
    keys = sorted({rng.key20() for _ in range(user_count)})
    world.absent_keys = [extreme for extreme in (b"\xff" * KEY_BYTES, b"\x00" * KEY_BYTES) if extreme not in keys]
    for near in keys[:3]:
        twin = near[:-1] + bytes([near[-1] ^ 1])
        if twin not in keys and twin not in world.absent_keys:
            world.absent_keys.append(twin)
    while len(world.absent_keys) < 4:
        extra = rng.key20()
        if extra not in keys:
            world.absent_keys.append(extra)
    all_ids = order_ids(rng, plan["orders"] + 6)
    for number, key in enumerate(keys):
        count = plan["orders"] if number == plan["target"] % max(len(keys), 1) else rng.between(0, 5)
        ids = sorted(rng.pick(all_ids) for _ in range(count))
        ids = sorted(set(ids))
        mode = plan["order_mode"] if number == plan["target"] % max(len(keys), 1) else rng.pick(["ring", "tree"])
        orders = [make_order(rng, oid, all_ids) for oid in ids]
        user = UserRec(key, orders, mode, rng)
        world.users.append(user)
    world.ids = all_ids
    # user body writers
    def write_user(user, body):
        user.body = body
        builder.fill(body, BODY_BYTES, rng)
        if user.mode == "tree":
            builder.put(body + USER_CAP, 8, UNIVERSAL_NICHE)
            pairs = [(order.oid, order) for order in user.orders]
            if not pairs:
                user.root, user.height = None, 0
                builder.put(body + USER_PTR_OR_ROOT, 8, 0)
                builder.put(body + USER_HEAD_OR_HEIGHT, 8, rng.below(3))
                return
            user.height = 0
            # split into a height-1 tree when the orders do not fit a single node, or when asked to
            if len(pairs) > NODE_CAPACITY or (plan["order_height"] > 0 and len(pairs) >= 3):
                user.root = split_tree(pairs, rng)
                user.height = tree_height(user.root)
            else:
                user.root = Node([k for k, _ in pairs], [v for _, v in pairs], [])
            builder.write_tree(user.root, False, rng, lambda order, at: builder.write_order(order, at, rng, OT_VAL_STRIDE))
            builder.put(body + USER_PTR_OR_ROOT, 8, user.root.addr)
            builder.put(body + USER_HEAD_OR_HEIGHT, 8, user.height)
        else:
            count = len(user.orders)
            user.cap = count + rng.below(3) + (1 if count == 0 else 0)
            user.head = rng.below(user.cap)
            user.ptr = builder.alloc(ORDER_RING_STRIDE * user.cap, 16)
            builder.fill(user.ptr, ORDER_RING_STRIDE * user.cap, rng)
            builder.put(body + USER_CAP, 8, user.cap)
            builder.put(body + USER_PTR_OR_ROOT, 8, user.ptr)
            builder.put(body + USER_HEAD_OR_HEIGHT, 8, user.head)
            builder.put(body + USER_LEN, 8, count)
            user.pos = {}
            for number, order in enumerate(user.orders):
                at = user.ptr + ((user.head + number) % user.cap) * ORDER_RING_STRIDE
                builder.write_order(order, at + ORDER_RING_BODY, rng, ORDER_RING_STRIDE - ORDER_RING_BODY)
                user.pos[order.oid] = number
            world.rings[body + USER_CAP] = user.pos
    if plan["users_mode"] == "tree":
        world.users_mode = "tree"
        builder.put(book + USERS_CAP, 8, UNIVERSAL_NICHE)
        pairs = [(user.key, user) for user in world.users]
        if not pairs:
            world.users_root = None
            builder.put(book + USERS_PTR, 8, 0)
            builder.put(book + USERS_HEAD, 8, rng.below(3))
        else:
            if len(pairs) > NODE_CAPACITY or (plan["users_height"] > 0 and len(pairs) >= 3):
                world.users_root = split_tree(pairs, rng)
            else:
                world.users_root = Node([k for k, _ in pairs], [v for _, v in pairs], [])
            world.users_height = tree_height(world.users_root)
            builder.write_tree(world.users_root, True, rng, write_user)
            builder.put(book + USERS_PTR, 8, world.users_root.addr)
            builder.put(book + USERS_HEAD, 8, world.users_height)
    else:
        world.users_mode = "ring"
        count = len(world.users)
        world.users_cap = count + rng.below(3) + (1 if count == 0 else 0)
        world.users_head = rng.below(world.users_cap)
        world.users_ring = builder.alloc(USER_STRIDE * world.users_cap, 16)
        builder.fill(world.users_ring, USER_STRIDE * world.users_cap, rng)
        builder.put(book + USERS_CAP, 8, world.users_cap)
        builder.put(book + USERS_PTR, 8, world.users_ring)
        builder.put(book + USERS_HEAD, 8, world.users_head)
        builder.put(book + USERS_LEN, 8, count)
        world.user_pos = {}
        for number, user in enumerate(world.users):
            at = world.users_ring + ((world.users_head + number) % world.users_cap) * USER_STRIDE
            write_user(user, at + USER_BODY)
            world.user_pos[user.key] = number
        world.rings[book + USERS_CAP] = world.user_pos
    # slab and the order-id map
    slab_count = plan["slab"]
    world.slab_ptr = builder.alloc(SLAB_STRIDE * (slab_count + 3), 16)
    builder.put(book + BOOK_SLAB_PTR, 8, world.slab_ptr)
    builder.put(book + BOOK_SLAB_LEN, 8, slab_count)
    builder.fill(world.slab_ptr, SLAB_STRIDE * (slab_count + 3), rng)
    for number in range(slab_count):
        at = world.slab_ptr + number * SLAB_STRIDE
        tag = VACANT if rng.chance(20) else 0
        user_key = rng.pick(keys) if keys and rng.chance(75) else rng.key20()
        order = make_order(rng, 0, all_ids, 0)
        order.tag = tag
        builder.write_order(order, at + SLAB_BODY, rng, 0x58, body=at + SLAB_BODY)
        builder.put(at, 4, tag)
        builder.memory.put_bytes(at + SLAB_KEY, user_key)
        world.slab.append(dict(tag=tag, key=user_key, order=order))
    index_len = plan["index"]
    world.index_len = index_len
    world.index_ptr = builder.alloc(INDEX_STRIDE * max(index_len, 1), 16)
    builder.fill(world.index_ptr, INDEX_STRIDE * max(index_len, 1), rng)
    builder.put(book + BOOK_INDEX_PTR, 8, world.index_ptr)
    builder.put(book + BOOK_INDEX_LEN, 8, index_len)
    for number in range(index_len):
        slot = rng.below(slab_count + 2) if slab_count else rng.below(3)
        world.index_slots.append(slot)
        builder.put(world.index_ptr + number * INDEX_STRIDE + INDEX_SLOT, 8, slot)
    world.oid_map = {}
    return world


def tree_height(node):
    return 0 if not node.kids else 1 + tree_height(node.kids[0])


def split_tree(pairs, rng):
    """A height-1 or height-2 tree over the sorted pairs; every node holds 1..11 keys."""
    count = len(pairs)
    if count <= NODE_CAPACITY and not rng.chance(50):
        return Node([k for k, _ in pairs], [v for _, v in pairs], [])
    for height in (1, 2):
        low = 3 if height == 1 else 7
        high = 4 * NODE_CAPACITY + 3 if height == 1 else 4 * (4 * NODE_CAPACITY + 3) + 3
        if low <= count <= high:
            chosen = height if (height == 1 or count > 4 * NODE_CAPACITY + 3 or rng.chance(35)) else 1
            if chosen == 1 and count > 4 * NODE_CAPACITY + 3:
                chosen = 2
            for attempt in range(60):
                tree_plan = shape(rng, chosen)
                if count_keys(tree_plan) == count:
                    return assemble(tree_plan, pairs, [0])
            return assemble(even_plan(count, chosen), pairs, [0])
    return assemble(even_plan(count, 1 if count <= 4 * NODE_CAPACITY + 3 else 2), pairs, [0])


def even_plan(count, height):
    if height == 0:
        return count
    children = 2
    while True:
        rest = count - (children - 1)
        base, extra = divmod(rest, children)
        sizes = [base + (1 if n < extra else 0) for n in range(children)]
        if height == 1 and all(1 <= s <= NODE_CAPACITY for s in sizes):
            return sizes
        if height == 2 and all(3 <= s <= 4 * NODE_CAPACITY + 3 for s in sizes):
            return [even_plan(s, 1) for s in sizes]
        children += 1
        if children > 5:
            raise EvidenceError("cannot shape tree for %d keys" % count)


class SpecPanic(Exception):
    def __init__(self, index):
        self.index = index


class Spec:
    """Predicts the stub calls, the panic and the byte writes of one call."""

    def __init__(self, world):
        self.world = world
        self.log = []
        self.writes = []
        self.panic = None

    def walk(self, root, height, key, user_kind):
        node = root
        remaining = height
        if node is None:
            return None
        while True:
            at = len(node.keys)
            for number, node_key in enumerate(node.keys):
                if user_kind:
                    self.log.append(("cmp", key, node_key))
                    order = compare_value(key, node_key)
                else:
                    order = (key > node_key) - (key < node_key)
                if order == 0:
                    return node.vals[number]
                if order < 0:
                    at = number
                    break
            if remaining == 0:
                return None
            remaining -= 1
            node = node.kids[at]

    def locate(self, key, oid):
        """Address of the order body, or None."""
        world = self.world
        self.log.append(("oid", oid))
        if oid in world.oid_map:
            index = world.oid_map[oid]
            if index >= world.index_len:
                raise SpecPanic(index)
            slot = world.index_slots[index]
            if slot >= len(world.slab):
                return None
            entry = world.slab[slot]
            if entry["tag"] == VACANT or entry["key"] != key:
                return None
            return entry["order"]
        if world.users_mode == "tree":
            user = self.walk(world.users_root, world.users_height, key, True)
        else:
            self.log.append(("users", key))
            position = world.user_pos.get(key)
            if position is None or position >= len(world.users):
                return None
            user = world.users[position]
        if user is None:
            return None
        if user.mode == "tree":
            return self.walk(user.root, user.height, oid, False)
        self.log.append(("orders", oid))
        position = user.pos.get(oid)
        if position is None or position >= len(user.orders):
            return None
        return user.orders[position]

    def store(self, addr, size, value):
        self.writes.append((addr, size, value))

    def link(self, key, first, second):
        order = self.locate(key, first)
        if order is not None:
            self.store(order.body + PEER_TAG, 8, 1)
            self.store(order.body + PEER_ID, 8, second)
            order.peer = second
        order = self.locate(key, second)
        if order is not None:
            self.store(order.body + PEER_TAG, 8, 1)
            self.store(order.body + PEER_ID, 8, first)
            order.peer = first

    def detach(self, key, oid):
        order = self.locate(key, oid)
        if order is None:
            return
        parent_tag = 1 if order.parent is not None else 0
        parent = order.parent
        self.store(order.body + PARENT_TAG, 8, 0)
        order.parent = None
        if parent_tag != 1:
            return
        holder = self.locate(key, parent)
        if holder is None or not holder.kids:
            return
        if oid not in holder.kids:
            return
        kept = [kid for kid in holder.kids if kid != oid]
        for number, kid in enumerate(kept):
            self.store(holder.kids_at + 8 * number, 8, kid)
        self.store(holder.body + KIDS_LEN, 8, len(kept))
        holder.kids = kept

    def run(self, op, key, first, second):
        try:
            if op == LINK:
                self.link(key, first, second)
            else:
                self.detach(key, first)
        except SpecPanic as caught:
            self.panic = (caught.index, PANIC_LOCATION)
        return self


# ---- harness ----


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.world = None
        self.log = []
        self.used = HEAP_SIZE
        self.hooks = {
            OID_PROBE: self.hook_oid,
            RING_USERS: self.hook_ring,
            RING_ORDERS: self.hook_ring,
        }
        self.machine.calls = dict(self.hooks)
        self.machine.slots = {FAKE_COMPARE: self.hook_compare, FAKE_PANIC: self.hook_panic}
        self.machine.memory.statics[GOT_COMPARE] = FAKE_COMPARE
        self.machine.memory.statics[GOT_PANIC] = FAKE_PANIC

    def hook_oid(self, machine):
        book, oid = machine.regs[RDI], machine.regs[RSI]
        if book != self.world.book:
            raise Halt("probe called with another book")
        self.log.append(("oid", oid))
        index = self.world.oid_map.get(oid)
        if index is None:
            machine.regs[RAX] = 0
        else:
            machine.regs[RAX] = 1
            machine.regs[RDX] = index
            machine.keep_rdx = True

    def hook_ring(self, machine):
        table = self.world.rings.get(machine.regs[RDI])
        if table is None:
            raise Halt("ring search on an unknown ring")
        if machine.regs[RDI] == self.world.book + USERS_CAP:
            key = bytes(machine.memory.bytes_at(machine.regs[RSI], KEY_BYTES))
            self.log.append(("users", key))
        else:
            key = machine.memory.read(machine.regs[RSI], 8)
            self.log.append(("orders", key))
        position = table.get(key)
        if position is None:
            machine.regs[RAX] = 1
            machine.regs[RDX] = sum(1 for other in table if other < key)
            machine.keep_rdx = True
        else:
            machine.regs[RAX] = 0
            machine.regs[RDX] = position
            machine.keep_rdx = True

    def hook_compare(self, machine):
        left = bytes(machine.memory.bytes_at(machine.regs[RDI], KEY_BYTES))
        right = bytes(machine.memory.bytes_at(machine.regs[RSI], KEY_BYTES))
        if machine.regs[RDX] != KEY_BYTES:
            raise Halt("compare length")
        self.log.append(("cmp", left, right))
        machine.regs[RAX] = compare_value(left, right) & MASK[4]

    def hook_panic(self, machine):
        raise Panicked((machine.regs[RDI], machine.regs[RDX]))

    def call(self, entry, world, key, first, second):
        machine = self.machine
        self.log = []
        key_at = world.builder.alloc(32, 16)
        world.builder.memory.put_bytes(key_at, key)
        before = bytes(machine.memory.heap[:world.builder.top - HEAP_BASE])
        args = {RDI: world.book, RSI: key_at, RDX: first, RCX: second}
        panic = None
        try:
            machine.run(entry, args)
        except Panicked as caught:
            panic = caught.args[0]
        after = bytes(machine.memory.heap[:world.builder.top - HEAP_BASE])
        return before, after, panic


def expected_after(before, writes):
    out = bytearray(before)
    for addr, size, value in writes:
        at = addr - HEAP_BASE
        out[at:at + size] = (value & MASK[size]).to_bytes(size, "little")
    return bytes(out)


def make_plan(rng, body):
    detach = body["op"] == DETACH
    return dict(
        users=rng.pick([0, 1, 1, 1, 2, 3, 5, 8, 12, 20, 40]),
        users_mode=rng.pick(["ring", "tree"]),
        users_height=rng.pick([0, 1, 1, 2]),
        orders=rng.pick([1, 2, 3, 6, 11, 14, 25, 40, 0]),
        order_mode=rng.pick(["ring", "tree"]),
        order_height=rng.pick([0, 1, 1]),
        target=rng.below(1000),
        slab=rng.pick([0, 1, 1, 2, 3, 6, 8]),
        index=rng.pick([0, 1, 2, 3, 4, 4]),
        detach=detach,
    )


def choose_call(rng, world, op):
    """Pick the user key and the order ids the call uses, and the slab-map entries that answer them."""
    plan_users = world.users
    if plan_users and rng.chance(88):
        user = plan_users[rng.below(len(plan_users))]
        key = user.key
    else:
        user = None
        key = rng.pick(world.absent_keys)
    pool = [order.oid for u in plan_users for order in u.orders]
    own = [order.oid for order in user.orders] if user else []

    top = max(pool) if pool else 1000
    low = min(pool) if pool else 1

    def pick_id():
        roll = rng.below(100)
        if own and roll < 55:
            return rng.pick(own)
        if pool and roll < 70:
            return rng.pick(pool)
        if roll < 82:
            return top + rng.between(1, 1 << 20)
        if roll < 92 and low > 1:
            return rng.between(1, low - 1)
        return rng.between(1, 1 << 40)

    first, second = pick_id(), pick_id()
    quiet = rng.chance(16)
    if quiet:
        key = rng.pick(world.absent_keys) if rng.chance(70) else key
    else:
        for oid in (first, second):
            aim_map(world, rng, key, oid)
    # give detach a parent chain: first's parent sometimes owns first as a child
    if op == DETACH and user and user.orders:
        for order in user.orders:
            if order.oid == first and rng.chance(70):
                holder = rng.pick(user.orders)
                set_parent(world, order, holder.oid)
                aim_map(world, rng, key, holder.oid, first)
                if rng.chance(80):
                    kids = [rng.between(1, 1 << 30) for _ in range(rng.between(0, 12))]
                    for _ in range(rng.between(0, 3)):
                        kids.insert(rng.below(len(kids) + 1), first)
                    set_kids(world, holder, kids, rng)
    return key, first, second


def bind_parent_children(world, rng):
    """Not needed: kids lists were drawn from the id pool, so duplicates and misses both occur."""
    return None


def set_parent(world, order, parent):
    order.parent = parent
    world.builder.put(order.body + PARENT_TAG, 8, 1 if parent is not None else 0)
    world.builder.put(order.body + PARENT_ID, 8, parent if parent is not None else order.junk)


def set_kids(world, holder, kids, rng):
    builder = world.builder
    holder.kids = list(kids)
    holder.kids_cap = len(kids) + rng.below(3)
    holder.kids_at = builder.alloc(8 * max(holder.kids_cap, 1), 8)
    for number in range(holder.kids_cap):
        builder.put(holder.kids_at + 8 * number, 8, kids[number] if number < len(kids) else rng.below(1 << 30) | 1 << 40)
    builder.put(holder.body + 0x30, 8, holder.kids_cap)
    builder.put(holder.body + KIDS_PTR, 8, holder.kids_at)
    builder.put(holder.body + KIDS_LEN, 8, len(kids))


def aim_map(world, rng, key, oid, kid=None):
    """Let the order-id map answer `oid` from the slab in one of its several ways (or not at all)."""
    roll = rng.below(100)
    if kid is not None and roll < 25:
        roll += 25
    if roll < 40 or not world.index_len:
        if roll >= 94 and not world.index_len:
            world.oid_map[oid] = world.index_len + rng.below(2)
        return
    if roll >= 94:
        world.oid_map[oid] = world.index_len + rng.below(2)
        return
    builder = world.builder
    index = rng.below(world.index_len)
    world.oid_map[oid] = index
    if rng.chance(12) or not world.slab:
        slot = len(world.slab) + rng.below(3)
    else:
        slot = rng.below(len(world.slab))
    world.index_slots[index] = slot
    builder.put(world.index_ptr + index * INDEX_STRIDE + INDEX_SLOT, 8, slot)
    if slot >= len(world.slab):
        # a well-formed slot lies just past the slab length, so only the length check keeps the body out of it
        at = world.slab_ptr + slot * SLAB_STRIDE
        trap = make_order(rng, 0, world.ids, 0)
        trap.kids = [kid] if kid is not None else []
        builder.write_order(trap, at + SLAB_BODY, rng, 0x58, body=at + SLAB_BODY)
        builder.put(at, 4, 0)
        builder.memory.put_bytes(at + SLAB_KEY, key)
    if slot < len(world.slab):
        entry = world.slab[slot]
        at = world.slab_ptr + slot * SLAB_STRIDE
        if rng.chance(78):
            entry["key"] = key
        else:
            entry["key"] = bytes([key[0] ^ 1]) + key[1:] if rng.chance(50) else key[:-1] + bytes([key[-1] ^ 0x80])
        builder.memory.put_bytes(at + SLAB_KEY, entry["key"])
        if kid is not None and rng.chance(85):
            others = [rng.between(1, 1 << 30) for _ in range(rng.between(0, 6))]
            others.insert(rng.below(len(others) + 1), kid)
            set_kids(world, entry["order"], others, rng)
        if rng.chance(30):
            entry["tag"] = VACANT
            builder.put(at, 4, VACANT)
        elif entry["tag"] == VACANT:
            entry["tag"] = rng.below(2)
            builder.put(at, 4, entry["tag"])


# ---- cases, controls and mutants ----

CASES_PER_BODY = 2600
PROBE_PER_BODY = 1500
VARIANTS = ("peer-same-id", "detach-keeps-parent", "retain-first-only", "no-second-link", "compare-reversed", "no-panic")


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


class VariantSpec(Spec):
    """A deliberately wrong specification; the comparison has to reject it."""

    def __init__(self, world, variant):
        super().__init__(world)
        self.variant = variant

    def walk(self, root, height, key, user_kind):
        if self.variant != "compare-reversed" or not user_kind:
            return super().walk(root, height, key, user_kind)
        node, remaining = root, height
        if node is None:
            return None
        while True:
            at = len(node.keys)
            for number, node_key in enumerate(node.keys):
                self.log.append(("cmp", key, node_key))
                order = -compare_value(key, node_key)
                if order == 0:
                    return node.vals[number]
                if order < 0:
                    at = number
                    break
            if remaining == 0:
                return None
            remaining -= 1
            node = node.kids[at]

    def link(self, key, first, second):
        if self.variant == "peer-same-id":
            second_id = second
            order = self.locate(key, first)
            if order is not None:
                self.store(order.body + PEER_TAG, 8, 1)
                self.store(order.body + PEER_ID, 8, second_id)
            order = self.locate(key, second)
            if order is not None:
                self.store(order.body + PEER_TAG, 8, 1)
                self.store(order.body + PEER_ID, 8, second_id)
            return
        if self.variant == "no-second-link":
            order = self.locate(key, first)
            if order is not None:
                self.store(order.body + PEER_TAG, 8, 1)
                self.store(order.body + PEER_ID, 8, second)
            return
        super().link(key, first, second)

    def detach(self, key, oid):
        if self.variant == "detach-keeps-parent":
            order = self.locate(key, oid)
            if order is None or order.parent is None:
                return
            holder = self.locate(key, order.parent)
            if holder is not None and oid in holder.kids:
                kept = [kid for kid in holder.kids if kid != oid]
                for number, kid in enumerate(kept):
                    self.store(holder.kids_at + 8 * number, 8, kid)
                self.store(holder.body + KIDS_LEN, 8, len(kept))
            return
        if self.variant == "retain-first-only":
            order = self.locate(key, oid)
            if order is None:
                return
            parent = order.parent
            self.store(order.body + PARENT_TAG, 8, 0)
            if parent is None:
                return
            holder = self.locate(key, parent)
            if holder is not None and oid in holder.kids:
                kept = list(holder.kids)
                kept.remove(oid)
                for number, kid in enumerate(kept):
                    self.store(holder.kids_at + 8 * number, 8, kid)
                self.store(holder.body + KIDS_LEN, 8, len(kept))
            return
        super().detach(key, oid)

    def run(self, op, key, first, second):
        try:
            if op == LINK:
                self.link(key, first, second)
            else:
                self.detach(key, first)
        except SpecPanic as caught:
            if self.variant != "no-panic":
                self.panic = (caught.index, PANIC_LOCATION)
        return self


def body_seed(body_index, number):
    return (number + 1) * 2654435761 + body_index * 40503 + 17


def run_case(harness, body_index, number, variant=None):
    body = BODIES[body_index]
    rng = Rng(body_seed(body_index, number))
    machine = harness.machine
    machine.memory.reset(harness.used)
    plan = make_plan(rng, body)
    world = build_world(machine, rng, plan)
    key, first, second = choose_call(rng, world, body["op"])
    harness.world = world
    spec = (VariantSpec(world, variant) if variant else Spec(world)).run(body["op"], key, first, second)
    before, after, panic = harness.call(body["entry"], world, key, first, second)
    harness.used = world.builder.top - HEAP_BASE + 64
    expect = expected_after(before, spec.writes)
    ok = harness.log == spec.log and panic == spec.panic and after == expect
    cmps = sum(1 for row in spec.log if row[0] == "cmp")
    row = (number, "%#x" % body["entry"], body["op"], plan["users_mode"], plan["order_mode"], len(world.oid_map), len(spec.log),
           cmps, len(spec.writes), "panic" if spec.panic else "-", machine.steps)
    return ok, row


def new_harness(image, patches=None):
    return Harness(image, patches)


def run_all(image, count):
    harness = new_harness(image)
    rows, failures = [], []
    tally = {}
    for body_index in range(len(BODIES)):
        for number in range(count):
            harness.machine.steps = 0
            ok, row = run_case(harness, body_index, number)
            if not ok:
                failures.append((body_index, number))
            kind = (row[2], row[3], row[4], "panic" if row[9] != "-" else "writes-%d" % min(row[8], 6))
            tally[kind] = tally.get(kind, 0) + 1
            rows.append(row)
    return rows, failures, tally


def variant_controls(image, per_variant=160):
    harness = new_harness(image)
    out = []
    for variant in VARIANTS:
        detected, tried = False, 0
        for body_index in range(len(BODIES)):
            op = BODIES[body_index]["op"]
            if variant in ("peer-same-id", "no-second-link") and op != LINK:
                continue
            if variant in ("detach-keeps-parent", "retain-first-only") and op != DETACH:
                continue
            for number in range(per_variant):
                tried += 1
                ok, _ = run_case(harness, body_index, number, variant)
                if not ok:
                    detected = True
                    break
            if detected:
                break
        out.append(("spec-variant", variant, detected, tried))
    return out


def corruption_controls(image):
    out = []
    bad = bytearray(image.blob)
    bad[len(bad) // 2] ^= 1
    try:
        Image(bytes(bad))
        digest = hashlib.sha256(bytes(bad)).hexdigest()
        out.append(("corrupt-binary-byte", "middle byte flipped", digest != SHA256, 1))
    except Exception:
        out.append(("corrupt-binary-byte", "middle byte flipped", True, 1))
    for label, address in (("entry-plus-one", BODIES[0]["entry"] + 1), ("below-text", 0x10), ("past-text", 0x7FFFFFFF)):
        try:
            image.exact_fde(address)
            out.append(("fde-boundary", label, False, 1))
        except EvidenceError:
            out.append(("fde-boundary", label, True, 1))
    for body in BODIES:
        start, end = image.exact_fde(body["entry"])
        out.append(("fde-end", "%#x" % body["entry"], end == body["end"], 1))
    return out


def jcc_patch(image, row):
    if row.op != "jcc":
        return None
    offset = 0 if image.read_byte(row.va) & 0xF0 == 0x70 else 1
    return {row.va + offset: image.read_byte(row.va + offset) ^ 1}


def imm_patch(image, row):
    if row.imm_at is None or row.op in ("jcc", "call", "jmp"):
        return None
    return {row.va + row.imm_at: image.read_byte(row.va + row.imm_at) ^ 1}


def read_byte(self, va):
    return self.blob[self.offset(va)]


Image.read_byte = read_byte


def decode_body(image, body):
    return decode_range(image, body["entry"], body["end"])


def killer(image, body_index, patches, order):
    """Run probe cases on a patched copy; return the first case number that disagrees, or None."""
    harness = new_harness(image, patches)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    for number in order:
        try:
            ok, _ = run_case(harness, body_index, number)
        except (Halt, Panicked, EvidenceError, IndexError, KeyError, ValueError, OverflowError, struct.error):
            return number
        if not ok:
            return number
    return None


EQUIVALENT = {}


def run_mutants(image):
    rows, survivors = [], []
    for body_index, body in enumerate(BODIES):
        listing = decode_body(image, body)
        order = list(range(PROBE_PER_BODY))
        for row in listing:
            for kind, make in (("jcc", jcc_patch), ("imm", imm_patch)):
                patches = make(image, row)
                if not patches:
                    continue
                found = killer(image, body_index, patches, order)
                rows.append((body_index, "%#x" % body["entry"], "%#x" % row.va, kind, "-" if found is None else found))
                if found is None:
                    survivors.append((body_index, row.va, kind))
                else:
                    order.remove(found)
                    order.insert(0, found)
    return rows, survivors


def layout_sites(image):
    rows = []
    for body_index, body in enumerate(BODIES):
        for row in decode_body(image, body):
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is not None and operand[1] != RSP and operand[4]:
                    rows.append((body_index, "%#x" % row.va, row.op, "disp", "%#x" % (operand[4] & MASK[8])))
            if row.imm_at is not None and row.op not in ("call", "jmp", "jcc"):
                value = row.b[1] if row.b and row.b[0] == "i" else row.target if row.op == "imul3" else None
                if value is not None:
                    rows.append((body_index, "%#x" % row.va, row.op, "imm", "%#x" % (value & MASK[8])))
    return rows


def copy_rows(image):
    rows = []
    for first, second in ((0, 1), (2, 3)):
        a, b = BODIES[first], BODIES[second]
        left, right = decode_body(image, a), decode_body(image, b)
        shifted = 0
        different = 0
        for x, y in zip(left, right):
            same = (x.op, x.width, x.cc, x.a, x.b) == (y.op, y.width, y.cc, y.a, y.b) and x.size == y.size
            if x.target is not None and y.target is not None and x.op in ("jcc", "jmp"):
                same = same and (x.target - a["entry"]) == (y.target - b["entry"])
            elif x.target != y.target:
                same = False
            different += 0 if same else 1
        raw_a = image.blob[image.offset(a["entry"]):image.offset(a["entry"]) + a["end"] - a["entry"]]
        raw_b = image.blob[image.offset(b["entry"]):image.offset(b["entry"]) + b["end"] - b["entry"]]
        byte_diffs = sum(1 for p, q in zip(raw_a, raw_b) if p != q)
        rows.append(("%#x" % a["entry"], "%#x" % b["entry"], len(left), len(right), different, byte_diffs))
    return rows


def table(rows):
    return "\n".join("\t".join(str(c) for c in row) for row in rows) + "\n"


def build(image, count):
    case_rows, failures, tally = run_all(image, count)
    if failures:
        raise EvidenceError("specification disagrees with the bytes on %d cases, first %r" % (len(failures), failures[0]))
    mutant_rows, survivors = run_mutants(image)
    controls = variant_controls(image) + corruption_controls(image)
    return case_rows, tally, mutant_rows, survivors, controls


def render(image, count):
    case_rows, tally, mutant_rows, survivors, controls = build(image, count)
    equivalent = [(b, va, kind) for b, va, kind in survivors if (b, va) in EQUIVALENT]
    unexplained = [s for s in survivors if (s[0], s[1]) not in EQUIVALENT]
    control_rows = [row for row in controls]
    detected_controls = sum(1 for row in control_rows if row[2])
    mutants_detected = sum(1 for row in mutant_rows if row[4] != "-")
    negative_controls = len(mutant_rows) + len(control_rows)
    negative_detected = mutants_detected + detected_controls
    files = {}
    files["cases.tsv"] = "case\tbody\toperation\tusers\torders\tid_map\tcalls\tcompares\twrites\tpanic\tsteps\n" + table(case_rows)
    files["outcomes.tsv"] = "operation\tusers\torders\toutcome\tcases\n" + table([k + (v,) for k, v in sorted(tally.items())])
    files["mutants.tsv"] = "body\tentry\taddress\tkind\tkilled_by_case\n" + table(mutant_rows)
    files["controls.tsv"] = "control\tdetail\tdetected\ttries\n" + table([(r[0], r[1], "yes" if r[2] else "NO", r[3]) for r in control_rows])
    files["equivalent-mutants.tsv"] = "body\taddress\tkind\treason\n" + table(
        [(b, "%#x" % va, kind, EQUIVALENT[(b, va)]) for b, va, kind in equivalent])
    files["sites.tsv"] = "body\taddress\toperation\tkind\tvalue\n" + table(layout_sites(image))
    files["copies.tsv"] = "first\tsecond\trows_first\trows_second\tdifferent_rows\tdifferent_bytes\n" + table(copy_rows(image))
    scope = []
    for body in BODIES:
        start, end = image.exact_fde(body["entry"])
        data = image.blob[image.offset(start):image.offset(start) + end - start]
        scope.append(("%#x" % start, "%#x" % end, end - start, body["op"], hashlib.sha256(data).hexdigest()))
    files["scope.tsv"] = "entry\tend\tbytes\toperation\tsha256\n" + table(scope)
    files["evidence.json"] = json.dumps(dict(
        binary_sha256=SHA256, bodies=len(BODIES), cases=len(case_rows), mutants=len(mutant_rows), survivors=len(unexplained),
        controls=len(control_rows), outcome_classes=len(tally),
    ), indent=2, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps(dict(
        cases=len(case_rows), negative_controls=negative_controls, negative_detected=negative_detected,
        equivalent=len(equivalent), unexplained=len(unexplained),
    ), indent=2, sort_keys=True) + "\n"
    return files, unexplained


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (folder / name).write_text(text)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=CASES_PER_BODY)
    args = parser.parse_args(argv)
    image = load_image()
    files, unexplained = render(image, args.cases)
    if unexplained:
        print("unexplained survivors: %r" % (unexplained,), file=sys.stderr)
    write_outputs(args.out, files)
    return 1 if unexplained else 0


if __name__ == "__main__":
    sys.exit(main())
