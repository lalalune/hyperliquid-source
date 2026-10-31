#!/usr/bin/env python3
"""Pin the node #94 block step named prune_book_empty_user_states from ELF bytes: which user_states entries of a book go.

The step `0x222bab0` (copies `0x4717c50`, `0x4710ec0`) walks every book twice through a per-book closure, `0x2773290` for the books
inside the `+0x3368` rows and `0x2773720` for the books of the `+0x3380` list. The closure collects the users whose `b` and `u` maps
are both empty, takes out each user that still holds an occupied slab slot, and removes what is left from `user_states`, dropping the
stored value. The real bytes run in a Python evaluator with real B-tree code and only allocator, memcmp and thread pool edges stubbed.
A separately written specification predicts every result, and every condition, immediate and field offset is flipped to show the run
can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

Copy = collections.namedtuple("Copy", "name step host site row_closure list_closure rows_field")
COPIES = (
    Copy("first", 0x222BAB0, 0x22297C0, 0x2229CBA, 0x2773290, 0x2773720, 0x3368),
    Copy("second", 0x4717C50, 0x470E9A0, 0x470EE9A, 0x43361B0, 0x4336700, 0x3368),
    Copy("third", 0x4710EC0, 0x47162D0, 0x4716837, 0x43361B0, 0x4336700, 0x3DE8),
)
INSTANT = 0x4EE3800
THREAD_WORD = 0x4E17630
STEP_NAME_TEXT = "prune_book_empty_user_states"
STEP_NAME = 0x3EFA87
STEP_LIMITS = 0x205E80
FIELD_TEXT = ((0x6EFFAC, "user_states"), (0x6EFFEE, "b"), (0x6EFFEF, "book_order_keys"), (0x6EFFFE, "r"), (0x6EFFFF, "u"), (0x6F0000, "untriggered_orders"))

SLOT_REGISTRY = 0x5773298
SLOT_GROW = 0x5773C68
SLOT_MEMCMP = 0x576E488
SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_REALLOC = 0x576E030
SLOT_PANIC = 0x576E470
SLOT_NOUNWIND = 0x576E128
SLOT_ADD = 0x576E118
SLOT_SLICE = 0x576E098
SLOT_ALLOC_ERROR = (0x576DFB8, 0x576E020, 0x576E108)
RESERVE_ERROR = 0x576DFB8

ROW_STRIDE = 0x138
BOOK_STRIDE = 0xD8
SLOT_STRIDE = 0xF8
VALUE_SIZE = 0x50
USER_SIZE = 20
VACANT = 2

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

GATE = HEAP_BASE + 0x40
REGISTRY_CELL = HEAP_BASE + 0x80
REGISTRY = HEAP_BASE + 0x100
WORKER = HEAP_BASE + 0x400
TLS_CELL = HEAP_BASE + 0x600
FIELD_ROWS = HEAP_BASE + 0x640
FIELD_BOOKS = HEAP_BASE + 0x680
ROWS = HEAP_BASE + 0x1000
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
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
        elif byte == 0xF2:
            repne = True
        elif byte not in (0x2E, 0x64):
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
                if self.read_code(pc, 1)[0] == 0x64:
                    raise Halt("thread local read at %#x" % pc)
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
    """Rule 1: the `b` length word and the `u` length word are both zero. The `r` vector plays no part."""
    return {entry["user"] for entry in entries if entry["b"] == 0 and entry["u"] == 0}


def held(slab, count):
    """Rule 2: a slot in the first `count` rows with a state dword other than 2 holds its user."""
    return {slot["user"] for slot in slab[:count] if slot["state"] & MASK[4] != VACANT}


def removed(book):
    if book.get("root_absent"):
        return set()
    return candidates(book["entries"]) - held(book["slab"], book["slab_len"])


def spec_book(book):
    gone = removed(book)
    kept = sorted(entry["user"] for entry in book["entries"] if entry["user"] not in gone)
    return {"users": [user.hex() for user in kept], "length": book["length"] - len(gone) if not book.get("root_absent") else book["length"]}


def run_spec(case):
    w = case.world
    if case.kind == "book":
        return {"books": [spec_book(w)], "leaked": 0, "intact": True, "stop": None}
    if w["flag"] != 1:
        return {"books": [{"users": [entry["user"].hex() for entry in sorted(book["entries"], key=lambda item: item["user"])], "length": book["length"]} for book in all_books(w)], "leaked": 0, "intact": True, "stop": None, "done": False, "instants": 0}
    return {"books": [spec_book(book) for book in all_books(w)], "leaked": 0, "intact": True, "stop": None, "done": True, "instants": 2}


def all_books(w):
    rows = [book for row in w["rows"] for book in row]
    return rows + list(w["books"])


# ---- harness: real bytes; allocator, memcmp and thread pool edges are stubbed ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Finished(Exception):
    """The step reached its timing tail: the state change is over."""


class Case:
    def __init__(self, label, kind, world, copy=0, closure="list"):
        self.label = label
        self.kind = kind
        self.world = world
        self.copy = copy
        self.closure = closure


Shape = collections.namedtuple("Shape", "parent keys key_size value_size parent_index length edges")
USER_SHAPE = Shape(0x370, 0x378, USER_SIZE, VALUE_SIZE, 0x454, 0x456, 0x458)
SET_SHAPE = Shape(0x0, 0x8, 8, 0, 0x60, 0x62, 0x68)
MAP_SHAPE = Shape(0x0, 0x8, 8, 0xB8, 0x848, 0x84A, 0x850)
FANOUT = 12
VALUE_R = 0x00
VALUE_B = 0x20
VALUE_U = 0x38
UNMAPPED = 0x10
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
                 SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_REALLOC: self.on_realloc, SLOT_PANIC: self.on_panic, SLOT_NOUNWIND: self.on_panic,
                 SLOT_ADD: self.on_panic, SLOT_SLICE: self.on_panic}
        for slot in SLOT_ALLOC_ERROR:
            table[slot] = self.on_panic
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        self.real.stubs = frozenset(machine.slots) | frozenset((INSTANT, THREAD_WORD))
        machine.calls = {INSTANT: self.on_instant, THREAD_WORD: self.on_thread}
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.owned = {}
        self.instants = 0

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

    def on_realloc(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        old = self.live.pop(at, None)
        if old is None or size > 0x40000:
            raise Halt("realloc %#x" % at)
        fresh = self.allocate(size)
        m.memory.copy(fresh, at, min(old, size))
        m.regs[RAX] = fresh

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x40000:
            raise Halt("copy size")
        m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_grow(self, m):
        """The RawVec one-step growth at slot 0x5773c68, element size 20, alignment 1."""
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

    def on_instant(self, m):
        if m.regs[RDI] & MASK[4] != 1:
            raise Halt("clock id")
        self.instants += 1
        if self.instants == 2:
            raise Finished()
        m.regs[RAX] = 0x1000
        m.regs[RDX] = 0x2000
        m.keep_rdx = True

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
            self.fill_entry(node + at * VALUE_SIZE, entry, owner)
        for at in range(len(own), FANOUT - 1):
            memory.put_bytes(node + USER_SHAPE.keys + at * USER_SIZE, b"\xfd" * USER_SIZE)
        for at, kid in enumerate(kids):
            memory.write(node + USER_SHAPE.edges + at * 8, 8, self.place(kid, node, at, height - 1, owner))
        return node

    def fill_entry(self, at, entry, owner):
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
        for offset, name, shape in ((VALUE_B, "b", SET_SHAPE), (VALUE_U, "u", MAP_SHAPE)):
            if entry[name]:
                memory.write(at + offset, 8, UNMAPPED)
                memory.write(at + offset + 8, 8, 0)
                memory.write(at + offset + 16, 8, entry[name])
            elif entry.get(name + "_leaf"):
                leaf = self.allocate(shape.edges)
                held_by.append(leaf)
                memory.put_bytes(leaf, ramp(shape.edges, 0x63))
                memory.write(leaf + shape.parent, 8, 0)
                memory.write(leaf + shape.length, 2, 0)
                memory.write(at + offset, 8, leaf)
                memory.write(at + offset + 8, 8, 0)
                memory.write(at + offset + 16, 8, 0)
            else:
                memory.write(at + offset, 8, 0)
                memory.write(at + offset + 8, 8, 0x55)
                memory.write(at + offset + 16, 8, 0)

    def book_world(self, base, slab_base, book):
        memory = self.machine.memory
        memory.put_bytes(base, ramp(BOOK_STRIDE, 0x2F))
        memory.write(base + 0x8, 8, slab_base)
        memory.write(base + 0x10, 8, book["slab_len"])
        for index, slot in enumerate(book["slab"]):
            at = slab_base + index * SLOT_STRIDE
            memory.put_bytes(at, ramp(SLOT_STRIDE, 0x41 + index))
            memory.write(at, 8, slot["state"])
            memory.put_bytes(at + 0xE0, slot["user"])
        owner = {}
        if book.get("root_absent"):
            memory.write(base + 0xB8, 8, 0)
            memory.write(base + 0xC0, 8, 0x77)
        else:
            rows = [(entry["user"], entry) for entry in sorted(book["entries"], key=lambda item: item["user"])]
            memory.write(base + 0xB8, 8, self.place(rows, 0, 0xFFFF, book["height"], owner))
            memory.write(base + 0xC0, 8, book["height"])
        memory.write(base + 0xC8, 8, book["length"])
        self.owned[base] = owner
        return memory.bytes_at(slab_base, len(book["slab"]) * SLOT_STRIDE), memory.bytes_at(base, 0xB8) + memory.bytes_at(base + 0xD0, 8)

    def read_book(self, base, values, book):
        """Walk the user tree; every step is bounded because a mutant can corrupt it."""
        memory = self.machine.memory
        root, height = memory.read(base + 0xB8, 8), memory.read(base + 0xC0, 8)
        users, nodes = [], set()

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
                    values.append((users[-1], memory.bytes_at(node + at * VALUE_SIZE, VALUE_SIZE)))
        if root:
            walk(root, height)
        return {"users": [user.hex() for user in users], "length": memory.read(base + 0xC8, 8)}, nodes

    def reachable(self, base, nodes, kept):
        out = set(nodes)
        for user in kept:
            out.update(self.owned[base].get(bytes.fromhex(user), ()))
        return out

    def finish(self, placed, books, answer):
        memory = self.machine.memory
        reached = set()
        out = []
        intact = True
        for (base, slab_base, slab_bytes, head, values_before), book in zip(placed, books):
            values = []
            row, nodes = self.read_book(base, values, book)
            out.append(row)
            reached |= self.reachable(base, nodes, row["users"])
            intact = intact and memory.bytes_at(slab_base, len(slab_bytes)) == slab_bytes
            intact = intact and memory.bytes_at(base, 0xB8) + memory.bytes_at(base + 0xD0, 8) == head
            intact = intact and all(values_before.get(user) == value for user, value in values)
        answer["books"] = out
        answer["intact"] = intact
        answer["leaked"] = len(set(self.live) - reached)

    def values_of(self, base, book):
        values = []
        self.read_book(base, values, book)
        return dict(values)

    def set_threads(self, w):
        memory = self.machine.memory
        memory.write(REGISTRY_CELL, 8, REGISTRY)
        memory.write(REGISTRY + 0x208, 8, w.get("threads", 0))
        memory.write(WORKER + 0x110, 8, REGISTRY)
        memory.write(TLS_CELL, 8, WORKER if w.get("worker") else 0)

    def run(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        copy = COPIES[case.copy]
        self.w = w
        self.instants = 0
        self.live = {}
        self.owned = {}
        memory.reset(self.brk - HEAP_BASE)
        self.brk = HEAP_FREE
        answer = {"stop": None}
        placed = []
        self.set_threads(w)
        try:
            if case.kind == "book":
                books = [w]
                slab, head = self.book_world(BOOKS, SLABS, w)
                placed.append((BOOKS, SLABS, slab, head, self.values_of(BOOKS, w)))
                entry = copy.list_closure if case.closure == "list" else copy.row_closure
                machine.run(entry, {RDI: POISON, RSI: BOOKS})
            else:
                books = all_books(w)
                at, slab_at = BOOKS, SLABS
                row_vectors = []
                for row in w["rows"]:
                    row_vectors.append((at, len(row)))
                    for book in row:
                        slab, head = self.book_world(at, slab_at, book)
                        placed.append((at, slab_at, slab, head, self.values_of(at, book)))
                        at += BOOK_STRIDE
                        slab_at += max(1, len(book["slab"])) * SLOT_STRIDE
                list_base = at
                for book in w["books"]:
                    slab, head = self.book_world(at, slab_at, book)
                    placed.append((at, slab_at, slab, head, self.values_of(at, book)))
                    at += BOOK_STRIDE
                    slab_at += max(1, len(book["slab"])) * SLOT_STRIDE
                memory.put_bytes(GATE, ramp(0x28, 0x13))
                memory.write(GATE + 0x20, 1, w["flag"])
                memory.write(FIELD_ROWS, 8, 0x4141)
                memory.write(FIELD_ROWS + 8, 8, ROWS)
                memory.write(FIELD_ROWS + 16, 8, len(w["rows"]))
                memory.write(FIELD_BOOKS, 8, 0x4242)
                memory.write(FIELD_BOOKS + 8, 8, list_base)
                memory.write(FIELD_BOOKS + 16, 8, len(w["books"]))
                for index, (base, count) in enumerate(row_vectors):
                    row = ROWS + index * ROW_STRIDE
                    memory.put_bytes(row, ramp(ROW_STRIDE, 0x35 + index))
                    memory.write(row + 8, 8, base)
                    memory.write(row + 0x10, 8, count)
                answer["done"] = False
                try:
                    machine.run(copy.step, {RDI: GATE, RSI: FIELD_ROWS, RDX: FIELD_BOOKS})
                except Finished:
                    answer["done"] = True
                answer["instants"] = self.instants
            self.finish(placed, books, answer)
        except Panicked as stop:
            answer["stop"] = stop.args[0]
        return answer


def spec_run(case):
    return run_spec(case)


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError)


def compare_run(harness, case):
    """Empty when the bytes and the specification agree, else one line."""
    wanted = spec_run(case)
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


def book(entries=(), slab=(), slab_len=None, height=None, length=None, **more):
    entries = list(entries)
    slab = list(slab)
    if height is None:
        height = 0 if len(entries) <= FANOUT - 1 else 1
    row = {"entries": entries, "slab": slab, "slab_len": len(slab) if slab_len is None else slab_len, "height": height, "length": len(entries) if length is None else length}
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
                for form, slab, label in ((0, [], "no slot"), (1, [slot(7)], "occupied"), (2, [slot(7, VACANT)], "vacant"), (3, [slot(9)], "other user"), (4, [slot(9), slot(11, 1), slot(7, 1)], "third slot")):
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
    rows.append(("root absent, length word stale", book(root_absent=True, length=5)))
    rows.append(("root absent, slab full", book(slab=[slot(1), slot(2)], root_absent=True, length=0)))
    rows.append(("empty leaf maps dropped", book([entry(1, 2, 0, 0, b_leaf=True, u_leaf=True), entry(2, 0, 0, 0, b_leaf=True), entry(3, 0, 0, 0, u_leaf=True)])))
    rows.append(("empty leaf maps kept while a slot holds", book([entry(1, 2, 0, 0, b_leaf=True, u_leaf=True)], [slot(1)])))
    rows.append(("r capacity without length dropped", book([entry(1, 0, 0, 0, r_cap=4)])))
    rows.append(("r length under capacity dropped", book([entry(1, 2, 0, 0, r_cap=9)])))
    rows.append(("b length only keeps", book([entry(1, 0, 1, 0)])))
    rows.append(("u length only keeps", book([entry(1, 0, 0, 1)])))
    rows.append(("large length words keep", book([entry(1, 0, 1 << 40, 0), entry(2, 0, 0, 1 << 40), entry(3, 0, 1 << 63, 0)])))
    return rows


def mixed(random, count, height=None, chance=3):
    numbers = list(range(1, count + 1))
    entries = []
    slab = []
    for number in numbers:
        kind = random.next(chance)
        if kind == 0:
            entries.append(entry(number, random.next(3)))
            if random.next(2):
                slab.append(slot(number))
        elif kind == 1:
            entries.append(entry(number, 1, random.next(3) + 1, random.next(2)))
        else:
            entries.append(entry(number, 0, 0, 0, b_leaf=bool(random.next(2)), u_leaf=bool(random.next(2))))
    for at in range(random.next(4)):
        slab.append(slot(numbers[-1] + at + 1, random.next(2) * VACANT))
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


def step_world(flag=1, rows=(), books=(), **more):
    w = {"flag": flag, "rows": [list(row) for row in rows], "books": list(books)}
    w.update(more)
    return w


def step_cases():
    solo = lambda start: book([entry(start)])
    one = lambda start: book([entry(start), entry(start + 1, 0, 1), entry(start + 2), entry(start + 3)], [slot(start + 2)])
    rows = [
        ("flag 0 changes nothing", step_world(0, [[one(1)]], [one(5)])),
        ("flag 2 changes nothing", step_world(2, [[one(1)]], [one(5)])),
        ("flag 3 changes nothing", step_world(3, [[one(1)]], [one(5)])),
        ("flag 1, no books", step_world()),
        ("flag 1, list only", step_world(1, [], [one(5)])),
        ("flag 1, list of three", step_world(1, [], [one(5), one(9), one(13)])),
        ("flag 1, one row", step_world(1, [[one(1)]])),
        ("flag 1, empty row", step_world(1, [[]], [one(5)])),
        ("flag 1, row of three", step_world(1, [[one(1), one(5), one(9)]])),
        ("flag 1, three rows", step_world(1, [[one(1)], [], [one(5), one(9)]], [one(13)])),
        ("flag 1, one row, one thread", step_world(1, [[solo(1)]], [], threads=1)),
        ("flag 1, one book, one thread", step_world(1, [], [solo(1)], threads=1)),
        ("flag 1, one book, eight threads", step_world(1, [], [solo(1)], threads=8)),
        ("flag 1, one row, worker thread", step_world(1, [[one(1)]], [one(5)], worker=True)),
        ("flag 1, one of each, one thread on a worker", step_world(1, [[solo(1)]], [solo(5)], threads=1, worker=True)),
    ]
    return rows


def all_cases():
    """First copy of the list closure takes every book row; the other three closures take the rows with small trees."""
    cases = []
    small = single_cases() + field_cases()
    trees = tree_cases()
    for label, world in small + trees:
        cases.append(Case("first list: %s" % label, "book", world, 0, "list"))
    for copy, closure in ((0, "row"), (1, "list"), (1, "row")):
        for label, world in small + trees[:12]:
            cases.append(Case("%s %s: %s" % (COPIES[copy].name, closure, label), "book", world, copy, closure))
    for copy in range(3):
        for label, world in step_cases():
            cases.append(Case("%s step: %s" % (COPIES[copy].name, label), "step", world, copy))
    return cases


# ---- static reads ----

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


def slot_sites(image, slot):
    """Every FF 15 call in .text through one data slot."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            rows.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return rows


# ---- mutation ----

def displacement_at(image, row):
    """Offset inside the instruction of a non-stack field displacement, or None."""
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, offset in instruction, kind) for every conditional, immediate and field offset."""
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



GROUPS = (
    (0x222BAB0, "step up to its timing tail", 0xCA),
    (0x228E8D0, "row walk", None),
    (0x21E1110, "books of one row", None),
    (0x21E1D80, "book list walk", None),
    (0x2773720, "per-book closure", None),
    (0x2577530, "collect entry references", None),
    (0x287C9B0, "build the set", None),
    (0x255D140, "parallel collect entry", None),
    (0x228D390, "filter on b and u lengths", None),
    (0x24C2420, "append the filtered keys", None),
    (0x27E8490, "remove loop", None),
    (0x2865710, "remove a held user from the set", None),
)
HEAVY_STEPS = 6000
LARGE_CASES = 3


def group_rows(image, start, stop):
    begin, end = image.exact_fde(start)
    return begin, begin + stop if stop else end, end


def mutated_groups(image):
    """(function start, role, decoded rows)."""
    groups = []
    for start, role, stop in GROUPS:
        begin, limit, _ = group_rows(image, start, stop)
        groups.append((start, role, decode_range(image, begin, limit)))
    return groups


def run_mutants(image, reached, costs, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run; large trees run only for rows nothing smaller reaches."""
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    cases = all_cases()
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for start, _, rows in mutated_groups(image):
        for va, at, kind in mutation_targets(image, rows):
            indices = by_va.get(va)
            if indices:
                light = [index for index in indices if costs[index] <= HEAVY_STEPS]
                large = sorted((index for index in indices if costs[index] > HEAVY_STEPS), key=lambda index: costs[index])
                indices = (light or large[:1]) + large[:LARGE_CASES]
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
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

FILTER_BYTES = bytes.fromhex("488b7248480b7230")
CLOSURE_ANCHORS = (
    ("mov rdx, [rsi+0xb8]: user_states root", 0x11, "488b96b8000000"),
    ("mov rcx, [rsi+0xc0]: user_states height", 0x2A, "488b8ec0000000"),
    ("mov rax, [rsi+0xc8]: user_states length", 0x31, "488b86c8000000"),
    ("mov rsi, [rcx+0x8]: slab pointer", 0xD1, "488b7108"),
    ("imul rcx, [rcx+0x10], 0xf8: slab end", 0xD5, "4869491" + "0f8000000"),
    ("cmp dword [rax], 2: vacant slot", 0x145, "833802"),
    ("mov ecx, [rax+0xf0]: last 4 user bytes", 0x15A, "8b88f0000000"),
    ("movups xmm0, [rax+0xe0]: first 16 user bytes", 0x164, "0f1080e0000000"),
)
SERIALIZER_ANCHORS = (
    ("lea rsi, [rbx+0xb8], then call 0x4382c50: user_states is book +0xb8", 0x431E8C4, "488db3b80000004889e7e87d430600"),
    ("lea r14, [rdi+0x20]: value field b", 0x43206D4, "4c8d7720"),
    ("add rbx, 0x38: value field u", 0x4320847, "4883c338"),
    ("cmp rdx, [rsi+0x3378]: asset / 10000 against the row count", 0x2755C95, "483b9678330000"),
    ("imul rbp, rdx, 0x138: row stride", 0x2755CB9, "4869ea38010000"),
    ("imul rax, r15, 0xd8: asset % 10000 times the book stride", 0x2755D13, "4969c7d8000000"),
)
FIELDS = {
    "state": {"+0x3368": "one row per dex: pointer +8, length +0x10, asset / 10000 picks the row in 0x2755c70; third copy +0x3de8", "+0x3380": "vector of books, pointer +8, length +0x10; third copy +0x3e00", "+0x38c0": "period word read before the step in the first copy", "+0x38c8": "last bucket word in the first copy"},
    "row": {"stride": "0x138", "+0x08/+0x10": "pointer and length of the books of this dex, asset % 10000 picks the book in 0x2755c70"},
    "book": {"stride": "0xd8", "+0x08/+0x10": "slab pointer and length", "+0xb8/+0xc0/+0xc8": "user_states root, height, length"},
    "slab_slot": {"stride": "0xf8", "+0x00": "state dword, 2 = vacant", "+0xe0": "20 byte user, 16 bytes plus a dword at +0xf0"},
    "user_states_node": {"+0x000": "11 values of 0x50 bytes", "+0x370": "parent", "+0x378": "11 keys of 20 bytes", "+0x454": "parent index", "+0x456": "length", "+0x458": "edges"},
    "user_state_value": {"+0x00": "field r: vector of 8 byte items, capacity, pointer, length", "+0x18": "8 bytes, not read here", "+0x20": "field b, name book_order_keys in the strings: root, height, length at +0x30", "+0x38": "field u, name untriggered_orders in the strings: root, height, length at +0x48"},
}
REFERENCE_CLAIMS = (
    {"reference": "l1/ (whole tree)", "claim": "no text prune_book_empty_user_states, user_states, book_order_keys or untriggered_orders", "observed": "the step name is at 0x3efa87, and the serializers at 0x431e6f0 and 0x43206c0 write the field names", "verdict": "missing in the reference"},
    {"reference": "l1/book/book/mod.rs:208", "claim": "user_orders: BTreeMap<User, BTreeMap<Oid, usize>>", "observed": "the value is 0x50 bytes with one vector and two maps; the inner value of field u is 0xb8 bytes", "verdict": "shape differs"},
)


def fixed_text(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def read_double(image, va):
    return struct.unpack_from("<d", image.blob, image.offset(va))[0]


def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def step_rows(image):
    """In each caller: the name, its length, the bucket gate and the two list fields, by exact byte patterns before the call."""
    rows = []
    for copy in COPIES:
        begin = copy.site - 0xB0
        window = code(image, begin, 0xB0)
        at = window.rfind(b"\x48\xc7\x44\x24\x28\x1c\x00\x00\x00")
        lea = at - 12
        if at < 0 or window[lea:lea + 3] != b"\x48\x8d\x05":
            raise EvidenceError("name bytes before %#x" % copy.site)
        name = begin + lea + 7 + struct.unpack_from("<i", window, lea + 3)[0]
        if fixed_text(image, name, 0x1C) != STEP_NAME_TEXT:
            raise EvidenceError("name address %#x" % name)
        limits_at = window.find(b"\x66\x0f\x28\x05", at)
        limits = begin + limits_at + 8 + struct.unpack_from("<i", window, limits_at + 4)[0]
        if (read_double(image, limits), read_double(image, limits + 8)) != (0.05, 0.05):
            raise EvidenceError("limit bytes before %#x" % copy.site)
        if b"\x0f\x97\x44\x24\x40" not in window or b"\x48\xf7\xf1" not in window:
            raise EvidenceError("gate bytes before %#x" % copy.site)
        rows_at = window.rindex(b"\x49\x8d\xb5")
        list_at = window.rindex(b"\x49\x8d\x95")
        rows_field = struct.unpack_from("<I", window, rows_at + 3)[0]
        list_field = struct.unpack_from("<I", window, list_at + 3)[0]
        if rows_field != copy.rows_field or list_field != rows_field + 0x18:
            raise EvidenceError("list fields before %#x" % copy.site)
        period = window.index(b"\x48\x8b\x89")
        bucket = window.index(b"\x49\x8b\x8d")
        target = copy.site + 5 + struct.unpack_from("<i", code(image, copy.site + 1, 4))[0]
        if code(image, copy.site, 1) != b"\xe8" or target != copy.step:
            raise EvidenceError("call at %#x" % copy.site)
        rows.append({"site": "%#x" % copy.site, "caller": "%#x" % copy.host, "step": "%#x" % copy.step, "name": "%#x" % name, "rows_field": "%#x" % rows_field, "list_field": "%#x" % list_field,
                     "period_field": "%#x" % struct.unpack_from("<I", window, period + 3)[0], "bucket_field": "%#x" % struct.unpack_from("<I", window, bucket + 3)[0], "limits": [read_double(image, limits), read_double(image, limits + 8)]})
    return rows


def anchors(image):
    rows = []
    for meaning, offset, wanted in CLOSURE_ANCHORS:
        for closure in (0x2773290, 0x2773720, 0x43361B0, 0x4336700):
            data = code(image, closure + offset, len(wanted) // 2).hex()
            if data != wanted:
                raise EvidenceError("closure bytes at %#x: %s" % (closure + offset, data))
            rows.append({"va": "%#x" % (closure + offset), "bytes": data, "meaning": meaning})
    for meaning, va, wanted in SERIALIZER_ANCHORS:
        data = code(image, va, len(wanted) // 2).hex()
        if data != wanted:
            raise EvidenceError("serializer bytes at %#x: %s" % (va, data))
        rows.append({"va": "%#x" % va, "bytes": data, "meaning": meaning})
    return rows


def filter_sites(image):
    """Every place in .text with the two length words of the filter next to each other."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(FILTER_BYTES)
    while at >= 0:
        rows.append({"va": "%#x" % (base + at), "fde": "%#x" % image.fde(base + at)[0]})
        at = text.find(FILTER_BYTES, at + 1)
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


def copy_table(image):
    first, first_targets = masked(image, COPIES[0].list_closure)
    rows = []
    for closure in (0x2773720, 0x2773290, 0x4336700, 0x43361B0):
        body, targets = masked(image, closure)
        if body != first:
            raise EvidenceError("closure %#x differs beyond displacements" % closure)
        rows.append({"closure": "%#x" % closure, "size": len(body), "masked_sha256": hashlib.sha256(body).hexdigest(), "callees": ["%#x" % target for target in targets]})
    return rows


def rule_table():
    rows = []
    for r in (0, 3):
        for b in (0, 1):
            for u in (0, 1):
                for occupied in (0, 1):
                    world = book([entry(1, r, b, u)], [slot(1, 0 if occupied else VACANT)])
                    rows.append({"r_length": r, "b_length": b, "u_length": u, "occupied_slot": occupied, "entry_removed": user_id(1) in removed(world)})
    return rows


def outcome_name(case, spec):
    if case.kind == "step":
        return "step %s" % ("does nothing" if not spec.get("done") else "runs")
    length = case.world["length"]
    if case.world.get("root_absent"):
        return "book without a root"
    gone = len(removed(case.world))
    return "book removes %s" % ("nothing" if not gone else "every entry" if gone == length else "some entries")


def case_line(case, spec):
    return "%s\t%s\t%s\t%s" % (case.kind, case.closure if case.kind == "book" else "", case.label.replace(": ", "\t", 1), outcome_name(case, spec))


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    lines = []
    machine = harness.machine
    costs = []
    for case in cases:
        machine.seen = set()
        before = machine.steps
        trouble = compare_run(harness, case)
        costs.append(machine.steps - before)
        if trouble:
            mismatches.append(trouble)
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        spec = spec_run(case)
        name = outcome_name(case, spec)
        outcomes[name] = outcomes.get(name, 0) + 1
        lines.append(case_line(case, spec))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    for start, role, stop in GROUPS:
        begin, limit, end = group_rows(image, start, stop)
        rows = decode_range(image, begin, limit)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "evaluated_to": "%#x" % limit, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    site_rows = []
    targets = tuple(sorted({copy.step for copy in COPIES} | {0x2773290, 0x2773720, 0x43361B0, 0x4336700}))
    direct = direct_sites(image, targets)
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    names = {}
    for va, text in FIELD_TEXT:
        if fixed_text(image, va, len(text)) != text:
            raise EvidenceError("field text at %#x" % va)
        names["%#x" % va] = text
    step_table = step_rows(image)
    byte_rows = anchors(image)
    sites = filter_sites(image)
    copies = copy_table(image)
    if fixed_text(image, STEP_NAME, 0x1C) != STEP_NAME_TEXT:
        raise EvidenceError("step name")
    results_rows = run_mutants(image, reached, costs, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "step_name": STEP_NAME_TEXT,
        "field_names": names,
        "step_sites": step_table,
        "filter_sites": sites,
        "closure_copies": copies,
        "anchors": byte_rows,
        "fields": FIELDS,
        "rule_table": rule_table(),
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_lines": lines,
    }


UNREACHED_REASON = "no case reaches it: a thread pool split arm, a tree of height 8 or more, an allocator failure arm, a panic arm or an unwind pad"
SURVIVED_REASONS = {
    0x222BAB0: "thread count plumbing: the plain loop runs either way, and the split arm is outside this packet",
    0x228E8D0: "thread count plumbing: the plain loop runs either way, and the split arm is outside this packet",
    0x21E1110: "thread count plumbing: the plain loop runs either way, and the split arm is outside this packet",
    0x21E1D80: "thread count plumbing: the plain loop runs either way, and the split arm is outside this packet",
    0x255D140: "thread count plumbing or result word moves of the collect entry; the plain loop runs either way",
    0x228D390: "the start capacity word of the filtered key list: a wrong start only changes when the list grows",
    0x24C2420: "a list link word of the single node chain: no case has a second node, and the split arm that makes one is outside this packet",
    0x2577530: "a capacity limit that no tree size here reaches, or a descent arm word that gives the same node on these trees",
    0x2773720: "an iterator back handle word that the collector does not read, the slab counter guard, or a value that gives the same walk on these trees",
    0x287C9B0: "a list or search start word that gives the same set on these key lists",
    0x27E8490: "a walk position word that gives the same removals on these trees",
    0x2865710: "a search start or a parent word that gives the same set on these key lists",
}


def reason_for(row):
    if row["result"] == "killed":
        return ""
    if row["result"] == "unreached":
        return UNREACHED_REASON
    return SURVIVED_REASONS[row["function"]]


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["kind\tclosure\tcopy\tlabel\toutcome"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_)) for row_ in results]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
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
