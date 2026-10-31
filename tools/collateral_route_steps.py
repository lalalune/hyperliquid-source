#!/usr/bin/env python3
"""Pin the node #94 collateral route steps of the abstraction modes from ELF bytes: move_token, the settle pass, the reserve moves and the sweep.

Orders of users in abstraction modes 2, 3 and 4 run these steps around the book insert. `0x46ea0b0` (`move_token`) moves USDC style collateral between spot and a
perp dex. `0x46ebca0` settles every dex of a token, `0x46efb70` pulls collateral to the target dex, `0x46ef4a0` sweeps it back, `0x46eb400` and `0x46f7240` run the
account block helper around them. The real bytes run in a Python evaluator with the edge callees stubbed. A separately written specification predicts every step, and
every condition, immediate and field offset of the fresh functions is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is
never executed. Standard library only.
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

SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMCMP = 0x576E488
SLOT_FORMAT = 0x576E040
SLOT_FORMAT_FN = 0x5770ED0
SLOT_SPOT_USER = 0x5773170
SLOT_RECORDER = 0x5773190
SLOT_AVAILABLE = 0x57738B8
SLOT_GROW_HITS = 0x5773A58
SLOT_GROW_FAILS = 0x57744B0
SLOT_NEGATE = 0x576EB38
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576DFB8, 0x576E108, 0x576E020)

# Each family is (first copy, second copy); the second reads the same fields 0xa80 lower.
MOVE = (0x46EA0B0, 0x46EAA10)
UNDO = (0x46E98E0, 0x46E9850)
RESERVE = (0x46EB400, 0x46EB850)
SETTLE = (0x46EBCA0, 0x46ED7D0)
WRAP = (0x46EF300, 0x46EF3D0)
SWEEP = (0x46EF4A0, 0x46EF720)
PULL = (0x46EFB70, 0x46EF9A0)
ACCOUNT = (0x46F7240, 0x46F73D0)
GATHER = (0x46F02F0, 0x46EFD40)
TRANSFER = (0x46E8290, 0x46E89A0)
FINISH = (0x46F0EE0, 0x46F0B20)
HELPER = 0x48CDAC0
AMOUNT = 0x4C23110
AMOUNT_TABLE = 0x70BD94
MODE_TEXT = 0x5A72F4
COUNT_MAP = 0x47D7550
DROP_STATUS = 0x472F840
DROP_DEX_ERROR = 0x3379490
COLLECT = 0x47BECA0
ITERATE = 0x4896090
MAP_INSERT = 0x492E880
MAP_SPLIT = 0x423AD10
MAP_DRAIN = 0x4947500
GROW_KEYS = 0x454F5D0
USER_ITERATE = 0x330F760
ONCE_STATE = 0x5786380
DEFAULT_ROW = 0x5786350
TO_SPOT_TEMPLATE = 0x1E03C9
FROM_SPOT_TEMPLATE = 0x1E76B6
ROUTERS = (0x4CA9710, 0x4CA8EB0, 0x4CA8510, 0x4CA7CB0)

ROW = 0x2F0
SECOND_SHIFT = 0xA80
OK = 0x186
TEXT_STATUS = 0x168
ACCOUNT_ERROR = 0xE1
FINISH_OK = 0x11
DEX_ERROR = 0x141
MAX64 = (1 << 64) - 1
MAX63 = (1 << 63) - 1
MIN63 = 1 << 63
NONE_WORD = 1 << 63
MODE_WORD_SWEEP = 2

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
HEAP_SIZE = 0x60000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 200000

OUT = HEAP_BASE + 0x400
USER_AT = HEAP_BASE + 0x480
WORD_AT = HEAP_BASE + 0x4C0
ENTRY_AT = HEAP_BASE + 0x500
COUNT_AT = HEAP_BASE + 0x580
OTHER_ENTRY = HEAP_BASE + 0x600
ROWS_AT = HEAP_BASE + 0x1000
STATE = HEAP_BASE + 0x4000
HEAP_FREE = HEAP_BASE + 0x8000
USER = "11223344556677889900aabbccddeeff00112233"
OTHER_USER = "21223344556677889900aabbccddeeff00112233"



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
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x6C, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
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
        self.tails = {}
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
            hook = self.tails.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
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


# ---- specification: written from the reading of the bytes; shares no code with the run ----

class SpecPanic(Exception):
    pass


def signed(value):
    value &= MAX64
    return value - (1 << 64) if value >> 63 else value


class Spec:
    """The steps as ordinary code. `self.log` is the ordered list of edge calls."""

    def __init__(self, w):
        self.w = w
        self.log = []
        self.xfer_calls = 0
        self.moves = 0

    def dex(self, index):
        rows = self.w["rows"]
        if index >= len(rows):
            raise SpecPanic("dex")
        return rows[index]

    def spot_free(self, token):
        """Whole free balance in wei; a hold above the total reports and gives 0."""
        pair = self.w["spot"].get(str(token)) if self.w["known_user"] else None
        if pair is None:
            return 0
        total, hold = pair
        if total < hold:
            self.log.append(["recorder", "wei"])
            return 0
        return total - hold

    def available(self, index, mode, byte):
        self.log.append(["available", index, mode, byte])
        key = "%d:%d" % (index, mode)
        return signed(self.w["available"].get(key, 0)), self.w["available_flag"].get(key, 0)

    def transfer(self, index, mode, amount):
        self.log.append(["transfer", index, mode, amount if mode != 2 else None])
        number = self.xfer_calls
        self.xfer_calls += 1
        return self.w["transfer_fail"].get(str(number), OK)

    def drop(self, status, text=None):
        self.log.append(["drop", status, text])

    def format(self, name, status):
        self.log.append(["format", name, status])
        return "move_token %s: %#x" % (name, status)

    def move_token(self, token, source, target, cap):
        """(status, amount or text): source and target None mean spot."""
        self.moves += 1
        if source == target:
            return OK, 0
        if self.w["exempt"]:
            return OK, 0
        limit = None
        if target is not None:
            row = self.dex(target)
            if row["tag"] != 3:
                if signed(row["cap"]) < 0:
                    raise SpecPanic("cap")
                left = signed(row["cap"]) - signed(row["used"])
                if not -(1 << 63) <= left < (1 << 63):
                    self.log.append(["recorder", "ntl"])
                    left = MAX63 if left > 0 else -(1 << 63)
                limit = max(left, 0)
        if source is not None:
            row = self.dex(source)
            if row["token"] != token:
                self.drop(TEXT_STATUS, "token mismatch")
                return OK, 0
            have = max(self.available(source, 4, row["byte"])[0], 0)
        else:
            have = self.spot_free(token) // 100
        amount = have if limit is None else min(have, limit)
        if cap is not None:
            amount = min(cap, amount)
        if amount == 0:
            return OK, 0
        if source is not None:
            if self.dex(source)["token"] != token:
                return TEXT_STATUS, "token mismatch"
            status = self.transfer(source, 1, amount)
            if status != OK:
                text = self.format("to_spot", status)
                self.drop(status)
                return TEXT_STATUS, text
        if target is not None:
            if self.dex(target)["token"] != token:
                return TEXT_STATUS, "token mismatch"
            status = self.transfer(target, 0, amount)
            if status != OK:
                if source is not None:
                    back = self.transfer(source, 0, amount)
                    if back != OK:
                        self.drop(back)
                text = self.format("from_spot", status)
                self.drop(status)
                return TEXT_STATUS, text
        return OK, amount

    def quiet_move(self, token, source, target, cap):
        status, value = self.move_token(token, source, target, cap)
        if status != OK:
            self.drop(TEXT_STATUS, value)
        return status, value

    def account(self, token, mode, opt, byte):
        """The account block step: (status, amount or byte)."""
        amount = self.spot_free(token) if mode in (1, 2) else None
        self.log.append(["helper", token, mode, amount, opt, byte ^ 3])
        word, tail, value = self.w["helper"].get(str(mode), (0, 0, 0))
        if word == 3:
            return ACCOUNT_ERROR, tail
        if word == 2:
            return OK, 0
        self.log.append(["finish", token, mode, word, value])
        if self.w["finish"].get(str(mode), FINISH_OK) != FINISH_OK:
            return ACCOUNT_ERROR, 0xA
        return OK, value

    def quiet_account(self, token, mode, opt, byte):
        status, value = self.account(token, mode, opt, byte)
        if status != OK:
            self.drop(ACCOUNT_ERROR)
        return status

    def reserve_move(self, token, target, word, byte):
        """Word (w, key, value): 2 runs modes 3 and 0, an odd word below 4 first takes the key entry, the rest run mode 3 only. Then the move."""
        reserve = self.w["reserve"]
        if word[0] == 2:
            if token in reserve:
                self.quiet_account(token, 3, None, byte)
                self.quiet_account(token, 0, None, byte)
        else:
            if word[0] < 4 and word[0] & 1 and word[1] in reserve:
                if self.account(word[1], 3, word[2], byte)[0] != OK:
                    self.drop(ACCOUNT_ERROR)
                    return
            if token in reserve:
                self.quiet_account(token, 3, None, byte)
        self.quiet_move(token, None, target, None)

    def sweep(self, token, source):
        self.quiet_move(token, source, None, None)
        if token in self.w["reserve"]:
            self.quiet_account(token, 2, None, 0)
            self.quiet_account(token, 1, None, 0)

    def need_of(self, value):
        if value == -(1 << 63):
            raise SpecPanic("negate")
        return -value if value < 0 else 0

    def settle(self, flag, every, token):
        w = self.w
        rows = w["rows"]
        tokens = sorted(w["reserve"]) if every else [token]
        indices = [row["index"] for row in rows]
        for index in indices:
            row = self.dex(index)
            if row["token"] in tokens:
                if flag:
                    status = self.transfer(index, 2, None)
                    if status != OK:
                        self.drop(status)
                else:
                    self.quiet_move(row["token"], index, None, None)
        if every:
            for key in sorted(w["reserve"]):
                self.sweep(key, 0 if False else None)
        hits_by_token = {}
        fails = []
        for current in tokens:
            if not rows:
                continue
            done = True
            taken = False
            hits = []
            for index in indices:
                row = self.dex(index)
                if row["token"] != current:
                    continue
                value, ready = self.available(index, 2, None) if flag else self.available(index, 4, row["byte"])
                need = self.need_of(value)
                if not ready & 1 and not need:
                    continue
                if ready & 1:
                    hits.append(index)
                if every and not taken:
                    taken = True
                    self.reserve_move(current, None, (MODE_WORD_SWEEP, 0, 0), flag)
                status, moved = self.quiet_move(current, None, index, need)
                if status != OK:
                    done = False
                elif moved < need:
                    done = False
            if every and taken:
                self.sweep(current, None)
            if not done:
                fails.append(current)
            if hits:
                hits_by_token[current] = hits
        total = min(sum(len(hits) for hits in hits_by_token.values()), MAX64)
        if flag and hits_by_token:
            for current in sorted(hits_by_token):
                hits = hits_by_token[current]
                if every:
                    self.reserve_move(current, None, (MODE_WORD_SWEEP, 0, 0), 1)
                spot = float(self.spot_free(current) // 100)
                shares = min(min(total * 3, MAX64) + (1 if every else 0), MAX64)
                share = spot * (3.0 / shares)
                share = int(share) if share > 0 else 0
                total -= len(hits)
                for index in hits:
                    row = self.dex(index)
                    if row["token"] != current:
                        continue
                    value, ready = self.available(index, 4, row["byte"])
                    need = self.need_of(value)
                    if not ready & 1 and not need:
                        continue
                    self.quiet_move(current, None, index, min(share, need))
                if every:
                    self.sweep(current, None)
        return fails or None

    def gather(self):
        for row in self.w["rows"]:
            index = row["index"]
            self.quiet_move(self.dex(index)["token"], index, None, None)
        for key in sorted(self.w["reserve"]):
            self.reserve_move(key, None, (0, 0, 0), 0)

    def pull(self, token, target, word, flag):
        flag &= 0xFF
        every = bool(flag) and token in self.w["reserve"]
        self.settle(0, every, token)
        if flag:
            self.reserve_move(token, target, word, 0)
        else:
            self.quiet_move(token, None, target, None)


def spec_run(case):
    w = case.world
    spec = Spec(w)
    kind = case.kind
    a = w["args"]
    try:
        if kind == "move":
            status, value = spec.move_token(a["token"], a["source"], a["target"], a["cap"])
            result = {"status": status, "value": value}
        elif kind == "wrap":
            status, value = spec.move_token(a["token"], a["source"], a["target"], a["cap"])
            if status != OK:
                spec.drop(TEXT_STATUS, value)
            result = {"some": status == OK, "value": value if status == OK else None}
        elif kind == "account":
            status, value = spec.account(a["token"], a["mode"], a["opt"], a["byte"])
            result = {"status": status, "value": value}
        elif kind == "reserve":
            spec.reserve_move(a["token"], a["target"], a["word"], a["byte"])
            result = {}
        elif kind == "sweep":
            spec.sweep(a["token"], a["source"])
            result = {}
        elif kind == "settle":
            result = {"fails": spec.settle(a["flag"], a["every"], a["token"])}
        elif kind == "gather":
            spec.gather()
            result = {}
        else:
            spec.pull(a["token"], a["target"], a["word"], a["flag"])
            result = {}
    except SpecPanic as error:
        return {"panic": str(error), "log": spec.log}
    return {"log": spec.log, "result": result, "counts": [min(w["count_all"] + spec.moves, MAX64), min(w["count_user"] + spec.moves, MAX64)]}


# ---- harness: real bytes; every edge callee is stubbed and logged ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Case:
    def __init__(self, label, kind, world):
        self.label = label
        self.kind = kind
        self.world = world


class Shape:
    """A B-tree node shape: where keys, the length, edges, the parent word and index sit, the key width and the node size."""

    def __init__(self, keys, width, length, edges, parent, slot, size):
        self.keys, self.width, self.length, self.edges, self.parent, self.slot, self.size = keys, width, length, edges, parent, slot, size


TOKEN_NODE = Shape(0x798, 8, 0x7F2, 0x7F8, 0x790, 0x7F0, 0x7F8)
SET_NODE = Shape(0x798, 0x14, 0x876, 0x878, 0x790, 0x874, 0x878)
SPOT_NODE = Shape(8, 8, 0x16A, 0x170, 0, 0x168, 0x170)
USER_NODE = Shape(0x218, 0x14, 0x2F6, 0x2F8, 0x210, 0x2F4, 0x2F8)
LEAF_KEYS = 3


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_FORMAT: self.on_format, SLOT_SPOT_USER: self.on_spot_user,
                 SLOT_RECORDER: self.on_recorder, SLOT_AVAILABLE: self.on_available, SLOT_GROW_HITS: self.on_grow, SLOT_GROW_FAILS: self.on_grow}
        for slot in SLOT_PANIC + (SLOT_NEGATE,):
            table[slot] = lambda m, which=slot: self.on_panic(m, which)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        machine.jump_low, machine.jump_high = image.exact_fde(AMOUNT)
        calls = {GROW_KEYS: self.on_grow, COUNT_MAP: self.on_count, DROP_STATUS: self.on_drop, DROP_DEX_ERROR: self.on_dex_error, HELPER: self.on_helper}
        for start in TRANSFER:
            calls[start] = self.on_transfer
        for start in FINISH:
            calls[start] = self.on_finish
        machine.tails = calls
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.xfer_calls = 0
        self.used = HEAP_SIZE

    def field(self, offset):
        """Fields from +0x1040 up sit 0xa80 lower in the second copy."""
        return STATE + offset - (SECOND_SHIFT if self.w["copy"] and offset >= 0x1040 else 0)

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x4000:
            raise Halt("allocation size")
        m.regs[RAX] = self.allocate(size)

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x4000:
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_compare(self, m):
        regs = m.regs
        if regs[RDX] != 0x14:
            raise Halt("compare length")
        left, right = m.memory.bytes_at(regs[RDI], 0x14), m.memory.bytes_at(regs[RSI], 0x14)
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[8])

    def on_panic(self, m, slot):
        regs = m.regs
        if slot == SLOT_NEGATE:
            if regs[RDI] != 0x572E4C8:
                raise Halt("negate location")
            raise Panicked("negate")
        if slot != 0x576E048 or regs[RSI] != 0x2B:
            raise Halt("panic slot or length")
        if regs[R8] == 0x56E9AE0:
            if m.memory.read(regs[RDX], 2) != DEX_ERROR:
                raise Halt("panic word")
            raise Panicked("dex")
        if regs[R8] != 0x572E4C8:
            raise Halt("panic location")
        raise Panicked("cap")

    def on_recorder(self, m):
        where = m.regs[RSI]
        if where not in (0x56DFD90, 0x572E4E0):
            raise Halt("recorder location")
        self.log.append(["recorder", "wei" if where == 0x56DFD90 else "ntl"])

    def check_user(self, m, at):
        if m.memory.bytes_at(at, 0x14) != bytes.fromhex(USER):
            raise Halt("user bytes")

    def on_spot_user(self, m):
        regs = m.regs
        if regs[RDI] != STATE + 0x80:
            raise Halt("spot map address")
        self.check_user(m, regs[RSI])
        regs[RAX] = ENTRY_AT if self.w["known_user"] else OTHER_ENTRY

    def on_count(self, m):
        regs = m.regs
        if regs[RDI] != self.field(0x11F0):
            raise Halt("count map address")
        self.check_user(m, regs[RSI])
        regs[RAX] = COUNT_AT

    def row_index(self, at):
        index, extra = divmod(at - ROWS_AT, ROW)
        if extra or not 0 <= index < len(self.w["rows"]):
            raise Halt("row pointer")
        return index

    def on_available(self, m):
        regs = m.regs
        index = self.row_index(regs[RDI])
        self.check_user(m, regs[RSI])
        mode = regs[RDX] & MASK[4]
        byte = None
        if mode == 4:
            byte = regs[RCX] & 0xFF
        self.log.append(["available", index, mode, byte])
        key = "%d:%d" % (index, mode)
        regs[RAX] = self.w["available"].get(key, 0)
        regs[RDX] = 0xAB00 | self.w["available_flag"].get(key, 0)
        m.keep_rdx = True

    def on_transfer(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RSI] != STATE:
            raise Halt("transfer state")
        self.check_user(m, regs[RCX])
        mode = regs[R8]
        if mode not in (0, 1, 2):
            raise Halt("transfer mode")
        self.log.append(["transfer", regs[RDX], mode, regs[R9] if mode != 2 else None])
        number = self.xfer_calls
        self.xfer_calls += 1
        status = self.w["transfer_fail"].get(str(number), OK)
        out = regs[RDI]
        memory.put_bytes(out, struct.pack("<H", status) + ramp(0x5E, status & 0x7F))

    def on_drop(self, m):
        memory = m.memory
        at = m.regs[RDI]
        status = memory.read(at, 2)
        if status == TEXT_STATUS:
            cap, text = memory.read(at + 8, 8), memory.read(at + 0x10, 8)
            if self.live.pop(text, None) != cap or memory.read(at + 0x18, 8) != cap or cap > 0x40:
                raise Halt("dropped text")
            self.log.append(["drop", status, memory.bytes_at(text, cap).decode("ascii")])
            return
        elif status == ACCOUNT_ERROR:
            pass
        elif memory.bytes_at(at + 2, 0x5E) != ramp(0x5E, status & 0x7F):
            raise Halt("dropped block")
        self.log.append(["drop", status, None])

    def on_dex_error(self, m):
        if m.memory.read(m.regs[RDI], 2) != DEX_ERROR:
            raise Halt("dex error word")

    def on_format(self, m):
        regs = m.regs
        memory = m.memory
        statics = memory.statics
        template, args = regs[RSI], regs[RDX]
        if template not in (TO_SPOT_TEMPLATE, FROM_SPOT_TEMPLATE):
            raise Halt("format template %#x" % template)
        if memory.read(args + 8, 8) != statics[SLOT_FORMAT_FN]:
            raise Halt("format function")
        status = memory.read(memory.read(args, 8), 2)
        name = "to_spot" if template == TO_SPOT_TEMPLATE else "from_spot"
        self.log.append(["format", name, status])
        data = ("move_token %s: %#x" % (name, status)).encode("ascii")
        at = self.allocate(len(data))
        memory.put_bytes(at, data)
        out = regs[RDI]
        memory.write(out, 8, len(data))
        memory.write(out + 8, 8, at)
        memory.write(out + 0x10, 8, len(data))

    def on_grow(self, m):
        memory = m.memory
        vector = m.regs[RDI]
        capacity, old, length = memory.read(vector, 8), memory.read(vector + 8, 8), memory.read(vector + 0x10, 8)
        if capacity != length or capacity > 0x100:
            raise Halt("grow vector")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * 8)
        if capacity:
            memory.copy(fresh, old, capacity * 8)
            if self.live.pop(old, None) != capacity * 8:
                raise Halt("grow free")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    def on_helper(self, m):
        regs = m.regs
        memory = m.memory
        rsp = regs[RSP]
        w = self.w
        if regs[RSI] != STATE + 0x498:
            raise Halt("account block")
        self.check_user(m, regs[RDX])
        token, mode, amount = regs[RCX], regs[R8], regs[R9]
        opt_flag = memory.read(rsp + 8, 8)
        value = memory.read(rsp + 0x10, 8)
        extra = memory.read(rsp + 0x18, 8)
        if memory.bytes_at(memory.read(rsp + 0x20, 8), 12) != ramp(12, 0x61) or memory.read(rsp + 0x28, 8) != STATE + 0x80:
            raise Halt("helper tail arguments")
        self.log.append(["helper", token, mode, amount if mode in (1, 2) else None, value if opt_flag else None, extra])
        word, tail, amount_out = w["helper"].get(str(mode), (0, 0, 0))
        out = regs[RDI]
        memory.put_bytes(out, struct.pack("<QB", word, tail) + ramp(0x107, mode * 3 + 1))
        memory.write(out + 0x100, 8, amount_out)

    def on_finish(self, m):
        regs = m.regs
        memory = m.memory
        if regs[RDI] != STATE or regs[R9] & 0xFF:
            raise Halt("finish arguments")
        self.check_user(m, regs[RSI])
        mode = regs[RCX] & 0xFF
        record = regs[R8]
        word, tail, amount_out = self.w["helper"].get(str(mode), (0, 0, 0))
        wanted = bytearray(ramp(0x107, mode * 3 + 1))
        wanted[0xF7:0xFF] = struct.pack("<Q", amount_out)
        if memory.read(record, 8) != word or memory.read(record + 8, 1) != tail or memory.bytes_at(record + 9, 0x107) != bytes(wanted):
            raise Halt("finish record")
        self.log.append(["finish", regs[RDX], mode, word, memory.read(record + 0x100, 8)])
        regs[RAX] = self.w["finish"].get(str(mode), FINISH_OK)

    def put_keys(self, at, shape, keys, spare, height=0, children=None):
        memory = self.machine.memory
        size = shape.size + (0x60 if height else 0)
        memory.put_bytes(at, ramp(size, 0x35))
        slots = (shape.edges - shape.keys) // shape.width if shape is not SPOT_NODE else 11
        for index in range(slots):
            memory.put_bytes(at + shape.keys + index * shape.width, keys[index] if index < len(keys) else spare)
        memory.write(at + shape.length, 2, len(keys))
        memory.write(at + shape.parent, 8, 0)
        if children:
            for index, child in enumerate(children):
                memory.write(at + shape.edges + index * 8, 8, child)
                memory.write(child + shape.parent, 8, at)
                memory.write(child + shape.slot, 2, index)

    def tree(self, shape, keys, spare):
        """A real tree of one or two levels; returns (root, height, node addresses)."""
        if not keys:
            return 0, 0, []
        if len(keys) <= LEAF_KEYS:
            root = self.static(shape.size)
            self.put_keys(root, shape, keys, spare)
            return root, 0, [root]
        leaves = []
        separators = []
        at = 0
        while at < len(keys):
            leaves.append(keys[at:at + LEAF_KEYS])
            separators.append(keys[at + LEAF_KEYS] if at + LEAF_KEYS < len(keys) else None)
            at += LEAF_KEYS + 1
        last = separators.pop()
        if last is not None:
            leaves[-1] = leaves[-1] + [last]
        nodes = []
        for leaf in leaves:
            node = self.static(shape.size)
            self.put_keys(node, shape, leaf, spare)
            nodes.append(node)
        root = self.static(shape.size + 0x60)
        self.put_keys(root, shape, separators, spare, 1, nodes)
        return root, 1, [root] + nodes

    def static(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        return at

    def spot_tree(self):
        """User balances: value words total and hold at +0x60 + 0x18 * index."""
        memory = self.machine.memory
        spot = self.w["spot"]
        keys = sorted(int(key) for key in spot)
        data = [struct.pack("<Q", key) for key in keys]
        root, height, nodes = self.tree(SPOT_NODE, data, struct.pack("<Q", self.w["args"].get("token", 7)))
        for node in nodes:
            count = memory.read(node + SPOT_NODE.length, 2)
            for index in range(count):
                key = memory.read(node + SPOT_NODE.keys + index * 8, 8)
                total, hold = spot[str(key)]
                memory.write(node + 0x60 + index * 0x18, 8, total)
                memory.write(node + 0x68 + index * 0x18, 8, hold)
        return root, height

    def build(self, w):
        memory = self.machine.memory
        self.w = w
        memory.reset(self.used)
        if w["zero_stack"]:
            memory.stack[:] = bytes(STACK_SIZE)
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.xfer_calls = 0
        memory.put_bytes(STATE, ramp(0x1400, 0x47))
        memory.put_bytes(STATE + 0x60, ramp(12, 0x61))
        memory.put_bytes(USER_AT, bytes.fromhex(USER))
        memory.write(STATE + 0x1040 - (SECOND_SHIFT if w["copy"] else 0) + 0, 8, ROWS_AT)
        memory.write(self.field(0x1048), 8, len(w["rows"]))
        for number, row in enumerate(w["rows"]):
            at = ROWS_AT + number * ROW
            memory.put_bytes(at, ramp(ROW, 0x13 + number))
            memory.write(at + 0x30, 8, row["index"])
            memory.write(at + 0x50, 8, row["token"])
            memory.write(at + 0x1C0, 8, row["cap"])
            memory.write(at + 0x230, 1, row["tag"])
            memory.write(at + 0x238, 8, row["used"])
            memory.write(at + 0x2ED, 1, row["byte"])
        reserve = sorted(w["reserve"])
        root, height, _ = self.tree(TOKEN_NODE, [struct.pack("<Q", key) for key in reserve], struct.pack("<Q", w["spare"]))
        memory.write(STATE + 0x568, 8, root)
        memory.write(STATE + 0x570, 8, height)
        memory.write(STATE + 0x578, 8, len(reserve))
        keys = sorted(bytes.fromhex(text) for text in w["set"] + ([USER] if w["exempt"] else []))
        root, height, _ = self.tree(SET_NODE, keys, bytes.fromhex(USER))
        memory.write(self.field(0x1350), 8, root)
        memory.write(self.field(0x1358), 8, height)
        memory.write(STATE + 0x598, 8, 0)
        memory.write(STATE + 0x5A0, 8, 0)
        if w["users"]:
            root, height, nodes = self.tree(USER_NODE, sorted(bytes.fromhex(text) for text in w["users"]), bytes.fromhex(OTHER_USER))
            memory.write(STATE + 0x598, 8, root)
            memory.write(STATE + 0x5A0, 8, height)
            for node in nodes:
                for index in range(memory.read(node + USER_NODE.length, 2)):
                    memory.write(node + index * 0x30 + 0x18, 8, 0)
        statics = memory.statics
        statics[ONCE_STATE] = 0
        statics[DEFAULT_ROW + 0x18] = statics[DEFAULT_ROW + 0x20] = statics[DEFAULT_ROW + 0x28] = 0
        root, height = self.spot_tree()
        memory.put_bytes(ENTRY_AT, ramp(0x40, 0x29))
        memory.write(ENTRY_AT + 0x10, 8, root)
        memory.write(ENTRY_AT + 0x18, 8, height)
        memory.put_bytes(OTHER_ENTRY, ramp(0x40, 0x2B))
        memory.write(OTHER_ENTRY + 0x10, 8, 0)
        memory.write(COUNT_AT + 0x38, 8, w["count_user"])
        memory.write(self.field(0x1258), 8, w["count_all"])

    def stack(self, words):
        memory = self.machine.memory
        for index, value in enumerate(words):
            memory.write(STACK_TOP - 0x100 + index * 8, 8, value)

    def run(self, case):
        w = case.world
        kind = case.kind
        a = w["args"]
        machine = self.machine
        memory = machine.memory
        self.build(w)
        copy = w["copy"]
        def side(value):
            return (0, 0x5151) if value is None else (1, value)
        try:
            if kind == "move" or kind == "wrap":
                source, target, cap = side(a["source"]), side(a["target"]), side(a["cap"])
                if kind == "move":
                    self.stack([target[0], target[1], cap[0], cap[1]])
                    machine.run(MOVE[copy], {RDI: OUT, RSI: STATE, RDX: USER_AT, RCX: a["token"], R8: source[0], R9: source[1]})
                else:
                    self.stack([target[1], cap[0], cap[1]])
                    rax = machine.run(WRAP[copy], {RDI: STATE, RSI: USER_AT, RDX: a["token"], RCX: source[0], R8: source[1], R9: target[0]})
                    some = rax == 1
                    if not some and rax != 0:
                        raise Halt("option word")
                    result = {"some": some, "value": machine.regs[RDX] if some else None}
            elif kind == "account":
                self.stack([a["opt"] if a["opt"] is not None else POISON, a["byte"]])
                machine.run(ACCOUNT[copy], {RDI: OUT, RSI: STATE, RDX: USER_AT, RCX: a["token"], R8: a["mode"], R9: 0 if a["opt"] is None else 1})
            elif kind == "reserve":
                target = side(a["target"])
                memory.put_bytes(WORD_AT, struct.pack("<QQQ", *a["word"]))
                self.stack([a["byte"]])
                machine.run(RESERVE[copy], {RDI: STATE, RSI: USER_AT, RDX: a["token"], RCX: target[0], R8: target[1], R9: WORD_AT})
                result = {}
            elif kind == "sweep":
                source = side(a["source"])
                machine.run(SWEEP[copy], {RDI: STATE, RSI: USER_AT, RDX: a["token"], RCX: source[0], R8: source[1]})
                result = {}
            elif kind == "gather":
                machine.run(GATHER[copy], {RDI: STATE, RSI: USER_AT})
                result = {}
            elif kind == "settle":
                machine.run(SETTLE[copy], {RDI: OUT, RSI: STATE, RDX: USER_AT, RCX: a["flag"], R8: 1 if a["every"] else 0, R9: a["token"]})
                result = self.read_list()
            else:
                target = side(a["target"])
                memory.put_bytes(WORD_AT, struct.pack("<QQQ", *a["word"]))
                self.stack([a["flag"]])
                machine.run(PULL[copy], {RDI: STATE, RSI: USER_AT, RDX: a["token"], RCX: target[0], R8: target[1], R9: WORD_AT})
                result = {}
        except Panicked as error:
            return {"panic": str(error), "log": self.log}
        if kind in ("move", "account"):
            result = self.read_status()
        if self.live:
            raise Halt("leak %r" % sorted(self.live.values()))
        return {"log": self.log, "result": result, "counts": [memory.read(self.field(0x1258), 8), memory.read(COUNT_AT + 0x38, 8)]}

    def read_list(self):
        memory = self.machine.memory
        cap = memory.read(OUT, 8)
        if cap == NONE_WORD:
            return {"fails": None}
        at, length = memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8)
        if length > 0x100:
            raise Halt("list length")
        fails = [memory.read(at + index * 8, 8) for index in range(length)]
        if self.live.pop(at, None) != cap * 8:
            raise Halt("list buffer")
        return {"fails": fails}

    def read_status(self):
        memory = self.machine.memory
        status = memory.read(OUT, 2)
        if status == OK:
            return {"status": status, "value": memory.read(OUT + 8, 8)}
        if status == ACCOUNT_ERROR:
            return {"status": status, "value": memory.read(OUT + 2, 1)}
        cap, at, length = memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8), memory.read(OUT + 0x18, 8)
        text = memory.bytes_at(at, length).decode("ascii")
        if status != TEXT_STATUS or self.live.pop(at, None) != cap or cap != length:
            raise Halt("text status")
        return {"status": status, "value": text}


CRASHES = (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError, TypeError, OverflowError, struct.error, UnicodeDecodeError, ZeroDivisionError)


def compare_run(harness, case):
    """None when the run agrees with the spec, else a text."""
    try:
        expected = spec_run(case)
        got = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.kind, case.label, str(error)[:120])
    if got != expected:
        return "%s: differ %s: %.400r != %.400r" % (case.kind, case.label, got, expected)
    return None


def ramp(count, start):
    return bytes((start + index * 7) & 0xFF for index in range(count))


# ---- cases ----

T1, T2, T3, T4 = 0x1234, 0x2345, 0x3456, 0x4567
AMOUNTS = (1, 99, 100, 101, 12345, 10 ** 12)


def dex_row(index, token=T1, tag=3, cap=10 ** 9, used=10 ** 6, byte=0):
    return {"index": index, "token": token, "tag": tag, "cap": cap, "used": used, "byte": byte}


def world(copy=0, rows=None, reserve=(), spot=None, exempt=False, others=(), known=True, available=None, ready=None, fail=None, helper=None, finish=None, args=None, count_all=5, count_user=7, spare=None, users=(), zero=False):
    rows = [dex_row(0), dex_row(1, T2)] if rows is None else rows
    return {"copy": copy, "rows": rows, "reserve": list(reserve), "spot": {str(k): v for k, v in (spot if spot is not None else {T1: (10 ** 10, 10 ** 8)}).items()}, "exempt": exempt, "set": list(others),
            "known_user": known, "available": {k: v & MAX64 for k, v in (available or {}).items()}, "available_flag": ready or {}, "transfer_fail": {str(k): v for k, v in (fail or {}).items()},
            "helper": {str(k): v for k, v in (helper or {}).items()}, "finish": {str(k): v for k, v in (finish or {}).items()}, "args": args or {}, "count_all": count_all, "count_user": count_user,
            "spare": (args or {}).get("token", T1) if spare is None else spare, "users": list(users), "zero_stack": zero}


def move_args(token=T1, source=None, target=None, cap=None):
    return {"token": token, "source": source, "target": target, "cap": cap}


def many_rows(count, token=T1):
    return [dex_row(index, token if index % 2 == 0 else T2, byte=index % 3) for index in range(count)]


def word_cases(copy):
    rows = []
    def add(kind, label, **options):
        rows.append(Case("copy %d %s %s" % (copy, kind, label), kind, world(copy, **options)))
    # move_token arguments and limits
    add("move", "spot to spot", args=move_args())
    add("move", "same dex", args=move_args(source=1, target=1, token=T2))
    add("move", "exempt user", exempt=True, args=move_args(target=0))
    add("move", "exempt with others", exempt=True, others=[OTHER_USER, "0" * 39 + "1", "f" * 40, "c" * 40, "d" * 40], args=move_args(target=0))
    add("move", "other users only", others=[OTHER_USER, "0" * 39 + "1", "f" * 40, "c" * 40, "d" * 40], args=move_args(target=0))
    add("move", "above every set key", others=["0" * 39 + "1", "0" * 39 + "2"], args=move_args(target=0))
    add("move", "below every set key", others=["e" * 40, "f" * 40], args=move_args(target=0))
    add("move", "counters saturated", args=move_args(target=0), count_all=MAX64, count_user=MAX64 - 1)
    for amount in AMOUNTS:
        add("move", "spot to main dex %d" % amount, spot={T1: (amount, 0)}, args=move_args(target=0))
        add("move", "dex to spot %d" % amount, available={"0:4": amount}, args=move_args(source=0))
        add("move", "cap %d" % amount, args=move_args(target=0, cap=amount))
        add("move", "limit left %d" % amount, rows=[dex_row(0, tag=1, cap=10 ** 9, used=10 ** 9 - amount)], args=move_args(target=0))
    add("move", "no spot row", spot={T2: (5000, 0)}, args=move_args(target=0))
    add("move", "unknown user", known=False, args=move_args(target=0))
    add("move", "wei keys tree", spot={k * 3 + 1: (1000 + k, k) for k in range(14)}, args=move_args(target=0, token=19))
    add("move", "wei keys tree miss", spot={k * 3 + 1: (1000 + k, k) for k in range(14)}, args=move_args(target=0, token=20))
    add("move", "hold above total", spot={T1: (5, 6)}, args=move_args(target=0))
    add("move", "negative dex value", available={"0:4": -5}, args=move_args(source=0))
    add("move", "zero dex value", args=move_args(source=0))
    add("move", "byte passes", rows=[dex_row(0, byte=2), dex_row(1, T2, byte=1)], available={"1:4": 7}, args=move_args(source=1, token=T2))
    add("move", "wrong source token", available={"1:4": 7}, args=move_args(source=1))
    add("move", "wrong target token", args=move_args(target=1))
    add("move", "wrong target after debit", rows=[dex_row(0), dex_row(1, T2)], available={"0:4": 700}, args=move_args(source=0, target=1))
    add("move", "dex to dex", rows=[dex_row(0), dex_row(1)], available={"0:4": 700}, args=move_args(source=0, target=1))
    add("move", "dex to dex limited", rows=[dex_row(0), dex_row(1, tag=1, cap=100, used=60)], available={"0:4": 700}, args=move_args(source=0, target=1))
    add("move", "dex to dex capped", rows=[dex_row(0), dex_row(1)], available={"0:4": 700}, args=move_args(source=0, target=1, cap=33))
    add("move", "negative cap panics", rows=[dex_row(0, tag=1, cap=MIN63)], args=move_args(target=0))
    add("move", "cap below used", rows=[dex_row(0, tag=1, cap=5, used=6)], args=move_args(target=0))
    add("move", "used negative overflow", rows=[dex_row(0, tag=1, cap=MAX63, used=(1 << 64) - 2)], args=move_args(target=0))
    add("move", "used most negative", rows=[dex_row(0, tag=2, cap=1, used=MIN63)], args=move_args(target=0))
    add("move", "tag 0 limited", rows=[dex_row(0, tag=0, cap=50, used=20)], args=move_args(target=0))
    add("move", "tag 4 limited", rows=[dex_row(0, tag=4, cap=50, used=20)], args=move_args(target=0))
    add("move", "target at count", args=move_args(target=2))
    add("move", "target above count", args=move_args(target=3))
    add("move", "source at count", args=move_args(source=2))
    add("move", "exact count minus one", available={"1:4": 9}, args=move_args(source=1, token=T2))
    add("move", "first debit fails", available={"0:4": 700}, fail={0: 0x71}, args=move_args(source=0))
    add("move", "credit fails from spot", fail={0: 0x72}, args=move_args(target=0))
    add("move", "credit fails, undo ok", rows=[dex_row(0), dex_row(1)], available={"0:4": 700}, fail={1: 0x73}, args=move_args(source=0, target=1))
    add("move", "credit and undo fail", rows=[dex_row(0), dex_row(1)], available={"0:4": 700}, fail={1: 0x73, 2: 0x74}, args=move_args(source=0, target=1))
    # wrapper
    add("wrap", "some", spot={T1: (900, 100)}, args=move_args(target=0))
    add("wrap", "some capped", spot={T1: (90000, 100)}, args=move_args(target=0, cap=5))
    add("wrap", "none", fail={0: 0x71}, args=move_args(target=0))
    add("wrap", "source", available={"0:4": 700}, args=move_args(source=0))
    add("wrap", "dex to dex", rows=[dex_row(0), dex_row(1)], available={"0:4": 700}, args=move_args(source=0, target=1, cap=9))
    # account step
    for mode in range(4):
        for byte in (0, 1):
            add("account", "mode %d byte %d" % (mode, byte), helper={mode: (0, 0x5, 0x777)}, args={"token": T1, "mode": mode, "opt": None, "byte": byte})
        add("account", "mode %d word 1" % mode, helper={mode: (1, 0x6, 0x888)}, args={"token": T1, "mode": mode, "opt": 0x99, "byte": 0})
        add("account", "mode %d none" % mode, helper={mode: (2, 0, 0)}, args={"token": T1, "mode": mode, "opt": None, "byte": 1})
        add("account", "mode %d error" % mode, helper={mode: (3, 0x2D, 0)}, args={"token": T1, "mode": mode, "opt": None, "byte": 1})
        add("account", "mode %d finish fails" % mode, helper={mode: (0, 7, 0x444)}, finish={mode: 0x12}, args={"token": T1, "mode": mode, "opt": None, "byte": 0})
    for mode in (1, 2):
        add("account", "mode %d no token" % mode, spot={T2: (5, 1)}, args={"token": T1, "mode": mode, "opt": None, "byte": 0})
        add("account", "mode %d unknown user" % mode, known=False, args={"token": T1, "mode": mode, "opt": None, "byte": 0})
        add("account", "mode %d hold above" % mode, spot={T1: (5, 6)}, args={"token": T1, "mode": mode, "opt": None, "byte": 0})
        add("account", "mode %d tree" % mode, spot={k * 3 + 1: (1000 + k, k) for k in range(14)}, args={"token": 19, "mode": mode, "opt": None, "byte": 0})
        add("account", "mode %d tree miss" % mode, spot={k * 3 + 1: (1000 + k, k) for k in range(14)}, args={"token": 20, "mode": mode, "opt": None, "byte": 0})
        add("account", "mode %d word 2 keeps nothing" % mode, helper={mode: (2, 0x3, 0x55)}, args={"token": T1, "mode": mode, "opt": None, "byte": 0})
    # reserve moves
    for word in ((0, 0, 0), (1, T2, 0x31), (1, T3, 0x31), (2, 0, 0), (3, T2, 0x32), (3, T3, 0x32), (4, T2, 0x33), (5, T2, 0x34), (9, T2, 0x35)):
        for reserve in ((), (T1,), (T2,), (T1, T2), (T1, T2, T3, T4, 0x9000, 0x9001, 0x9002, 0x9003)):
            for byte in (0, 1):
                add("reserve", "word %d key %#x in %d %#x byte %d" % (word[0], word[1], len(reserve), reserve[0] if reserve else 0, byte), reserve=reserve, args={"token": T1, "target": 0, "word": list(word), "byte": byte})
    for mode, failed in ((3, 0), (0, 0)):
        add("reserve", "word 2 mode %d fails" % mode, reserve=(T1,), helper={mode: (3, 9, 0)}, args={"token": T1, "target": 0, "word": [2, 0, 0], "byte": 0})
    add("reserve", "word 1 key step fails stops", reserve=(T1, T2), helper={3: (3, 9, 0)}, args={"token": T1, "target": 0, "word": [1, T2, 5], "byte": 0})
    add("reserve", "word 0 step fails moves", reserve=(T1,), helper={3: (3, 9, 0)}, args={"token": T1, "target": 0, "word": [0, 0, 0], "byte": 0})
    add("reserve", "move fails", reserve=(T1,), fail={0: 0x75}, args={"token": T1, "target": 0, "word": [2, 0, 0], "byte": 1})
    add("reserve", "no target", reserve=(T1,), args={"token": T1, "target": None, "word": [0, 0, 0], "byte": 0})
    # sweep
    for reserve in ((), (T1,), (T2, T4), (T1, T2, T3, T4, 0x9000)):
        add("sweep", "spot in %d" % len(reserve), reserve=reserve, args={"token": T1, "source": None})
        add("sweep", "dex in %d" % len(reserve), reserve=reserve, available={"0:4": 77}, args={"token": T1, "source": 0})
    add("sweep", "move fails", reserve=(T1,), available={"0:4": 77}, fail={0: 0x76}, args={"token": T1, "source": 0})
    add("sweep", "mode 2 fails", reserve=(T1,), helper={2: (3, 9, 0)}, args={"token": T1, "source": None})
    add("sweep", "mode 1 fails", reserve=(T1,), helper={1: (3, 9, 0)}, args={"token": T1, "source": None})
    add("sweep", "last key", reserve=(T1, T2, T3), args={"token": T3, "source": None})
    # settle
    def settle(label, flag=0, every=False, token=T1, **options):
        add("settle", label, args={"flag": flag, "every": every, "token": token}, **options)
    for flag in (0, 1):
        settle("flag %d no dex" % flag, flag, rows=[])
        settle("flag %d one token idle" % flag, flag)
        settle("flag %d no row for token" % flag, flag, token=T3)
        key = 2 if flag else 4
        settle("flag %d need covered" % flag, flag, available={"0:%d" % key: -500, "0:4": 700 if flag else -500})
        settle("flag %d need short" % flag, flag, spot={T1: (10000, 0)}, available={"0:%d" % key: -500, "0:4": -500})
        settle("flag %d ready, no need" % flag, flag, ready={"0:%d" % key: 1, "0:4": 1})
        settle("flag %d ready high bits" % flag, flag, ready={"0:%d" % key: 2, "0:4": 2})
        settle("flag %d ready with need" % flag, flag, ready={"0:%d" % key: 1, "0:4": 1}, available={"0:%d" % key: -50, "0:4": -50})
        settle("flag %d two rows of token" % flag, flag, rows=[dex_row(0), dex_row(1), dex_row(2, T2, byte=1)], available={"0:%d" % key: -50, "1:%d" % key: -60, "0:4": -50, "1:4": -60}, ready={"0:%d" % key: 1, "1:%d" % key: 1, "0:4": 1, "1:4": 1})
        settle("flag %d five rows" % flag, flag, rows=many_rows(5), available={"%d:%d" % (i, key): -50 - i for i in range(5)}, ready={"%d:%d" % (i, key): 1 for i in range(5)})
        settle("flag %d four rows" % flag, flag, rows=many_rows(4), available={"0:4": 100, "2:4": 100})
        settle("flag %d duplicate index" % flag, flag, rows=[dex_row(1), dex_row(1), dex_row(0, T2)])
        settle("flag %d index at count" % flag, flag, rows=[dex_row(2), dex_row(1, T2)])
        settle("flag %d most negative" % flag, flag, available={"0:%d" % key: -(1 << 63)})
        settle("flag %d move fails" % flag, flag, available={"0:%d" % key: -50}, fail={(0 if not flag else 1): 0x77})
        settle("flag %d first pass fails" % flag, flag, available={"0:4": 900}, fail={0: 0x78})
        settle("flag %d every, no reserve" % flag, flag, True)
        settle("flag %d every, one" % flag, flag, True, reserve=(T1,), available={"0:%d" % key: -50, "0:4": -50 if not flag else 90})
        settle("flag %d every, two" % flag, flag, True, reserve=(T1, T2), spot={T1: (10 ** 9, 0), T2: (10 ** 9, 0)}, available={"0:%d" % key: -50, "1:%d" % key: -70, "0:4": -50, "1:4": -70}, ready={"0:%d" % key: 1, "1:%d" % key: 1, "0:4": 1, "1:4": 1})
        settle("flag %d every, reserve without row" % flag, flag, True, reserve=(T3,))
        settle("flag %d every, many keys" % flag, flag, True, reserve=(T1, T2, T3, T4, 0x9000, 0x9001, 0x9002, 0x9003, 0x9004, 0x9005), available={"0:%d" % key: -5, "0:4": -5})
        settle("flag %d every, helper fails" % flag, flag, True, reserve=(T1,), helper={3: (3, 8, 0), 2: (3, 8, 0)}, available={"0:%d" % key: -50, "0:4": -50})
    settle("share of one hit", 1, available={"0:2": -40, "0:4": -40}, ready={"0:2": 1, "0:4": 1}, spot={T1: (0, 0)})
    settle("share after first", 1, available={"0:2": -4000, "0:4": 5000}, ready={"0:2": 1}, spot={T1: (10 ** 7, 0)})
    for spot_wei in (0, 99, 100, 700, 800, 1000, 3000, 12345678, 10 ** 11):
        settle("share over two %d" % spot_wei, 1, rows=[dex_row(0), dex_row(1), dex_row(2, T2)], spot={T1: (spot_wei, 0)}, ready={"0:2": 1, "1:2": 1}, available={"0:4": -700, "1:4": -900})
        settle("share with reserve %d" % spot_wei, 1, True, rows=[dex_row(0), dex_row(1)], reserve=(T1,), spot={T1: (spot_wei, 0)}, ready={"0:2": 1, "1:2": 1}, available={"0:4": -700, "1:4": -900})
    settle("share two tokens", 1, True, rows=[dex_row(0), dex_row(1), dex_row(2, T2), dex_row(3, T2)], reserve=(T1, T2), spot={T1: (10 ** 7, 0), T2: (3 * 10 ** 7, 0)}, ready={"%d:2" % i: 1 for i in range(4)}, available={"%d:4" % i: -10 ** 6 for i in range(4)})
    settle("share three tokens", 1, False, rows=[dex_row(0), dex_row(1)], spot={T1: (10 ** 7, 0)}, ready={"0:2": 1, "1:2": 1}, available={"1:4": -10 ** 6})
    settle("share, hold above", 1, spot={T1: (5, 6)}, ready={"0:2": 1})
    settle("share, no balance", 1, spot={T2: (5, 0)}, ready={"0:2": 1}, available={"0:4": -9})
    settle("share, ready high", 1, ready={"0:2": 1, "0:4": 2}, available={"0:4": 0})
    settle("share, ready none", 1, ready={"0:2": 1, "0:4": 0}, available={"0:4": 0})
    settle("share, most negative", 1, ready={"0:2": 1}, available={"0:4": -(1 << 63)})
    settle("share, move fails", 1, ready={"0:2": 1}, available={"0:4": -900}, fail={0: 0x79})
    settle("share, huge spot", 1, ready={"0:2": 1}, available={"0:4": -(10 ** 15)}, spot={T1: (MAX64, 0)})
    settle("share, index past count", 1, rows=[dex_row(2), dex_row(1, T2)], ready={"2:2": 1})
    # pull
    def pull(label, flag=0, word=(0, 0, 0), token=T1, target=0, **options):
        add("pull", label, args={"token": token, "target": target, "word": list(word), "flag": flag}, **options)
    for flag in (0, 1):
        pull("plain flag %d" % flag, flag)
        pull("in reserve flag %d" % flag, flag, reserve=(T1,))
        pull("other reserve flag %d" % flag, flag, reserve=(T2,))
        pull("no target flag %d" % flag, flag, target=None)
        pull("failed list freed flag %d" % flag, flag, available={"0:4": -500}, spot={T1: (10000, 0)})
        pull("failed move flag %d" % flag, flag, fail={0: 0x7A})
        pull("high flag bits %d" % flag, flag | 0x100)
        pull("every keys flag %d" % flag, flag, reserve=(T1, T2, T3, T4, 0x9000, 0x9001, 0x9002, 0x9003, 0x9004))
        pull("last key flag %d" % flag, flag, reserve=(T1, T2, T3, T4), token=T4, rows=[dex_row(0), dex_row(1, T4)], target=1)
        pull("above keys flag %d" % flag, flag, reserve=(T1, T2), token=0x8000, spot={0x8000: (5000, 0)}, rows=[dex_row(0, 0x8000)])
    for word in ((1, T1, 0x31), (2, 0, 0), (3, T2, 0x31), (4, 0, 0)):
        pull("word %d" % word[0], 1, word, reserve=(T1, T2))
    # second round: gaps the first mutation pass showed
    add("move", "target past count, nothing to move", spot={}, args=move_args(target=2))
    add("move", "huge source into a saturated limit", rows=[dex_row(0), dex_row(1, tag=1, cap=MAX63, used=(1 << 64) - 2)], available={"0:4": MAX63}, args=move_args(source=0, target=1))
    add("move", "stale cap word", zero=True, args=move_args(target=0))
    add("move", "user counter one below", count_all=MAX64 - 1, count_user=MAX64, args=move_args(target=0))
    add("sweep", "stale cap word", zero=True, reserve=(T1,), available={"0:4": 77}, args={"token": T1, "source": 0})
    add("reserve", "stale cap word", zero=True, args={"token": T1, "target": 0, "word": [0, 0, 0], "byte": 0})
    keys = (T1, T2, T3, T4, 0x9000, 0x9001, 0x9002, 0x9003)
    for key in (5, T1, T3, 0x4000, T4, 0x9003, 0x9999):
        for reserve in (keys[:3], keys):
            add("reserve", "key %#x word 1 over %d" % (key, len(reserve)), reserve=reserve, spare=key, args={"token": key, "target": 0, "word": [1, key, 0x31], "byte": 0})
            add("reserve", "key %#x word 2 over %d" % (key, len(reserve)), reserve=reserve, spare=key, args={"token": key, "target": 0, "word": [2, 0, 0], "byte": 0})
            add("reserve", "key %#x word 4 over %d" % (key, len(reserve)), reserve=reserve, spare=key, args={"token": key, "target": 0, "word": [4, 0, 0], "byte": 0})
            add("sweep", "key %#x over %d" % (key, len(reserve)), reserve=reserve, spare=key, args={"token": key, "source": None})
            add("pull", "key %#x over %d" % (key, len(reserve)), reserve=reserve, spare=key, args={"token": key, "target": 0, "word": [2, 0, 0], "flag": 1})
    pull("failed list with reserve", 1, (2, 0, 0), reserve=(T1,), available={"0:4": -500}, spot={T1: (10000, 0)})
    pull("high flag bits, in map", 0x100, (2, 0, 0), reserve=(T1,))
    pull("high flag bits with low bit, in map", 0x101, (2, 0, 0), reserve=(T1,))
    settle("no dex, keys", 0, True, rows=[], reserve=(T1, T2))
    settle("no dex, keys, flag", 1, True, rows=[], reserve=(T1, T2))
    settle("nine rows", 0, rows=many_rows(9), available={"%d:4" % i: 10 + i for i in range(9)})
    settle("nine rows, flag", 1, rows=many_rows(9), ready={"%d:2" % i: 1 for i in range(9)}, available={"%d:4" % i: -10 - i for i in range(9)})
    settle("index past count, no tokens", 0, True, rows=[dex_row(2), dex_row(1, T2)])
    settle("index past count, no tokens, flag", 1, True, rows=[dex_row(2), dex_row(1, T2)])
    settle("stale cap word", 0, zero=True, available={"0:4": 77})
    for flag, key in ((0, 4), (1, 2)):
        settle("high positive value %d" % flag, flag, available={"0:%d" % key: (1 << 62) + 1})
        settle("first of two moves fails %d" % flag, flag, rows=[dex_row(0), dex_row(1), dex_row(2, T2)], available={"0:%d" % key: -50, "1:%d" % key: -60}, fail={(0 if not flag else 2): 0x7C})
        settle("spot tree %d" % flag, flag, spot={k * 3 + 1: (10 ** 6 + k, k) for k in range(14)}, rows=[dex_row(0, 19), dex_row(1, 20)], token=19, available={"0:%d" % key: -50, "0:4": -50}, ready={"0:%d" % key: 1})
        settle("spot tree miss %d" % flag, flag, spot={k * 3 + 1: (10 ** 6 + k, k) for k in range(14)}, rows=[dex_row(0, 19), dex_row(1, 20)], token=20, available={"1:%d" % key: -50, "1:4": -50}, ready={"1:%d" % key: 1})
    settle("share high positive", 1, ready={"0:2": 1}, available={"0:4": (1 << 62) + 1})
    settle("share first of two fails", 1, rows=[dex_row(0), dex_row(1), dex_row(2, T2)], ready={"0:2": 1, "1:2": 1}, available={"0:4": -50, "1:4": -60}, fail={0: 0x7D})
    wide = list(range(0x100, 0x10D))
    for flag, key in ((0, 4), (1, 2)):
        settle("thirteen tokens %d" % flag, flag, True, reserve=wide, rows=[dex_row(i, wide[i]) for i in range(13)], spot={token: (10 ** 7, 0) for token in wide}, available={"%d:4" % i: -5 - i for i in range(13)}, ready={"%d:%d" % (i, key): 1 for i in range(13)})
    # gather
    add("gather", "no dex, no reserve", rows=[])
    add("gather", "idle", args={})
    add("gather", "balances", rows=many_rows(4), available={"%d:4" % i: 100 + i for i in range(4)})
    add("gather", "five rows", rows=many_rows(5), available={"%d:4" % i: 100 + i for i in range(5)})
    add("gather", "index past count", rows=[dex_row(2), dex_row(1, T2)])
    add("gather", "move fails", available={"0:4": 900}, fail={0: 0x7B})
    add("gather", "reserve", reserve=(T1, T2), helper={3: (2, 0, 0)})
    add("gather", "many keys", reserve=(T1, T2, T3, T4, 0x9000, 0x9001), available={"1:4": 500})
    add("gather", "account fails", reserve=(T1,), helper={3: (3, 4, 0)})
    add("gather", "nine rows", rows=many_rows(9), available={"%d:4" % i: 100 + i for i in range(9)})
    add("gather", "stale cap word", zero=True, available={"0:4": 900})
    add("gather", "user entry", users=[USER])
    add("gather", "other users", users=[OTHER_USER, "0" * 40])
    add("gather", "user above keys", users=["0" * 39 + "1", "0" * 39 + "2"])
    add("gather", "user among keys", users=["0" * 39 + "1", USER, OTHER_USER, "a" * 40, "b" * 40, "c" * 40])
    return rows


def all_cases():
    return word_cases(0) + word_cases(1)


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


FAMILIES = (("collateral move", MOVE), ("undo of a debit", UNDO), ("reserve move", RESERVE), ("settle pass", SETTLE), ("move wrapper", WRAP), ("sweep", SWEEP), ("pull", PULL), ("account block step", ACCOUNT), ("gather", GATHER))
GROUPS = tuple((pair[index], "%s copy %d" % (name, index + 1), None) for name, pair in FAMILIES for index in (0, 1))
EXTRA_FUNCTIONS = ((AMOUNT, "amount helper: a table row in #46 and #922, run with no mutants", None), (COLLECT, "key collector, run with no mutants", None), (ITERATE, "key iterator, run with no mutants", None),
                   (MAP_INSERT, "result map insert, run with no mutants", None), (MAP_SPLIT, "result map node split, run with no mutants", None), (MAP_DRAIN, "result map drain, run with no mutants", None), (USER_ITERATE, "user tree iterator with an unused result, run with no mutants", None))


def group_rows(image, begin, end, ranges):
    """Whole body, or only the listed arms."""
    if ranges is None:
        return decode_range(image, begin, end)
    rows = []
    for low, high in ranges:
        rows += decode_range(image, low, high)
    return rows


def mutated_groups(image):
    """(function start, role, decoded rows inside the range of the group)."""
    groups = []
    for start, role, ranges in GROUPS:
        begin, end = image.exact_fde(start)
        groups.append((start, role, group_rows(image, begin, end, ranges)))
    return groups


def run_mutants(image, reached, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run; the last killers go first."""
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
                    del first_kill[60:]
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": ":".join(failed.split(":")[:2])[:70] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def require(image, va, data, what):
    if code(image, va, len(data)) != data:
        raise EvidenceError("%s: bytes at %#x differ" % (what, va))


def lea_target(image, site):
    """Target of a rip relative lea of seven bytes."""
    data = code(image, site, 7)
    if data[1] != 0x8D or data[2] & 0xC7 != 5:
        raise EvidenceError("no rip lea at %#x" % site)
    return site + 7 + struct.unpack_from("<i", data, 3)[0]


def text_at(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")



def location_row(image, relative, slot):
    path, line, column = image.location(slot, relative)
    return {"slot": "%#x" % slot, "path": path, "line": line, "column": column}


def text_rows(image):
    """Length prefixed format templates and the immediates that spell the fixed text."""
    rows = []
    for va in (TO_SPOT_TEMPLATE, FROM_SPOT_TEMPLATE):
        size = image.blob[image.offset(va)]
        rows.append({"va": "%#x" % va, "length": size, "text": text_at(image, va + 1, size)})
    return rows


def mismatch_sites(image):
    """Every `movabs rcx` pair spelling the 14 byte text inside the move bodies, by raw bytes."""
    rows = []
    low = struct.pack("<Q", 0x696D206E656B6F74)
    high = struct.pack("<Q", 0x686374616D73696D)
    for start in MOVE:
        begin, end = image.exact_fde(start)
        body = code(image, begin, end - begin)
        sites = [begin + match.start() for match in re.finditer(b"\\x48\\xb9" + re.escape(high), body)]
        rows.append({"function": "%#x" % start, "sites": ["%#x" % site for site in sites], "low_words": body.count(low), "text": (low + high)[:8].decode("ascii") + (high)[2:].decode("ascii")})
    return rows


def call_rows(image):
    """Direct callers of the route entry points, by rel32 bytes."""
    targets = {}
    for name, pair in (("move", MOVE), ("wrapper", WRAP), ("settle", SETTLE), ("sweep", SWEEP), ("pull", PULL), ("reserve", RESERVE), ("account", ACCOUNT), ("gather", GATHER)):
        for index, start in enumerate(pair):
            targets[start] = (name, index + 1)
    rows = []
    for target, sites in sorted(direct_sites(image, list(targets)).items()):
        for site, opcode in sorted(sites):
            rows.append({"name": targets[target][0], "copy": targets[target][1], "target": "%#x" % target, "site": "%#x" % site, "host": "%#x" % image.fde(site)[0], "opcode": "call" if opcode == 0xE8 else "jump"})
    return rows


def copy_rows(image):
    """Second copy against the first, instruction by instruction: calls, jumps and rip words aside, only a field 0xa80 lower may differ."""
    rows = []
    for name, pair in FAMILIES:
        first = decode_range(image, *image.exact_fde(pair[0]))
        second = decode_range(image, *image.exact_fde(pair[1]))
        row = {"family": name, "first": "%#x" % pair[0], "second": "%#x" % pair[1], "first_rows": len(first), "second_rows": len(second), "same_shape": len(first) == len(second)}
        if len(first) == len(second):
            shifted = other = 0
            for left, right in zip(first, second):
                if left.op != right.op:
                    other += 1
                for one, two in ((left.a, right.a), (left.b, right.b)):
                    if one != two and one and two and one[0] == "m" and two[0] == "m" and one[1] is not None:
                        if one[4] - two[4] == SECOND_SHIFT and one[4] >= 0x1040:
                            shifted += 1
                        else:
                            other += 1
            row.update(shifted_fields=shifted, other_differences=other)
        rows.append(row)
    return rows


FIELD_OFFSETS = (0x30, 0x50, 0x568, 0x570, 0x578, 0x7F2, 0x1C0, 0x230, 0x238, 0x2ED, 0x1040, 0x1048, 0x1258, 0x1350, 0x1358, 0x876, 0x878, 0x16A, 0x170)


def field_rows(image):
    """Operand displacement census in the first copies, from decoded rows."""
    counts = collections.Counter()
    for name, pair in FAMILIES:
        for row in decode_range(image, *image.exact_fde(pair[0])):
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4] in FIELD_OFFSETS:
                    counts[operand[4]] += 1
    return {"%#x" % offset: counts[offset] for offset in FIELD_OFFSETS}


def table_rows(image):
    """Mode table of the amount helper; entries 0 to 3 land in the function."""
    begin, end = image.exact_fde(AMOUNT)
    rows = []
    for index in range(4):
        arm = AMOUNT_TABLE + struct.unpack_from("<i", image.blob, image.offset(AMOUNT_TABLE) + index * 4)[0]
        if not begin <= arm < end:
            raise EvidenceError("amount table entry %d" % index)
        rows.append({"mode": index, "arm": "%#x" % arm})
    return rows


def router_rows(image):
    """Routers: each pull call site has `cmp r32,4; sete al` before it, and `cmp r32,4; jne` after the insert, so mode 4 sets the flag and takes the sweep."""
    rows = []
    for start in ROUTERS:
        begin, end = image.exact_fde(start)
        body = code(image, begin, end - begin)
        pull = [site for site, _ in direct_sites(image, list(PULL))[PULL[0 if start in ROUTERS[:2] else 1]] if begin <= site < end]
        sweep = [site for site, _ in direct_sites(image, list(SWEEP))[SWEEP[0 if start in ROUTERS[:2] else 1]] if begin <= site < end]
        if len(pull) != 1 or len(sweep) != 1:
            raise EvidenceError("router %#x mode tests" % start)
        flags = [begin + match.start() for match in re.finditer(b"(?:\x41)?\x83[\xf8-\xff]\x04\x0f\x94\xc0", body) if 0 < pull[0] - begin - match.start() < 0x60]
        tests = [begin + match.start() for match in re.finditer(b"(?:\x41)?\x83[\xf8-\xff]\x04\x75", body) if pull[0] < begin + match.start() < sweep[0]]
        if len(flags) != 1 or len(tests) != 1:
            raise EvidenceError("router %#x order" % start)
        rows.append({"router": "%#x" % start, "flag_test": "%#x" % flags[0], "pull": "%#x" % pull[0], "mode_test": "%#x" % tests[0], "sweep": "%#x" % sweep[0]})
    return rows


def float_words(image):
    return {"%#x" % va: "%#x" % struct.unpack_from("<Q", image.blob, image.offset(va))[0] for va in (0x20AAB8, 0x20ACB8, 0x20A7F0, 0x20A2C8, 0x20A4B0)}


def outcome_name(case, spec):
    if "panic" in spec:
        return "%s panic %s" % (case.kind, spec["panic"])
    result = spec["result"]
    if "status" in result:
        return "%s status %#x" % (case.kind, result["status"])
    if "some" in result:
        return "%s %s" % (case.kind, "some" if result["some"] else "none")
    if "fails" in result:
        return "%s %s" % (case.kind, "fails" if result["fails"] else "all covered")
    return "%s done" % case.kind


def case_line(case, spec):
    return "\t".join((case.kind, "copy %d" % (case.world["copy"] + 1), case.label, outcome_name(case, spec), str(len(spec["log"]))))


def sample_lines():
    """Worked share: two dexes of one token, 3 parts each, one part kept for the account block when it has the token."""
    rows = []
    for every, reserve in ((False, ()), (True, (T1,))):
        w = world(rows=[dex_row(0), dex_row(1)], reserve=reserve, spot={T1: (10 ** 8, 0)}, ready={"0:2": 1, "1:2": 1}, available={"0:4": -10 ** 7, "1:4": -10 ** 7}, args={"flag": 1, "every": every, "token": T1})
        spec = Spec(w)
        spec.settle(1, every, T1)
        moved = [row for row in spec.log if row[0] == "transfer" and row[2] == 0]
        rows.append("every=%d free=%d: %s" % (every, 10 ** 8 // 100, " ".join("dex %d +%d" % (row[1], row[3]) for row in moved)))
    return rows


def analyse(image, full=True, verbose=False):
    harness = Harness(image)
    cases = all_cases()
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    lines = []
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
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
    for start, role, ranges in GROUPS + EXTRA_FUNCTIONS:
        begin, end = image.exact_fde(start)
        rows = group_rows(image, begin, end, ranges)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    calls = call_rows(image)
    statics = {
        "templates": text_rows(image),
        "mismatch_text": mismatch_sites(image),
        "copies": copy_rows(image),
        "fields": field_rows(image),
        "amount_table": table_rows(image),
        "float_words": float_words(image),
        "routers": router_rows(image),
        "locations": [location_row(image, relative, slot) for slot in (0x56E9AE0, 0x56DFD90, 0x572E4E0, 0x572E4C8)],
        "mode_text": {"va": "%#x" % MODE_TEXT, "text": text_at(image, MODE_TEXT, 43)},
    }
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "samples": sample_lines(),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "route_call_summary": dict(sorted(collections.Counter("%s copy %d" % (row_["name"], row_["copy"]) for row_ in calls).items())),
        "_results": results_rows, "_lines": lines, "_calls": calls,
    }
    doc.update(statics)
    return doc


SURVIVED_DEFAULT = "no reason recorded"
TEXT_REASON = "equivalent: the two stores overlap by two bytes, so the low byte of this word is overwritten"
BOUND_REASON = "second read of a bound that an earlier check on the same index already passed"
ITERATOR_REASON = "back half of the range iterator: forward iteration never reads it"
DANGLING_REASON = "dangling pointer or start value of an empty Vec, never read"
CAPACITY_REASON = "layout overflow test of the key Vec: needs a map above 2^60 keys"
SUM_REASON = "saturation of a sum of list lengths: needs over 2^62 hits"
DEEP_REASON = "walk of a result map of height 2 or more: needs over 132 tokens"
CLAMP_REASON = "clamp and saturation of the share cast: free spot times 3 cannot reach 2^63"
LOOKUP_REASON = "a wrong length in this read only changes a share that the later free read inside the move caps at the same value"
TAIL_REASON = "user lookup and walk whose result is never used: no state or call depends on it"
WORD_REASON = "word 1 here needs a stale stack key that is in the map, which the frame never holds"
SURVIVED_REASONS = {}
for _start, _offsets, _reason in (
    (MOVE[0], (0x3BE, 0x5D7), TEXT_REASON), (MOVE[0], (0x471, 0x50E), BOUND_REASON),
    (SETTLE[0], (0x2A1, 0x7D5, 0x895, 0x8C1, 0x1386, 0x13B0), BOUND_REASON),
    (SETTLE[0], (0x8B, 0x512, 0x15FC), ITERATOR_REASON), (SETTLE[0], (0x14F, 0x4E3, 0x5CC, 0x697), DANGLING_REASON),
    (SETTLE[0], (0x47B, 0x482, 0x48C), CAPACITY_REASON), (SETTLE[0], (0xC7E, 0xCA6, 0xCAA, 0x120F, 0x1216, 0x121A), SUM_REASON),
    (SETTLE[0], (0xD25, 0xDB9, 0xDC6, 0xDF3, 0xE08, 0xF45, 0xFDA, 0x1013, 0x1028), DEEP_REASON),
    (SETTLE[0], (0x12CA, 0x12D4, 0x1301), CLAMP_REASON), (SETTLE[0], (0x1131,), LOOKUP_REASON),
    (GATHER[0], (0x118,), BOUND_REASON), (GATHER[0], (0x225,), ITERATOR_REASON), (GATHER[0], (0x288,), DANGLING_REASON), (GATHER[0], (0x225 + 0x2F,), ITERATOR_REASON),
    (GATHER[0], (0x225, 0x22C), CAPACITY_REASON), (GATHER[0], (0x2B6,), ITERATOR_REASON), (GATHER[0], (0x313,), WORD_REASON),
    (GATHER[0], (0x393, 0x39A, 0x3D3, 0x3D5, 0x3E9, 0x3EC, 0x3F8, 0x3FF, 0x401, 0x408, 0x442, 0x45A, 0x466, 0x474, 0x48C, 0x4BB), TAIL_REASON),
):
    for _offset in _offsets:
        SURVIVED_REASONS[_start + _offset] = _reason
        SURVIVED_REASONS[{MOVE[0]: MOVE[1], SETTLE[0]: SETTLE[1], GATHER[0]: GATHER[1]}[_start] + _offset] = _reason
SURVIVED_REASONS.update({MOVE[1] + 0x3E6: TEXT_REASON, MOVE[1] + 0x5FB: TEXT_REASON, MOVE[1] + 0x499: BOUND_REASON, MOVE[1] + 0x530: BOUND_REASON, MOVE[1] + 0x2FF: BOUND_REASON})


UNREACHED_REASON = "no case reaches it: an allocator failure arm, a panic arm, an unwind pad, the second token check of a move (the first check returns before it), or an arm the sums make dead"


def reason_for(row):
    if row["result"] == "killed":
        return ""
    if row["result"] == "unreached":
        return UNREACHED_REASON
    return SURVIVED_REASONS.get(row["va"], SURVIVED_DEFAULT)


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    calls = evidence.pop("_calls")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["name\tcopy\ttarget\tsite\thost\tkind"]
    lines += ["\t".join((row_["name"], str(row_["copy"]), row_["target"], row_["site"], row_["host"], row_["opcode"])) for row_ in calls]
    files["route_call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["kind\tcopy\tlabel\toutcome\tedge_calls"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_))) for row_ in results]
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
