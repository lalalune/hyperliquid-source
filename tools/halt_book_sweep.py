#!/usr/bin/env python3
"""Pin the node #94 perp halt transition of one asset from ELF bytes.

`0x4cf0850` and `0x4cf0d10` take a packed asset, and on the first insert into a per-market asset set
they cancel the book, take the asset's entries out of a keyed queue, and hand the position rows to
the apply path. `0x4cf3550` and `0x4cf36a0` are the delay gate in front of them, `0x42f2400` and
`0x42f2bb0` are the queue sweep, and `0x4cf0530` is the way back out of the set. The real bytes run in a Python evaluator with only the edges
stubbed, and a separately written specification predicts every event and every record byte. Every
condition and immediate is then flipped to show the run can tell. No objdump or readelf output is
parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
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

GATES = (0x4CF3550, 0x4CF36A0)
HALTS = (0x4CF0850, 0x4CF0D10)
QUEUES = (0x42F2400, 0x42F2BB0)
UNHALT = 0x4CF0530
SET_REMOVE = 0x4942D10
BOOK_SWEEPS = (0x4307E60, 0x4307860)
FINISHES = (0x4329870, 0x432A100)
USER_CANCELS = (0x4303650, 0x4303DB0)
DISPATCHERS = (0x4CAA870, 0x4CB3200)
DISPATCH_TABLES = (0x711064, 0x711244)
DISPATCH_FIELD = 0x34 - 0x12
SET_INSERT = 0x493AC40
RECORD = 0x3987CB0
APPLY = 0x4CD84F0
DROP_ERROR = 0x3379490
POP = 0x44C0FE0
PUSH = 0x44C1900
REMOVE_ORDER = 0x49432C0
REMOVE_USER = 0x4944610
DRAIN_MAP = 0x494B020
CONVERT = 0x46CA710
DROP_FAILED = 0x4344430
ROW_PRODUCER = 0x36FF770
DATE_HELPER = 0x1459CA0
STATUS_TABLE = 0x7038DC
STATUS_FN = 0x4A9A1A0
SLOT_ROWS = 0x5774970
SLOT_DATE = 0x576EFB8
SLOT_FREE = 0x576E010
SLOT_PANIC = 0x576E470
SLOT_UNWRAP = 0x576E048
SLOT_ONCE = 0x576E8B8
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_GROW_RETAINED = 0x57747D8
SLOT_GROW_OUT = 0x5773D58
SLOT_VOTE_RESOLVE = 0x5773950
ONCE_STATE = 0x577AB98
ONCE_VALUE = 0x577AB80
ONCE_VTABLE = 0x5669F68
ONCE_LOCATION = 0x5669F50
DELAY_TABLE = 0x207AF0
LOCATION_MARKET = 0x56E9AF8
LOCATION_COLLECTION = 0x56E9B28
LOCATION_BOOK = 0x5742338
LOCATION_GATE = 0x56E9AE0
ERROR_WORD = 0x141
UNWRAP_MESSAGE = 0x2B
STATUS_OK = 0x186
STATUS_TOO_SOON = 0x79
STATUS_BLOCKED = 0x162
APPLY_KIND = 0x30003
DELISTED_STATUS = 0xC
DIVISOR = 10000
QUEUE_ENTRY = 0x28
OUT_STRIDE = 0x278
ROW_STRIDE = 0x238
MARKET_STRIDE = 0x2F0
COLLECTION_STRIDE = 0x138
BOOK_STRIDE = 0xD8
MARKET_SET = 0x270
MARKET_STATUS = 0x230
MARKET_TIME = 0x218
OUTER_TIME = 0x60
OUTER_TAG = 0
OUTER_FIRST = 8
OUTER_SECOND = 0x28
RECORD_TAG = 4
RECORD_NONE = 0x8000000000000001
FAILED_WORD = 0xCE
NONE_BYTE = 2

# Per copy: the field set read from the outer object.
FIELD_SETS = (
    {"markets": 0x5C0, "market_count": 0x5C8, "collections": 0x3370, "collection_count": 0x3378, "byte": 0x8F2},
    {"markets": 0x1040, "market_count": 0x1048, "collections": 0x3DF0, "collection_count": 0x3DF8, "byte": 0x1372},
)

# B-tree node shapes: keys, key stride, parent, parent index, length, edges, values, value stride.
SET_NODE = dict(keys=8, stride=8, parent=0, index=0x60, length=0x62, edges=0x68, size=0x68 + 12 * 8)
USER_NODE = dict(keys=0x110, stride=20, parent=0, index=0x1EC, length=0x1EE, edges=0x1F0, size=0x1F0 + 12 * 8,
                 values=8, value_stride=0x18)
ORDER_NODE = dict(keys=0x428, stride=8, parent=0x420, index=0x480, length=0x482, edges=0x488, size=0x488 + 12 * 8,
                  values=0, value_stride=0x60)

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
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
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
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
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


# ---- cases and specification ----

def lcg(variant):
    """A small fixed generator so the sampled tiers are the same on every run."""
    state = (variant * 0x9E3779B97F4A7C15 + 0x1234567) & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 16


def user_id(number):
    return bytes((number * 37 + index * 11 + 5) & 0xFF for index in range(20))


class GateCase:
    def __init__(self, label, asset=20003, markets=3, status=0, byte=0, deadline=(5, 6, 7), now=(5, 6, 7)):
        self.label, self.asset, self.markets, self.status, self.byte = label, asset, markets, status, byte
        self.deadline, self.now = deadline, now


class HaltCase:
    def __init__(self, label, asset=20003, markets=3, collections=3, books=5, keys=(), width=11, tag=1, byte=7, once=0, once_late=0,
                 rows=(4, 2), shrink=None, book_vector=(0, 8, 0), queue_vector=None, apply_vector=(0, 8, 0)):
        self.label, self.asset, self.markets, self.collections, self.books = label, asset, markets, collections, books
        self.keys, self.width, self.tag, self.byte, self.once, self.once_late = tuple(sorted(keys)), width, tag, byte, once, once_late
        self.rows, self.shrink, self.book_vector, self.queue_vector, self.apply_vector = rows, shrink, book_vector, queue_vector, apply_vector


class Entry:
    """One queue record. `order` is the key, `asset` the value word held in the user's order map."""

    def __init__(self, order, user, tag=9, pad=0x1122334455667788, gone=False):
        self.order, self.user, self.tag, self.pad, self.gone = order, user, tag, pad, gone

    def bytes(self):
        return struct.pack("<QIQ", self.order, self.tag, self.pad) + user_id(self.user)


class UnhaltCase:
    def __init__(self, label, asset=20003, markets=3, status=0, present=1, once=0):
        self.label, self.asset, self.markets, self.status, self.present, self.once = label, asset, markets, status, present, once


class QueueCase:
    def __init__(self, label, asset=20003, entries=(), users=None, markets=3, out_capacity=2, width=11, order_width=11, drain=1):
        self.label, self.asset, self.entries, self.markets = label, asset, tuple(entries), markets
        self.users = users or {}
        self.out_capacity, self.width, self.order_width, self.drain = out_capacity, width, order_width, drain


def spec_gate(copy, case):
    fields = FIELD_SETS[copy]
    dex = case.asset // DIVISOR
    if dex >= case.markets:
        return {"events": [], "stop": ("unwrap", LOCATION_GATE, ERROR_WORD, UNWRAP_MESSAGE)}
    events = [("drop", ERROR_WORD)]
    word = STATUS_OK
    if case.status != 3:
        delay = 300.0 if case.byte in (1, 2) else 3600.0
        events.append(("date", time_bytes(), to_bits(delay)))
        first = signed32(case.deadline[0]), case.deadline[1], case.deadline[2]
        second = signed32(case.now[0]), case.now[1], case.now[2]
        if first > second:
            word = STATUS_TOO_SOON
    if word == STATUS_OK:
        events.append(("halt", OUTER, case.asset))
    return {"events": events, "word": word}


def spec_unhalt(case):
    dex = case.asset // DIVISOR
    if dex >= case.markets:
        return {"events": [], "stop": ("unwrap", LOCATION_MARKET, ERROR_WORD, UNWRAP_MESSAGE)}
    events = [("drop", ERROR_WORD)]
    if case.status not in (0, 3):
        return {"events": events, "word": STATUS_BLOCKED}
    events.append(("remove asset", MARKETS + dex * MARKET_STRIDE + MARKET_SET, case.asset))
    if case.present and case.once:
        events.append(("once", ONCE_STATE, 1, ONCE_VTABLE, ONCE_LOCATION, ONCE_VALUE))
    return {"events": events, "word": STATUS_OK}


def signed32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


def time_bytes():
    return tuple(range(0x40, 0x4C))


def spec_halt(copy, case):
    dex = case.asset // DIVISOR
    local = case.asset % DIVISOR
    events = []
    if dex >= case.markets:
        return {"events": events, "stop": ("unwrap", LOCATION_MARKET, ERROR_WORD, UNWRAP_MESSAGE)}
    events.append(("drop", ERROR_WORD))
    market = MARKETS + dex * MARKET_STRIDE
    forced = ("once", ONCE_STATE, 1, ONCE_VTABLE, ONCE_LOCATION, ONCE_VALUE)
    if case.asset in case.keys:
        return {"events": events + [forced] * bool(case.once)}
    events.append(("insert", market + MARKET_SET, case.asset))
    if dex >= case.collections:
        return {"events": events, "stop": ("unwrap", LOCATION_COLLECTION, ERROR_WORD, UNWRAP_MESSAGE)}
    events.append(("drop", ERROR_WORD))
    collection = COLLECTIONS + dex * COLLECTION_STRIDE
    if local >= case.books:
        return {"events": events, "stop": ("panic", LOCATION_BOOK)}
    events.append(("book", BOOKS + local * BOOK_STRIDE, OUTER, (0, 8, 0)))
    events.append(("queue", collection + 0x18, case.asset, OUTER, case.book_vector))
    final = case.queue_vector or case.book_vector
    events.append(("finish", final, dex, OUTER))
    events += [forced] * bool(case.once)
    state = case.once_late if case.once else 0
    if case.shrink is not None and dex >= case.shrink:
        return {"events": events, "stop": ("unwrap", LOCATION_MARKET, ERROR_WORD, UNWRAP_MESSAGE)}
    events.append(("drop", ERROR_WORD))
    events.append(("rows", market, case.asset, OUTER))
    fields = FIELD_SETS[copy]
    record = bytes(range(0x60, 0x80)) if case.tag == 1 else bytes(32)
    if case.tag == 1:
        events.append(("record", case.byte, OUTER_B, OUTER_A, 0))
    events.append(("apply", market, ROWS, case.rows[1], (1,) + tuple(record), 0, APPLY_KIND))
    events.append(("finish", case.apply_vector, dex, OUTER))
    if case.rows[0]:
        events.append(("free", ROWS, case.rows[0] * ROW_STRIDE, 0))
    return {"events": events + [forced] * bool(state)}


def spec_queue(copy, case):
    dex = case.asset // DIVISOR
    market = MARKETS + dex * MARKET_STRIDE
    events = []
    retained = []
    capacity = 0
    out_capacity = case.out_capacity
    output = []
    counts = {user: len(orders) for user, orders in case.users.items()}
    for entry in case.entries:
        events.append(("pop", QUEUE))
        orders = case.users.get(entry.user, {})
        value = orders.get(entry.order)
        if value != case.asset:
            if len(retained) == capacity:
                events.append(("grow retained", capacity))
                capacity = max(capacity * 2, 4)
            retained.append(entry)
            continue
        events.append(("remove order", entry.order))
        if entry.gone:
            events.append(("drop failed", FAILED_WORD))
            continue
        counts[entry.user] -= 1
        if counts[entry.user] == 0:
            events.append(("remove user", user_id(entry.user)))
            for step in range(case.drain):
                events.append(("drain", step))
        if dex >= case.markets:
            return {"events": events, "stop": ("unwrap", LOCATION_GATE, ERROR_WORD, UNWRAP_MESSAGE)}
        events.append(("drop", ERROR_WORD))
        events.append(("convert", market, order_value(entry.order)))
        if len(output) == out_capacity:
            events.append(("grow out", out_capacity))
            out_capacity = max(out_capacity * 2, 4)
        output.append(entry)
        events.append(("copy", OUT_STRIDE))
    events.append(("pop", QUEUE))
    for entry in retained:
        events.append(("push", entry.bytes()))
    if capacity:
        events.append(("free", RETAINED, capacity * QUEUE_ENTRY, 0))
    return {"events": events, "records": [spec_record(entry) for entry in output], "out_capacity": out_capacity}


def order_value(order):
    """The 0x60-byte value the stub returns for a removed order: a word then a fixed pattern."""
    body = bytearray(struct.pack("<Q", order) + bytes((order + index * 7 + 1) & 0xFF for index in range(0x58)))
    body[0x22] = 1
    return bytes(body)


def converted(order):
    return bytes((order + index * 3) & 0xFF for index in range(0x58))


def spec_record(entry):
    """Defined bytes of one 0x278 output record, by offset."""
    return [(0, struct.pack("<Q", RECORD_TAG)), (8, converted(entry.order)), (0x60, struct.pack("<Q", RECORD_NONE)),
            (0x78, struct.pack("<Q", entry.order)), (0x80, bytes(time_bytes())), (0x8C, user_id(entry.user))]


def gate_cases():
    rows = []

    def add(label, **options):
        rows.append(GateCase(label, **options))

    add("dex equals market count", asset=30000)
    add("dex past market count", asset=MASK[8])
    add("last market, last local", asset=29999)
    add("first asset", asset=0, markets=1)
    add("status 3 skips the date", status=3, deadline=(9, 9, 9), now=(1, 1, 1))
    for status in (0, 1, 2, 4, 255):
        add("status %d equal" % status, status=status)
    for byte in (0, 1, 2, 3, 4, 255):
        add("byte %d too soon" % byte, byte=byte, deadline=(5, 6, 8))
        add("byte %d due" % byte, byte=byte, deadline=(5, 6, 6))
    triples = [(0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1), (0xFFFFFFFF, 0, 0), (0x7FFFFFFF, 0, 0), (0x80000000, 0, 0),
               (0, 0x80000000, 0), (0, 0, 0x80000000), (0, 0xFFFFFFFF, 0), (0, 0, 0xFFFFFFFF), (2, 1, 1), (1, 2, 2), (1, 1, 2)]
    for first in triples:
        for second in triples:
            add("%r against %r" % (first, second), deadline=first, now=second)
    return rows


def unhalt_cases():
    rows = []
    for status in (0, 1, 2, 3, 4, 255):
        for present in (0, 1):
            for once in (0, 1):
                rows.append(UnhaltCase("status %d present %d once %d" % (status, present, once), status=status, present=present, once=once))
    for asset, markets in ((0, 1), (9999, 1), (10000, 1), (10000, 2), (19999, 2), (20000, 2), (20000, 3), (MASK[8], 3)):
        rows.append(UnhaltCase("asset %d of %d markets" % (asset, markets), asset=asset, markets=markets))
    return rows


def halt_cases():
    rows = []

    def add(label, **options):
        rows.append(HaltCase(label, **options))

    add("plain first insert")
    add("empty set, no record", tag=0)
    add("tag 2 takes the zero record", tag=2)
    add("asset 0", asset=0, markets=1, collections=1, books=1, keys=(5,))
    add("last book", asset=20004)
    add("book equals length", asset=20005)
    add("book past length", asset=29999)
    add("no books", asset=20000, books=0)
    add("dex equals market count", asset=30000)
    add("dex past market count", asset=MASK[8])
    add("collection missing after the insert", asset=20000, collections=2)
    add("collection count zero", asset=0, collections=0)
    add("rows empty capacity", rows=(0, 0))
    add("rows capacity 1", rows=(1, 1))
    add("once forced once", once=1)
    add("once state stays set", once=1, once_late=1)
    add("present with once", keys=(20003,), once=1)
    add("shrink after the sweep", shrink=2)
    add("shrink after the sweep, once on", shrink=2, once=1)
    add("vectors carry items", book_vector=(4, 0x70000, 2), queue_vector=(8, 0x71000, 5), apply_vector=(16, 0x72000, 3))
    for byte in (0, 1, 2, 3, 255):
        add("record byte %d" % byte, byte=byte)
    trees = (
        ("single key equal", (20003,), 11),
        ("single key below", (20002,), 11),
        ("single key above", (20004,), 11),
        ("full leaf holding it first", tuple(range(20003, 20014)), 11),
        ("full leaf holding it last", tuple(range(19993, 20004)), 11),
        ("full leaf without it", tuple(range(30000, 30011)), 11),
        ("two levels on an edge", tuple(range(19980, 20030, 3)), 3),
        ("two levels off an edge", tuple(range(19981, 20030, 3)), 3),
        ("three levels", tuple(range(19900, 20100, 2)), 2),
        ("three levels, asset odd miss", tuple(range(19900, 20100, 2)), 2),
        ("high keys above 2^63", tuple((1 << 63) + index for index in range(5)), 11),
    )
    for label, keys, width in trees:
        add(label, keys=keys, width=width)
        add(label + ", absent later", keys=keys, width=width, asset=20005)
    random = lcg(3)
    for index in range(60):
        size = next(random) % 30
        keys = sorted({20000 + next(random) % 12 for _ in range(size)})
        add("random %d" % index, keys=keys, width=2 + next(random) % 4, asset=20000 + next(random) % 5, tag=next(random) % 2,
            once=next(random) % 2, once_late=next(random) % 2, rows=(next(random) % 3, next(random) % 3))
    return rows


def queue_cases():
    rows = []

    def add(label, **options):
        rows.append(QueueCase(label, **options))

    mine = 20003
    other = 20004
    add("empty queue")
    add("empty maps", entries=[Entry(1, 1)])
    add("user missing", entries=[Entry(1, 2)], users={1: {1: mine}})
    add("order missing", entries=[Entry(7, 1)], users={1: {1: mine}})
    add("other asset stays", entries=[Entry(1, 1)], users={1: {1: other}})
    add("one match empties the user", entries=[Entry(1, 1)], users={1: {1: mine}})
    add("one match leaves the user", entries=[Entry(1, 1)], users={1: {1: mine, 2: other}})
    add("two matches, same user", entries=[Entry(1, 1), Entry(2, 1)], users={1: {1: mine, 2: mine}})
    add("mixed order", entries=[Entry(3, 2), Entry(1, 1), Entry(2, 1), Entry(9, 3), Entry(4, 2)],
        users={1: {1: mine, 2: other}, 2: {3: mine, 4: other}})
    add("gone at removal", entries=[Entry(1, 1, gone=True)], users={1: {1: mine}})
    add("gone among others", entries=[Entry(2, 1), Entry(1, 1, gone=True), Entry(3, 1)], users={1: {1: mine, 2: mine, 3: other}})
    add("key equal to the asset", entries=[Entry(mine, 1)], users={1: {mine: mine}})
    add("queue word differs, map decides", entries=[Entry(1, 1, tag=1), Entry(2, 1, tag=0xFFFFFFFF, pad=0)], users={1: {1: mine, 2: other}})
    add("zero output capacity", out_capacity=0, entries=[Entry(1, 1)], users={1: {1: mine}})
    add("output grows twice", out_capacity=1, entries=[Entry(index, 1) for index in range(1, 7)],
        users={1: {index: mine for index in range(1, 7)}})
    add("retained grows twice", entries=[Entry(index, 1) for index in range(1, 10)], users={1: {index: other for index in range(1, 10)}})
    add("drain three", drain=3, entries=[Entry(1, 1)], users={1: {1: mine}})
    add("drain none", drain=0, entries=[Entry(1, 1)], users={1: {1: mine}})
    add("order below the only key", entries=[Entry(1, 1)], users={1: {5: mine}})
    add("order above the only key", entries=[Entry(9, 1)], users={1: {5: mine}})
    add("user below the only key", entries=[Entry(1, 7)], users={1: {1: mine}})
    add("asset at a multiple", asset=20000, entries=[Entry(1, 1)], users={1: {1: 20000}})
    add("asset just under a multiple", asset=19999, entries=[Entry(1, 1)], users={1: {1: 19999}})
    add("market missing, no match", markets=2, entries=[Entry(1, 1)], users={1: {1: other}})
    add("market missing at the match", markets=2, entries=[Entry(1, 1)], users={1: {1: mine}})
    add("market missing after a retained row", markets=2, entries=[Entry(5, 1), Entry(1, 1)], users={1: {1: mine}})
    many = {user: {user * 100 + order: (mine if order % 2 else other) for order in range(13)} for user in range(1, 30)}
    add("deep user tree", width=2, order_width=11, entries=[Entry(user * 100 + 1, user) for user in (1, 5, 13, 29)], users=many)
    add("deep user tree, last key", width=3, order_width=2, entries=[Entry(user * 100 + 12, user) for user in (1, 7, 29)], users=many)
    add("deep order tree", width=11, order_width=2, entries=[Entry(100 + order, 1) for order in range(13)], users={1: many[1]})
    add("deep trees, misses", width=2, order_width=2, entries=[Entry(99, 1), Entry(113, 1), Entry(2900, 30), Entry(100, 0)], users=many)
    for index in range(3):
        add("full nodes %d" % index, width=11, order_width=11, entries=[Entry(1 + index, 1 + index * 5)],
            users={user: {order: mine for order in range(1, 12)} for user in range(1, 12)})
    random = lcg(5)
    for index in range(50):
        users = {}
        for user in range(1, 2 + next(random) % 8):
            users[user] = {order: (mine if next(random) % 2 else other) for order in sorted({next(random) % 20 + 1 for _ in range(1 + next(random) % 9)})}
        entries, used = [], set()
        for _ in range(next(random) % 14):
            user, order = 1 + next(random) % 9, next(random) % 21 + 1
            if (user, order) in used:
                continue
            used.add((user, order))
            entries.append(Entry(order, user, gone=next(random) % 7 == 0))
        add("random %d" % index, entries=entries, users=users, width=2 + next(random) % 4, order_width=2 + next(random) % 4,
            out_capacity=next(random) % 3, drain=next(random) % 3)
    return rows


# ---- harness ----

OUTER = HEAP_BASE + 0x1000
OUTER_A = 0x1111222233334444
OUTER_B = 0x5555666677778888
MARKETS = HEAP_BASE + 0x8000
COLLECTIONS = HEAP_BASE + 0xC000
BOOKS = 0x650000000
ROWS = 0x660000000
QUEUE = HEAP_BASE + 0xE000
RESULT = HEAP_BASE + 0xE100
VECTOR = HEAP_BASE + 0xE200
RETAINED = HEAP_BASE + 0x10000
OUTPUT = HEAP_BASE + 0x20000
NODES = HEAP_BASE + 0x40000
LEAF_EDGE = 0x4242424242424200


def tree_height(count, width):
    """Smallest height whose full tree of `width` keys per node holds `count` keys."""
    height = 0
    while (width + 1) ** (height + 1) - 1 < count:
        height += 1
    return height


def chunks(keys, width, height):
    """Split sorted keys into (separators, children) so that all leaves end at the same depth."""
    if height == 0:
        return keys, None
    below = (width + 1) ** height - 1
    count = 2
    while count * below + count - 1 < len(keys):
        count += 1
    share = (len(keys) - (count - 1)) / count
    separators, children, start = [], [], 0
    for index in range(1, count):
        at = int(share * index) + index - 1
        children.append(keys[start:at])
        separators.append(keys[at])
        start = at + 1
    children.append(keys[start:])
    return separators, children


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        slots = (SLOT_ROWS, SLOT_DATE, SLOT_FREE, SLOT_PANIC, SLOT_UNWRAP, SLOT_ONCE, SLOT_GROW_RETAINED, SLOT_GROW_OUT)
        for slot in slots:
            machine.memory.statics[slot] = relative[slot]
        machine.memory.statics[SLOT_MEMCMP] = FAKE_MEMCMP
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCMP + 0x10
        machine.memory.statics[ONCE_STATE] = 0
        machine.slots = {relative[SLOT_ROWS]: self.on_rows, relative[SLOT_DATE]: self.on_date, relative[SLOT_FREE]: self.on_free,
                         relative[SLOT_PANIC]: self.on_panic, relative[SLOT_UNWRAP]: self.on_unwrap, relative[SLOT_ONCE]: self.on_once,
                         relative[SLOT_GROW_RETAINED]: self.on_grow_retained, relative[SLOT_GROW_OUT]: self.on_grow_out,
                         FAKE_MEMCMP: self.on_memcmp, FAKE_MEMCMP + 0x10: self.on_memcpy}
        machine.calls = {DROP_ERROR: self.on_drop, SET_INSERT: self.on_insert, RECORD: self.on_record, APPLY: self.on_apply, POP: self.on_pop,
                         PUSH: self.on_push, REMOVE_ORDER: self.on_remove_order, REMOVE_USER: self.on_remove_user, DRAIN_MAP: self.on_drain,
                         CONVERT: self.on_convert, DROP_FAILED: self.on_drop_failed, SET_REMOVE: self.on_remove_asset}
        for start in BOOK_SWEEPS:
            machine.calls[start] = self.on_book
        for start in QUEUES:
            machine.calls[start] = self.on_queue
        for start in FINISHES:
            machine.calls[start] = self.on_finish
        for start in HALTS:
            machine.calls[start] = self.on_halt
        self.used = HEAP_SIZE
        self.brk = NODES

    def reset(self):
        self.machine.memory.reset(self.used)
        self.machine.memory.statics[ONCE_STATE] = 0
        self.used = NODES - HEAP_BASE
        self.events = []
        self.brk = NODES

    def carve(self, size):
        at = self.brk
        self.brk += (size + 15) & ~15
        self.used = max(self.used, self.brk - HEAP_BASE)
        return at

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def build_tree(self, at, keys, shape, width, write_key, write_value=None):
        """Lay real nodes for sorted keys at map header `at`: root, height, length."""
        keys = list(keys)
        if not keys:
            self.word(at, 0)
            self.word(at + 8, 0)
            self.word(at + 0x10, 0)
            return

        def make(items, parent, slot, level):
            node = self.carve(shape["size"])
            self.machine.memory.put_bytes(node, bytes(shape["size"]))
            # A real leaf ends before the edges, so a read of one must not look like a null root.
            self.machine.memory.put_bytes(node + shape["edges"], struct.pack("<Q", LEAF_EDGE) * 12)
            self.word(node + shape["parent"], parent)
            self.word(node + shape["index"], slot, 2)
            separators, children = chunks(items, width, level)
            self.word(node + shape["length"], len(separators), 2)
            for index, key in enumerate(separators):
                write_key(node + shape["keys"] + index * shape["stride"], key)
                if write_value:
                    write_value(node + shape["values"] + index * shape["value_stride"], key)
            for index, child in enumerate(children or ()):
                self.word(node + shape["edges"] + index * 8, make(child, node, index, level - 1))
            return node

        height = tree_height(len(keys), width)
        root = make(keys, 0, 0, height)
        self.word(at, root)
        self.word(at + 8, height)
        self.word(at + 0x10, len(keys))

    def install_outer(self, copy, markets, collections, books, byte=0):
        fields = FIELD_SETS[copy]
        self.word(OUTER + fields["markets"], MARKETS)
        self.word(OUTER + fields["market_count"], markets)
        self.word(OUTER + fields["collections"], COLLECTIONS)
        self.word(OUTER + fields["collection_count"], collections)
        self.word(OUTER + fields["byte"], byte, 1)
        self.machine.memory.put_bytes(OUTER + OUTER_TIME, bytes(time_bytes()))
        self.word(OUTER + OUTER_FIRST, OUTER_A)
        self.word(OUTER + OUTER_SECOND, OUTER_B)
        for index in range(min(collections, 8)):
            at = COLLECTIONS + index * COLLECTION_STRIDE
            self.word(at + 8, BOOKS)
            self.word(at + 0x10, books)

    # -- runs --

    def run_gate(self, copy, case):
        self.reset()
        self.case = case
        self.copy = copy
        self.install_outer(copy, case.markets, 0, 0, case.byte)
        dex = case.asset // DIVISOR
        if dex < case.markets:
            market = MARKETS + dex * MARKET_STRIDE
            self.word(market + MARKET_STATUS, case.status, 1)
            self.machine.memory.put_bytes(market + MARKET_TIME, bytes(time_bytes()))
        for index, value in enumerate(case.now):
            self.word(OUTER + OUTER_TIME + index * 4, value, 4)
        machine = self.machine
        machine.real = frozenset()
        self.word(RESULT, 0x7777, 2)
        try:
            machine.run(GATES[copy], {RDI: RESULT, RSI: OUTER, RDX: case.asset})
        except Panicked as stop:
            return {"events": self.events, "stop": stop.args[0]}
        return {"events": self.events, "word": machine.memory.read(RESULT, 2)}

    def run_halt(self, copy, case):
        self.reset()
        self.case = case
        self.copy = copy
        self.install_outer(copy, case.markets, case.collections, case.books, case.byte)
        self.word(OUTER + OUTER_TAG, case.tag, 4)
        dex = case.asset // DIVISOR
        self.dex = dex
        if dex < min(case.markets, 8):
            self.build_tree(MARKETS + dex * MARKET_STRIDE + MARKET_SET, case.keys, SET_NODE, case.width,
                            lambda at, key: self.word(at, key))
        machine = self.machine
        machine.memory.statics[ONCE_STATE] = case.once
        machine.real = frozenset()
        try:
            machine.run(HALTS[copy], {RDI: OUTER, RSI: case.asset})
        except Panicked as stop:
            return {"events": self.events, "stop": stop.args[0]}
        return {"events": self.events}

    def run_unhalt(self, case):
        self.reset()
        self.case = case
        dex = case.asset // DIVISOR
        if dex < case.markets:
            self.word(MARKETS + dex * MARKET_STRIDE + MARKET_STATUS, case.status, 1)
        machine = self.machine
        machine.memory.statics[ONCE_STATE] = case.once
        machine.real = frozenset()
        self.word(RESULT, 0x7777, 2)
        try:
            machine.run(UNHALT, {RDI: RESULT, RSI: MARKETS, RDX: case.markets, RCX: case.asset})
        except Panicked as stop:
            return {"events": self.events, "stop": stop.args[0]}
        return {"events": self.events, "word": machine.memory.read(RESULT, 2)}

    def run_queue(self, copy, case):
        self.reset()
        self.case = case
        self.copy = copy
        self.install_outer(copy, case.markets, 0, 0)
        self.pending = list(case.entries)
        self.drain = 0
        self.word(VECTOR, case.out_capacity)
        self.word(VECTOR + 8, OUTPUT)
        self.word(VECTOR + 0x10, 0)
        self.grown = RETAINED

        def write_user(at, user):
            self.machine.memory.put_bytes(at, user_id(user))

        def write_orders(at, user):
            orders = case.users[user]

            def write_value(slot, order):
                self.word(slot, orders[order])

            self.build_tree(at, sorted(orders), ORDER_NODE, case.order_width, lambda key_at, key: self.word(key_at, key), write_value)

        ordered = sorted(case.users, key=user_id)
        self.build_tree(QUEUE + 0x18, ordered, dict(USER_NODE, compare=None), case.width,
                        lambda at, user: write_user(at, user), write_orders)
        machine = self.machine
        machine.real = frozenset()
        try:
            machine.run(QUEUES[copy], {RDI: QUEUE, RSI: case.asset, RDX: OUTER, RCX: VECTOR})
        except Panicked as stop:
            return {"events": self.events, "stop": stop.args[0]}
        memory = machine.memory
        count = memory.read(VECTOR + 0x10, 8)
        pointer = memory.read(VECTOR + 8, 8)
        records = []
        for index in range(count):
            at = pointer + index * OUT_STRIDE
            records.append([(offset, memory.bytes_at(at + offset, len(data))) for offset, data in spec_record_shape()])
        return {"events": self.events, "records": records, "out_capacity": memory.read(VECTOR, 8)}

    # -- edges --

    def on_drop(self, machine):
        self.events.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_insert(self, machine):
        self.events.append(("insert", machine.regs[RDI], machine.regs[RSI]))

    def on_remove_asset(self, machine):
        regs = machine.regs
        self.events.append(("remove asset", regs[RDI], machine.memory.read(regs[RSI], 8)))
        regs[RAX] = (POISON & ~0xFF) | self.case.present

    def on_date(self, machine):
        regs = machine.regs
        self.events.append(("date", tuple(machine.memory.bytes_at(regs[RSI], 12)), machine.xmm[0] & MASK[8]))
        for index, value in enumerate(self.case.deadline):
            self.word(regs[RDI] + index * 4, value, 4)

    def on_halt(self, machine):
        self.events.append(("halt", machine.regs[RDI], machine.regs[RSI]))

    def vector_at(self, at):
        memory = self.machine.memory
        return memory.read(at, 8), memory.read(at + 8, 8), memory.read(at + 16, 8)

    def on_book(self, machine):
        regs = machine.regs
        self.events.append(("book", regs[RDI], regs[RSI], self.vector_at(regs[RDX])))
        for index, value in enumerate(self.case.book_vector):
            self.word(regs[RDX] + index * 8, value)

    def on_queue(self, machine):
        regs = machine.regs
        self.events.append(("queue", regs[RDI], regs[RSI], regs[RDX], self.vector_at(regs[RCX])))
        for index, value in enumerate(self.case.queue_vector or self.case.book_vector):
            self.word(regs[RCX] + index * 8, value)

    def on_finish(self, machine):
        regs = machine.regs
        self.events.append(("finish", self.vector_at(regs[RDI]), regs[RSI], regs[RDX]))
        if self.case.shrink is not None and len([e for e in self.events if e[0] == "finish"]) == 1:
            self.word(OUTER + FIELD_SETS[self.copy]["market_count"], self.case.shrink)

    def on_once(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("once", regs[RDI], regs[RSI] & MASK[4], regs[RCX], regs[R8], memory.read(memory.read(regs[RDX], 8), 8)))
        memory.statics[ONCE_STATE] = getattr(self.case, "once_late", 0)

    def on_rows(self, machine):
        regs = machine.regs
        self.events.append(("rows", regs[RSI], regs[RDX], regs[RCX]))
        self.word(regs[RDI], self.case.rows[0])
        self.word(regs[RDI] + 8, ROWS)
        self.word(regs[RDI] + 0x10, self.case.rows[1])

    def on_record(self, machine):
        regs = machine.regs
        self.events.append(("record", regs[RSI] & 0xFF, regs[RDX], regs[RCX], regs[R8]))
        machine.memory.put_bytes(regs[RDI], bytes(range(0x60, 0x80)))

    def on_apply(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("apply", regs[RDI], regs[RSI], regs[RDX], tuple(memory.bytes_at(regs[RCX], 33)), regs[R8], regs[R9] & MASK[4]))
        vector = memory.read(regs[RSP] + 8, 8)
        if self.vector_at(vector) != (0, 8, 0):
            raise Halt("apply vector is not empty")
        for index, value in enumerate(self.case.apply_vector):
            self.word(vector + index * 8, value)

    def on_free(self, machine):
        regs = machine.regs
        self.events.append(("free", regs[RDI], regs[RSI], regs[RDX] & MASK[4]))

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_unwrap(self, machine):
        regs = machine.regs
        raise Panicked(("unwrap", regs[R8], machine.memory.read(regs[RDX], 2), regs[RSI]))

    def on_pop(self, machine):
        regs = machine.regs
        self.events.append(("pop", regs[RSI]))
        if self.pending:
            self.popped = self.pending.pop(0)
            machine.memory.put_bytes(regs[RDI], self.popped.bytes())
        else:
            self.word(regs[RDI] + 8, 0, 4)

    def on_push(self, machine):
        regs = machine.regs
        if regs[RDI] != QUEUE:
            raise Halt("push target")
        self.events.append(("push", machine.memory.bytes_at(regs[RSI], QUEUE_ENTRY)))

    def on_remove_order(self, machine):
        regs = machine.regs
        memory = machine.memory
        order = memory.read(regs[RDX], 8)
        self.events.append(("remove order", order))
        if self.popped.gone:
            self.word(regs[RDI] + 0x22, NONE_BYTE, 1)
            return
        memory.put_bytes(regs[RDI], order_value(order))
        self.word(regs[RSI] + 0x10, memory.read(regs[RSI] + 0x10, 8) - 1)

    def on_remove_user(self, machine):
        regs = machine.regs
        memory = machine.memory
        if regs[RSI] != QUEUE + 0x18:
            raise Halt("user map")
        self.events.append(("remove user", memory.bytes_at(regs[RDX], 20)))
        self.word(regs[RDI], 1)
        self.word(regs[RDI] + 8, 0x70000)
        self.word(regs[RDI] + 0x10, 2)
        self.word(regs[RDI] + 0x18, 0)
        self.drain = 0

    def on_drain(self, machine):
        regs = machine.regs
        memory = machine.memory
        expected = (1, 0, 0x70000, 2, 1, 0, 0x70000, 2)
        if tuple(memory.read(regs[RSI] + index * 8, 8) for index in range(8)) != expected or memory.read(regs[RSI] + 0x40, 8) != 0:
            raise Halt("drain iterator")
        if self.drain < self.case.drain:
            self.events.append(("drain", self.drain))
            self.drain += 1
            self.word(regs[RDI], 0x71000)
        else:
            self.word(regs[RDI], 0)

    def on_convert(self, machine):
        regs = machine.regs
        memory = machine.memory
        body = memory.bytes_at(regs[RSI], 0x60)
        self.events.append(("convert", regs[RDX], body))
        memory.put_bytes(regs[RDI], converted(struct.unpack_from("<Q", body)[0]))

    def on_drop_failed(self, machine):
        self.events.append(("drop failed", machine.memory.read(machine.regs[RDI], 2)))

    def on_memcmp(self, machine):
        regs = machine.regs
        memory = machine.memory
        if regs[RDX] != 20:
            raise Halt("memcmp length")
        left, right = memory.bytes_at(regs[RDI], 20), memory.bytes_at(regs[RSI], 20)
        result = 0
        for one, two in zip(left, right):
            if one != two:
                result = one - two
                break
        regs[RAX] = result & MASK[4]

    def on_memcpy(self, machine):
        regs = machine.regs
        self.events.append(("copy", regs[RDX]))
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])

    def on_grow_out(self, machine):
        at = machine.regs[RDI]
        if at != VECTOR:
            raise Halt("output vector")
        self.grow(at, OUT_STRIDE, "grow out", None)

    def on_grow_retained(self, machine):
        self.grow(machine.regs[RDI], QUEUE_ENTRY, "grow retained", self.grown)

    def grow(self, vector, stride, name, fresh):
        memory = self.machine.memory
        capacity, pointer = memory.read(vector, 8), memory.read(vector + 8, 8)
        if fresh is not None and capacity == 0 and pointer != 8:
            raise Halt("empty vector pointer")
        self.events.append((name, capacity))
        new = max(capacity * 2, 4)
        if fresh is None:
            fresh = pointer
        elif capacity:
            memory.copy(fresh, pointer, capacity * stride)
        self.word(vector, new)
        self.word(vector + 8, fresh)


def spec_record_shape():
    return spec_record(Entry(0, 0))


def compare(actual, expected, label):
    """Empty when the two outcomes agree, else the first difference."""
    if actual.get("stop") != expected.get("stop"):
        return "%s: stop %r, want %r" % (label, actual.get("stop"), expected.get("stop"))
    if actual["events"] != expected["events"]:
        for index, (left, right) in enumerate(zip(actual["events"], expected["events"])):
            if left != right:
                return "%s: event %d %r, want %r" % (label, index, left, right)
        return "%s: %d events, want %d" % (label, len(actual["events"]), len(expected["events"]))
    for key in ("word", "records", "out_capacity"):
        if actual.get(key) != expected.get(key):
            return "%s: %s %r, want %r" % (label, key, actual.get(key), expected.get(key))
    return ""


def guarded(run, *args):
    try:
        return run(*args), ""
    except Exception as stop:
        return None, "%s %s" % (type(stop).__name__, stop)


def compare_gate(harness, copy, case):
    actual, trouble = guarded(harness.run_gate, copy, case)
    return "%s: %s" % (case.label, trouble) if trouble else compare(actual, spec_gate(copy, case), case.label)


def compare_halt(harness, copy, case):
    actual, trouble = guarded(harness.run_halt, copy, case)
    return "%s: %s" % (case.label, trouble) if trouble else compare(actual, spec_halt(copy, case), case.label)


def compare_unhalt(harness, copy, case):
    actual, trouble = guarded(harness.run_unhalt, case)
    return "%s: %s" % (case.label, trouble) if trouble else compare(actual, spec_unhalt(case), case.label)


def compare_queue(harness, copy, case):
    actual, trouble = guarded(harness.run_queue, copy, case)
    return "%s: %s" % (case.label, trouble) if trouble else compare(actual, spec_queue(copy, case), case.label)


# ---- structure of the bytes ----

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
    """A row with its branch target made relative when the target stays inside the function."""
    target = row.target
    if target is not None and start <= target < end:
        target = "+%#x" % (target - start)
    elif target is not None:
        target = "%#x" % (target & MASK[8])
    return (row.op, row.width, row.cc, operand_text(row.a), operand_text(row.b), target)


def copy_differences(image, first, second):
    """Rows of two same-sized functions that differ after normalising code distance."""
    begin, end = image.exact_fde(first)
    other, other_end = image.exact_fde(second)
    if end - begin != other_end - other:
        raise EvidenceError("copies differ in size: %#x %#x" % (first, second))
    rows = decode_range(image, begin, end)
    others = decode_range(image, other, other_end)
    if [row.va - begin for row in rows] != [row.va - other for row in others]:
        raise EvidenceError("copies differ in instruction boundaries: %#x %#x" % (first, second))
    found = []
    for row, peer in zip(rows, others):
        left, right = row_shape(row, begin, end), row_shape(peer, other, other_end)
        if left != right:
            found.append({"first": first, "second": second, "offset": row.va - begin, "left": " ".join(map(str, left)),
                          "right": " ".join(map(str, right))})
    return found


def code_reader(image):
    def read(va, count):
        at = image.offset(va)
        return bytes(image.blob[at:at + count])
    return read


def stores_outside_stack(image, start):
    """Rows of one function whose destination is memory not addressed through rsp."""
    rows = decode_range(image, *image.exact_fde(start))
    found = []
    for row in rows:
        writes = row.op in ("mov", "movx", "movsd", "movq", "set", "add", "sub", "and", "or", "xor", "inc", "dec", "neg", "not")
        if writes and row.a and row.a[0] == "m" and row.a[1] != RSP:
            found.append(row.va)
    return found


def dispatch_arm(image, copy):
    """Follow table entry 0x22 of a dispatcher to the halt call: bool byte, status check, call."""
    table = DISPATCH_TABLES[copy]
    start, end = image.exact_fde(DISPATCHERS[copy])
    arm = table + struct.unpack_from("<i", image.blob, image.offset(table) + DISPATCH_FIELD * 4)[0]
    if not start <= arm < end:
        raise EvidenceError("dispatch arm outside its function: %#x" % arm)
    read = code_reader(image)
    first = decode(read, arm)
    second = decode(read, first.next)
    if (first.op, first.a, first.b[1], first.b[4], first.width) != ("mov", ("r", RSI), R15, 8, 4):
        raise EvidenceError("arm does not read the asset word at %#x" % arm)
    if (second.op, second.a, second.b[1], second.b[4], second.cc) != ("movzx", ("r", RBX), R15, 0xC, 1):
        raise EvidenceError("arm does not read the flag byte at %#x" % second.va)
    row, resolve = second, None
    for _ in range(16):
        row = decode(read, row.next)
        if row.op == "calli" and row.a == ("m", None, None, 1, SLOT_VOTE_RESOLVE, False):
            resolve = row.va
        if resolve and row.op == "cmp" and row.a[0] == "m" and row.b == ("i", 1):
            jump = decode(read, row.next)
            break
    else:
        raise EvidenceError("no resolve check in arm %#x" % arm)
    test = decode(read, jump.target)
    skip = decode(read, test.next)
    move = decode(read, skip.next)
    move2 = decode(read, move.next)
    call = decode(read, move2.next)
    if (test.op, test.a, test.b, test.width) != ("test", ("r", RBX), ("r", RBX), 1) or skip.op != "jcc" or skip.cc != 4:
        raise EvidenceError("no flag test at %#x" % jump.target)
    if (move.a, move.b, move2.a, move2.b) != (("r", RDI), ("r", R14), ("r", RSI), ("r", RCX)) or call.op != "call" or call.target != HALTS[copy]:
        raise EvidenceError("flag true does not call the halt at %#x" % call.va)
    return {"dispatcher": "%#x" % DISPATCHERS[copy], "table": "%#x" % table, "entry": DISPATCH_FIELD, "arm": "%#x" % arm, "flag_test": "%#x" % test.va,
            "flag_false_arm": "%#x" % skip.target, "halt_call": "%#x" % call.va}


def status_names(image, table=STATUS_TABLE):
    """Follow the jump table of the status serializer: byte value to (arm, name)."""
    start, end = image.exact_fde(STATUS_FN)
    base = image.offset(table)
    read = code_reader(image)
    rows = []
    while True:
        arm = table + struct.unpack_from("<i", image.blob, base + len(rows) * 4)[0]
        if not start <= arm < end:
            break
        row = decode(read, arm)
        if row.op != "lea" or row.a != ("r", RSI) or row.b[1] is not None:
            raise EvidenceError("status arm %#x does not load a name" % arm)
        text = row.b[4]
        following = decode(read, row.next)
        if following.op == "jmp":
            following = decode(read, following.target)
        if following.op != "mov" or following.a != ("r", RDX) or following.b[0] != "i":
            raise EvidenceError("status arm %#x does not load a length" % arm)
        rows.append(read(text, following.b[1]).decode("ascii"))
    return rows


def book_sweep_sites(image):
    """In each book sweep: the single user-cancel call, flag edx and reason r9d just before it."""
    names = status_names(image)
    found = []
    for copy, start in enumerate(BOOK_SWEEPS):
        rows = decode_range(image, *image.exact_fde(start))
        calls = [index for index, row in enumerate(rows) if row.op == "call" and row.target == USER_CANCELS[copy]]
        if len(calls) != 1:
            raise EvidenceError("expected one user cancel in %#x" % start)
        before = rows[calls[0] - 6:calls[0]]
        flag = [row for row in before if row.op == "mov" and row.a == ("r", RDX)]
        reason = [row for row in before if row.op == "mov" and row.a == ("r", R9)]
        if len(flag) != 1 or len(reason) != 1:
            raise EvidenceError("flag or reason not found before %#x" % rows[calls[0]].va)
        found.append({"sweep": "%#x" % start, "call": "%#x" % rows[calls[0]].va, "flag": flag[0].b[1], "reason": reason[0].b[1],
                      "status_name": names[reason[0].b[1]]})
    if any(row["reason"] != DELISTED_STATUS or row["flag"] != 1 for row in found):
        raise EvidenceError("book sweep reason or flag changed")
    return found


# Exact bytes at the callers that set the market status byte and walk the asset keys.
BYTE_PINS = (
    (0x49FF5E7, "c680300200" "0002", "status byte +0x230 set to 2 when the flag is set"),
    (0x49FEB67, "c680300200" "0002", "same store in the second copy"),
    (0x49FF6B7, "c680300200" "0000", "status byte +0x230 set to 0 when the flag is clear"),
    (0x49FEC37, "c680300200" "0000", "same store in the second copy"),
    (0x36FFD76, "4180bc243002000003", "row producer 0x36ff770 tests the status byte against 3 before the stamp"),
    (0x36FFD8C, "4189842420020000", "row producer stamps market +0x220 from outer +0x68"),
    (0x36FFD94, "488b014989842418", "row producer stamps market +0x218 from outer +0x60"),
)


def byte_pins(image):
    read = code_reader(image)
    rows = []
    for va, expected, meaning in BYTE_PINS:
        if read(va, len(expected) // 2).hex() != expected:
            raise EvidenceError("pin changed at %#x" % va)
        rows.append({"va": "%#x" % va, "bytes": expected, "meaning": meaning})
    return rows


# ---- mutation pass ----

MUTATED = (GATES[0], HALTS[0], QUEUES[0], UNHALT)
SECOND_WALK = "this height step is in the second user walk, which repeats a walk that just found the same key, so the height never runs out"
EQUIVALENT = {0x42F2732: SECOND_WALK, 0x42F2748: SECOND_WALK}
UNREACHED_GROUPS = ((0x4CF0C66, 0x4CF0D07, "unwind cleanup"), (0x42F2B40, 0x42F2BA6, "unwind cleanup"))


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


def run_mutants(image, seen):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    choices = {GATES[0]: (gate_cases(), compare_gate), HALTS[0]: (halt_cases(), compare_halt), QUEUES[0]: (queue_cases(), compare_queue),
               UNHALT: (unhalt_cases(), compare_unhalt)}
    for start in MUTATED:
        cases, check = choices[start]
        rows = decode_range(image, *image.exact_fde(start))
        for va, at, kind in mutation_targets(image, rows):
            if va not in seen:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            for index, case in enumerate(cases):
                failed = check(harness, 0, case)
                if failed:
                    cases.insert(0, cases.pop(index))
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed.split(":")[0] if failed else ""})
    return results


# ---- evidence ----

LOCATIONS = (LOCATION_MARKET, LOCATION_COLLECTION, LOCATION_BOOK, LOCATION_GATE)
RECORD_MAP = (
    (0x00, 8, "tag, always 4 on this path"),
    (0x08, 0x58, "output of 0x46ca710 over the removed 0x60-byte order value"),
    (0x60, 8, "constant 0x8000000000000001"),
    (0x78, 8, "queue key"),
    (0x80, 12, "outer +0x60 time, 8 then 4 bytes"),
    (0x8C, 20, "user, 20 bytes"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/books.rs:260-269", "claim": "0x4CF0850 ensure_main_perp_book_registered returns the book and marks it registered with reset caches",
     "bytes": "no return value is read by any of the three callers, no store leaves the stack, and the first insert runs the book cancel, queue sweep and position rows"},
    {"reference": "l1/books.rs:271-280", "claim": "0x4CF0D10 is the perp-dex mirror of that path",
     "bytes": "it is the same 1207 bytes with the second field set; which set belongs to which clearinghouse is not settled here"},
    {"reference": "l1/action/vote_global.rs:102", "claim": "HaltPerpTrading is raw 0x34, case 0x22, with asset and is_halted",
     "bytes": "table entry 0x22 reaches a word read at +8 and a byte read at +0xc; the byte being nonzero calls the two functions here, so this label agrees"},
    {"reference": "l1/books.rs:262", "claim": "registered_main_perp_assets only grows",
     "bytes": "the flag-clear arm of both dispatchers and of the two caller functions calls 0x4cf0530, which removes the asset from the same set and restores nothing else"},
)


def count_outcomes(evaluated):
    table = {}
    for name in evaluated:
        table[name] = table.get(name, 0) + 1
    return dict(sorted(table.items()))


def analyse(image, full=True):
    machine_seen = set()
    harness = Harness(image)
    gates, halts, queues, unhalts = gate_cases(), halt_cases(), queue_cases(), unhalt_cases()
    mismatches = []
    outcomes = []
    for copy in (0, 1):
        for case in gates:
            trouble = compare_gate(harness, copy, case)
            if trouble:
                mismatches.append(trouble)
            spec = spec_gate(copy, case)
            outcomes.append("gate panic" if "stop" in spec else "gate too soon" if spec["word"] == STATUS_TOO_SOON else "gate pass")
        for case in halts:
            trouble = compare_halt(harness, copy, case)
            if trouble:
                mismatches.append(trouble)
            spec = spec_halt(copy, case)
            if "stop" in spec:
                outcomes.append("halt panic")
            elif any(row[0] == "insert" for row in spec["events"]):
                outcomes.append("halt full path")
            else:
                outcomes.append("halt already present")
        for case in queues:
            trouble = compare_queue(harness, copy, case)
            if trouble:
                mismatches.append(trouble)
            spec = spec_queue(copy, case)
            events = [row[0] for row in spec["events"]]
            outcomes.append("queue panic" if "stop" in spec else "queue with removals" if "copy" in events else "queue without removals")
            queue_rows = (events.count("copy"), events.count("push"), events.count("drop failed"))
            harness.tally = tuple(map(sum, zip(getattr(harness, "tally", (0, 0, 0)), queue_rows)))
    for case in unhalts:
        trouble = compare_unhalt(harness, 0, case)
        if trouble:
            mismatches.append(trouble)
        spec = spec_unhalt(case)
        outcomes.append("unhalt panic" if "stop" in spec else "unhalt blocked" if spec["word"] == STATUS_BLOCKED else "unhalt ok")
    machine_seen = set(harness.machine.seen)
    steps = harness.machine.steps
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    functions = []
    for role, pair in (("delay gate", GATES), ("halt transition", HALTS), ("queue sweep", QUEUES), ("book sweep", BOOK_SWEEPS)):
        start, end = image.exact_fde(pair[0])
        other, other_end = image.exact_fde(pair[1])
        rows = decode_range(image, start, end)
        functions.append({"role": role, "first": "%#x" % start, "second": "%#x" % other, "size": end - start, "second_size": other_end - other,
                          "instructions": len(rows), "evaluated_here": role != "book sweep",
                          "instructions_stepped_first": sum(1 for row in rows if row.va in machine_seen),
                          "instructions_stepped_second": sum(1 for row in decode_range(image, other, other_end) if row.va in machine_seen)})
    start, end = image.exact_fde(UNHALT)
    rows = decode_range(image, start, end)
    functions.append({"role": "set removal", "first": "%#x" % start, "second": "", "size": end - start, "second_size": 0, "instructions": len(rows),
                      "evaluated_here": True, "instructions_stepped_first": sum(1 for row in rows if row.va in machine_seen), "instructions_stepped_second": 0})
    sites = direct_sites(image, GATES + HALTS + QUEUES + BOOK_SWEEPS + (UNHALT,))
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    differences = []
    for first, second in (GATES, HALTS, QUEUES):
        differences += copy_differences(image, first, second)
    results = run_mutants(image, machine_seen) if full else []
    tally = {key: sum(1 for row in results if row["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "field_sets": [{key: "%#x" % value for key, value in fields.items()} for fields in FIELD_SETS],
        "constants": {"divisor": DIVISOR, "market_stride": "%#x" % MARKET_STRIDE, "collection_stride": "%#x" % COLLECTION_STRIDE, "book_stride": "%#x" % BOOK_STRIDE,
                      "market_set": "%#x" % MARKET_SET, "market_status": "%#x" % MARKET_STATUS, "market_time": "%#x" % MARKET_TIME, "outer_time": "%#x" % OUTER_TIME,
                      "apply_kind": "%#x" % APPLY_KIND, "ok_word": "%#x" % STATUS_OK, "too_soon_word": "%#x" % STATUS_TOO_SOON, "blocked_word": "%#x" % STATUS_BLOCKED, "error_word": "%#x" % ERROR_WORD,
                      "queue_entry": "%#x" % QUEUE_ENTRY, "output_record": "%#x" % OUT_STRIDE, "row_stride": "%#x" % ROW_STRIDE, "record_tag": RECORD_TAG,
                      "record_none": "%#x" % RECORD_NONE, "failed_word": "%#x" % FAILED_WORD},
        "delay_seconds": {"index_0": struct.unpack_from("<d", image.blob, image.offset(DELAY_TABLE))[0],
                          "index_1": struct.unpack_from("<d", image.blob, image.offset(DELAY_TABLE + 8))[0], "table": "%#x" % DELAY_TABLE},
        "node_shapes": {name: {key: "%#x" % value for key, value in shape.items()} for name, shape in (("asset_set", SET_NODE), ("user_map", USER_NODE), ("order_map", ORDER_NODE))},
        "slots": {"%#x" % slot: "%#x" % relative[slot] for slot in (SLOT_ROWS, SLOT_DATE)},
        "slot_targets_are_fde_starts": [image.exact_fde(relative[slot])[0] == relative[slot] for slot in (SLOT_ROWS, SLOT_DATE)],
        "locations": [{"slot": "%#x" % slot, "path": image.location(slot, relative)[0], "line": image.location(slot, relative)[1],
                       "column": image.location(slot, relative)[2]} for slot in LOCATIONS],
        "unwrap_message": bytes(image.blob[image.offset(0x58C079):image.offset(0x58C079) + UNWRAP_MESSAGE]).decode("ascii"),
        "dispatch": [dispatch_arm(image, copy) for copy in (0, 1)],
        "book_sweep_sites": book_sweep_sites(image),
        "byte_pins": byte_pins(image),
        "stores_outside_stack": {"%#x" % start: ["%#x" % va for va in stores_outside_stack(image, start)] for start in GATES + HALTS + (UNHALT,)},
        "record_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in RECORD_MAP],
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"gate": len(gates), "halt": len(halts), "queue": len(queues), "unhalt": len(unhalts)},
        "outcomes": count_outcomes(outcomes),
        "queue_rows_two_copies": {"removed": harness.tally[0], "retained": harness.tally[1], "failed_removal": harness.tally[2]},
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_differences": differences, "_results": results,
    }


def reason_for(row):
    if row["result"] == "survived":
        return EQUIVALENT.get(row["va"], "")
    if row["result"] == "unreached":
        for low, high, reason in UNREACHED_GROUPS:
            if low <= row["va"] < high:
                return reason
    return ""


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    differences = evidence.pop("_differences")
    results = evidence.pop("_results")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["target\tsite\topcode\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%#x\t%#x\t%#x" % row for row in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["first\tsecond\toffset\tfirst_row\tsecond_row"]
    lines += ["%#x\t%#x\t%#x\t%s\t%s" % (row["first"], row["second"], row["offset"], row["left"], row["right"]) for row in differences]
    files["copy_differences.tsv"] = "\n".join(lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%#x\t%s\t%s\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"], row["by"], reason_for(row)) for row in results]
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
