#!/usr/bin/env python3
"""Pin what one node #94 TWAP slice result does to its schedule record, from ELF bytes.

After the slices of a block have run, two callers (`0x4ce0680`, `0x4ce0cc0`) hand each result to one
of four handlers (`0x42ed300` family). A handler either adds the fills to the record, or keeps the
record for the next step, or ends it with a text row. The error Display `0x3a008e0` names the
rejection classes that the 24-bit test in the handler sorts, and `0x47ef250` with `0x42e9000` turns
the row into JSON. The real bytes of all of these run in a Python evaluator with only the edges
stubbed, a separately written specification predicts every event and every byte, and every
condition, immediate and field offset is then flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard
library only.
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

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

PERP, SPOT = "perp", "spot"
# One row per handler: market field offsets are only read by the perp copies.
HANDLERS = (
    dict(start=0x42ED300, family=PERP, markets=0x1040, count=0x1048, advance=0x42EEF80, caller=0x4CE0680),
    dict(start=0x42EDCF0, family=PERP, markets=0x5C0, count=0x5C8, advance=0x42F0AF0, caller=0x4CE0CC0),
    dict(start=0x42ECA60, family=SPOT, advance=0x42F0240, caller=0x4CE0680),
    dict(start=0x42EE6E0, family=SPOT, advance=0x42EF990, caller=0x4CE0CC0),
)
# One row per caller: every field offset the two copies do not share.
CALLERS = (
    dict(start=0x4CE0680, perp=0x42ED300, spot=0x42ECA60, drain=0x42F2040, collect=0x48841A0, map_perp=0x47F61F0, map_spot=0x47F7EB0, flush_perp=0x432A100, flush_spot=0x432A990, limit=0x4524, height=0x4408, markets=0x1040, count=0x1048,
         books=0x3DE8, dex_ptr=0x3DF0, dex_count=0x3DF8, gate=0x4548, spot_tracker=0x3F60, spot_books=0x3E00),
    dict(start=0x4CE0CC0, perp=0x42EDCF0, spot=0x42EE6E0, drain=0x42F1C80, collect=0x487D820, map_perp=0x47F8B10, map_spot=0x47F8D50, flush_perp=0x4329870, flush_spot=0x432B440, limit=0x3AA4, height=0x3988, markets=0x5C0, count=0x5C8,
         books=0x3368, dex_ptr=0x3370, dex_count=0x3378, gate=0x3AC8, spot_tracker=0x34E0, spot_books=0x3380),
)
DISPLAY = 0x3A008E0
DISPLAY_TABLE = 0x5A572C
SLOT_DISPLAY = 0x57748E0
SLOT_FORMAT = 0x576E008
SLOT_F64_DISPLAY = 0x576EA18
STRING_VTABLE = 0x571CBD8
WRITE_STR_FIELD = 0x18
STATUS_TEXT = 0x4B011C0
DROP_ERROR = 0x3379490
DROP_FAILED = 0x4344430
SLOT_RECORDER = 0x5773190
SLOT_FREE = 0x576E010
SLOT_UNWRAP = 0x576E048
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAILED = 0x576DFB8
SLOT_GROW_PERP = 0x5773D58
SLOT_GROW_SPOT = 0x5773D50
LOCATION_MARKET = 0x56E9AE0
LOCATION_DEX = 0x56E9B28
LOCATION_STRING = 0x571CC08
LOCATION_SUM_FIRST = 0x572FF98
LOCATION_SUM_SECOND = 0x572FFB0
LOCATION_ADD_FIRST = 0x572AFA0
LOCATION_ADD_SECOND = 0x5736328
UNWRAP_TEXT = 0x58C079
UNWRAP_SIZE = 0x2B
STRING_TEXT = 0x6F0E7D
STRING_TEXT_SIZE = 0x37
STATUS_REJECTED = 0xC4
STATUS_OK = 0x186
TERMINAL_MASK = 0xFC02F9
NICHE_BIT = 1 << 63
NICHE_DEFAULT = 2
ERROR_WORD = 0x141
FAILED_WORD = 0xCE
DIVISOR = 10000
MARKET_STRIDE = 0x2F0
MARKET_ID_FIELD = 0x30
DEX_STRIDE = 0x138
DEX_TRACKER_FIELD = 0x18
TIME_FIELD = 0x60
HEIGHT_FIELD = 0x28
SPOT_CONVERT_FIELD = 0x90
RESULT_STRIDE = 0x88
RESULT_ASSET = 0x60
RESULT_OID = 0x68
RESULT_USER = 0x70
ROW_PREFIX = 0xA0
RECORD_SIZE = {PERP: 0x278, SPOT: 0x268}
FILL_STRIDE = {PERP: 0x238, SPOT: 0x228}
FILL_KEY = {PERP: 0x208, SPOT: 0x1F8}
EXECUTED = 0x28
SECOND = 0x30
RECORD_TAG = 4
FINISH_WORD = 0x8000000000000002
HALT_WORD = 0x8000000000000001
HALT_ROWS = (0x42F2400, 0x42F2BB0)
SERIAL_RECORD = 0x47EF250
SERIAL_FIELD = 0x4A87060
SERIAL_STATUS = 0x42E9000
SERIAL_TABLE = 0x6EEC64
STR_WRITE = 0x49C6940
VEC_GROW = 0x454F5D0
FIELD_TIME = 0x4A8F530
FIELD_ID = 0x4A78A30
FIELD_STATE = 0x4A7AD30
STRUCT_END = 0x4865440
SLOT_JSON_ERROR = 0x576EF80
SLOT_ASSERT = 0x576E108
FLUSH_TABLE = 0x6EED68
FLUSH_START = 0x432A100
ROW_BODY = 0x98
HISTORY_STATUS = 0x58
HISTORY_ID = 0x70
HISTORY_TIME = 0x78
STATUS_KEY = 0x6FD876
STREAM_NAME = 0x6FD940
STREAM_TEXT = b"node_twap_statuses"
UNREACHABLE_TEXT = 0x7040C0
UNREACHABLE_SIZE = 0x28
UNREACHABLE_LOCATION = 0x5737D60

CONVERT = {PERP: 0x46CA710, SPOT: 0x46CA2B0}
ORDER_REMOVE = {PERP: 0x49432C0, SPOT: 0x4944230}
USER_REMOVE = {PERP: 0x4944610, SPOT: 0x49463E0}
USER_DROP = {PERP: 0x494B020, SPOT: 0x49B7AD0}
USER_ENTRY = {PERP: 0x495B000, SPOT: 0x495A910}

# B-tree node shapes: keys, key stride, parent, parent index, length, edges, values, value stride.
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
FAKE_MEMCPY = 0x7E000010

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
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



def user_id(number):
    return bytes((number * 37 + index * 11 + 1) & 0xFF for index in range(20))


def ramp(size, start, step):
    return bytes((start + index * step) & 0xFF for index in range(size))


def order_body(oid, asset, executed, second):
    body = bytearray(ramp(0x60, oid * 5 + 3, 7))
    body[0:8] = struct.pack("<Q", asset)
    body[EXECUTED:EXECUTED + 8] = struct.pack("<Q", executed)
    body[SECOND:SECOND + 8] = struct.pack("<Q", second)
    return bytes(body)


def removed_value(oid):
    body = bytearray(ramp(0x60, oid + 1, 7))
    body[0x22] = 1
    return bytes(body)


def converted(oid):
    return ramp(0x58, oid, 3)


def status_text(status):
    return ("status %d" % status).encode()


# Text the Display gives for each tag. An int in place of a string is the template address,
# and the formatted tags are checked separately by their arguments.
LITERALS = {
    0: b"Price must be divisible by tick size.",
    3: b"Insufficient margin to place order.",
    4: b"Order would exceed maximum position size for current leverage. Reduce leverage to increase maximum position size.",
    5: b"Reduce only order would increase position.",
    7: b"Post only order would have immediately matched.",
    8: b"Order could not immediately match against any resting orders.",
    9: b"Invalid TP/SL price.",
    10: b"No liquidity available for market order.",
    11: b"Cannot increase position when open interest is at cap.",
    12: b"Cannot flip position when open interest is at cap.",
    14: b"Open interest is increasing too quickly. Try again in a few seconds.",
    15: b"Asset open interest is at cap.",
    16: b"Asset size-denominated open interest is at cap.",
    17: b"Perp DEX open interest is at cap.",
    18: b"Insufficient spot balance",
    19: b"Price too far from oracle",
    20: b"Outcome has been settled",
    21: b"Cross margin currently only supports reduce-only orders",
    22: b"Cross margin disabled",
    23: b"Halted",
}
F64_TEN = 0x20A8A8
F64_HUNDREDTH = 0x20A2F8
ARG_TEXT = 0x3C15530
ARG_PAIR = 0x37ECE50
TEMPLATES = {
    1: (0x1FC3FA, "Order must have minimum value of ${}."),
    2: (0x2023CA, "Order must have minimum value of {} {}."),
    6: (0x1F6C10, "Post only order would have immediately matched, bbo was {}\x40{}."),
    13: (0x1FE8A4, "Cannot place order {} more aggressive than oracle when open interest is at cap."),
}
TAG_COUNT = 24


def decode_template(blob, at):
    """Read one format template: a byte below 0x80 opens that many literal bytes, 0xc0 is a placeholder, 0 ends it."""
    pieces = []
    while True:
        byte = blob[at]
        if byte == 0:
            return "".join(pieces)
        if byte == 0xC0:
            pieces.append("{}")
            at += 1
        elif byte < 0x80:
            pieces.append(bytes(blob[at + 1:at + 1 + byte]).decode("ascii"))
            at += 1 + byte
        else:
            raise EvidenceError("unknown template byte %#x at %#x" % (byte, at))


def tag_of(word):
    return word ^ NICHE_BIT if word & NICHE_BIT else NICHE_DEFAULT


def terminal(tag):
    return bool(TERMINAL_MASK >> (tag & 63) & 1)


def display_events(tag, payload, relative):
    """The events and the text one tag gives through the Display, given where its payload sits."""
    if tag in LITERALS:
        return [("write", LITERALS[tag])], LITERALS[tag]
    template, text = TEMPLATES[tag]
    if tag == 1:
        args = ((F64_TEN, relative[SLOT_F64_DISPLAY]),)
    elif tag == 2:
        args = ((F64_TEN, relative[SLOT_F64_DISPLAY]), (payload, ARG_TEXT))
    elif tag == 6:
        args = ((payload + 8, ARG_PAIR), (payload + 0x10, ARG_PAIR))
    else:
        args = ((F64_HUNDREDTH, relative[SLOT_F64_DISPLAY]),)
    return [("format", template, args)], text.encode()


class Fill:
    def __init__(self, key, first, second):
        self.key, self.first, self.second = key, first, second


class ResultCase:
    def __init__(self, label, status=STATUS_OK, word=0, fills=(), oid=5, user=1, others=(), orders=(), asset=20003, executed=0, second=0, markets=3,
                 width=11, users_missing=False, order_missing=False, gone=False, user_value=True, user_root=True, drop_steps=1, capacity=4, filled=1,
                 write_fails=False):
        self.label, self.status, self.word, self.fills, self.oid, self.user = label, status, word, tuple(fills), oid, user
        self.others, self.orders, self.asset, self.executed, self.second = others, orders, asset, executed, second
        self.markets, self.width, self.users_missing, self.order_missing = markets, width, users_missing, order_missing
        self.gone, self.user_value, self.user_root, self.drop_steps = gone, user_value, user_root, drop_steps
        self.capacity, self.filled, self.write_fails = capacity, filled, write_fails


def saturated_sum(events, left, right, location):
    total = left + right
    if total > MASK[8]:
        events.append(("recorder", 0, location))
        return MASK[8]
    return total


def spec_fills(events, fills):
    """Sum the fills with the two gates, and give the two amounts the record takes."""
    if not fills:
        return 0, 0
    first, second = fills[0].first, fills[0].second
    for fill in fills[1:]:
        first = saturated_sum(events, fill.first, first, LOCATION_SUM_FIRST)
        second = saturated_sum(events, fill.second, second, LOCATION_SUM_SECOND)
        if fill.key != fills[0].key:
            return 0, 0
    if first == 0 or first > second:
        return 0, 0
    return first, second


def spec_result(row, case, relative):
    """Everything one handler call must do, from the rules alone."""
    family = row["family"]
    tracker, rows = TRACKER, ROWS
    events = []
    body = order_body(case.oid, case.asset, case.executed, case.second)
    outcome = {"events": events, "body": body, "count": case.filled}
    if case.users_missing:
        events.append(("entry", USER_ENTRY[family], user_id(case.user), tracker + 0x18, 0, 0, 0))
        outcome["body"] = None
        return outcome
    if case.order_missing:
        outcome["body"] = None
        return outcome
    advance = ("advance", row["advance"], tracker, user_id(case.user), case.oid, EXCHANGE, rows)
    if case.status == STATUS_OK:
        first, second = spec_fills(events, case.fills)
        executed = saturated_sum(events, case.executed, first, LOCATION_ADD_FIRST)
        progress = saturated_sum(events, case.second, second, LOCATION_ADD_SECOND)
        outcome["body"] = order_body(case.oid, case.asset, executed, progress)
        events.append(advance)
        return outcome
    if case.status == STATUS_REJECTED:
        tag = tag_of(case.word)
        if not terminal(tag):
            events.append(advance)
            return outcome
        shown, text = display_events(tag, RESULT + 8, relative)
        events.extend(shown)
        if case.write_fails:
            outcome["stop"] = ("unwrap", LOCATION_STRING, STRING_TEXT, STRING_TEXT_SIZE, None)
            return outcome
    else:
        text = status_text(case.status)
        events.append(("status text", RESULT, 0))
    if family == PERP:
        market = case.asset // DIVISOR
        if market >= case.markets:
            outcome["stop"] = ("unwrap", LOCATION_MARKET, UNWRAP_TEXT, UNWRAP_SIZE, ERROR_WORD)
            return outcome
        events.append(("drop", ERROR_WORD))
        events.append(("convert", CONVERT[family], MARKETS + market * MARKET_STRIDE, body))
    else:
        events.append(("convert", CONVERT[family], EXCHANGE + SPOT_CONVERT_FIELD, body))
    if case.capacity == case.filled:
        events.append(("grow", family))
    events.append(("copy", RECORD_SIZE[family]))
    outcome["count"] = case.filled + 1
    outcome["row"] = (struct.pack("<Q", RECORD_TAG) + converted(case.oid), text, struct.pack("<Q", case.oid) + TIME_BYTES + user_id(case.user))
    events.append(("remove order", ORDER_REMOVE[family], case.oid))
    if case.gone:
        events.append(("drop failed", FAILED_WORD))
        return outcome
    if len(case.orders) == 0:
        events.append(("remove user", USER_REMOVE[family], user_id(case.user)))
        if case.user_value:
            words = (1, 0, USER_TREE, USER_HEIGHT, 1, 0, USER_TREE, USER_HEIGHT, USER_COUNT) if case.user_root else (0, 0, 0)
            if family == PERP:
                for index in range(case.drop_steps):
                    events.append(("user drop", index) + words)
            else:
                events.append(("user drop", 0, USER_TREE if case.user_root else 0))
    return outcome


def result_cases():
    cases = []

    def add(label, **options):
        cases.append(ResultCase(label, **options))

    add("no fills", executed=500, second=9000)
    add("one fill", fills=[Fill(9, 100, 200)], executed=500, second=9000)
    add("one fill, first equals second", fills=[Fill(9, 100, 100)], executed=1, second=2)
    add("one fill, first one above second", fills=[Fill(9, 101, 100)], executed=1, second=2)
    add("one fill, first zero", fills=[Fill(9, 0, 100)], executed=1, second=2)
    add("one fill, both zero", fills=[Fill(9, 0, 0)], executed=1, second=2)
    add("one fill of 1 and 1", fills=[Fill(9, 1, 1)], executed=1, second=2)
    add("two fills, same key", fills=[Fill(9, 100, 200), Fill(9, 30, 70)], executed=500, second=9000)
    add("three fills, same key", fills=[Fill(9, 100, 200), Fill(9, 30, 70), Fill(9, 1, 2)], executed=500, second=9000)
    add("four fills, same key", fills=[Fill(4, 1, 2), Fill(4, 30, 70), Fill(4, 9, 11), Fill(4, 2, 2)], executed=7)
    add("two fills, second key differs", fills=[Fill(9, 100, 200), Fill(8, 30, 70)], executed=500, second=9000)
    add("three fills, third key differs", fills=[Fill(9, 100, 200), Fill(9, 30, 70), Fill(1 << 40, 1, 2)], executed=500, second=9000)
    add("two fills, sum over gate", fills=[Fill(9, 60, 50), Fill(9, 50, 60)], executed=3, second=4)
    add("two fills, one gate pass after sum", fills=[Fill(9, 50, 10), Fill(9, 10, 50)], executed=3, second=4)
    add("two fills, first sum saturates", fills=[Fill(9, MASK[8], MASK[8]), Fill(9, 1, 0)], executed=3, second=4)
    add("two fills, second sum saturates", fills=[Fill(9, 1, MASK[8]), Fill(9, 1, 1)], executed=3, second=4)
    add("two fills, both sums saturate", fills=[Fill(9, MASK[8], MASK[8]), Fill(9, 1, 1)], executed=3, second=4)
    add("two fills, saturate and key differs", fills=[Fill(9, MASK[8], MASK[8]), Fill(8, 1, 1)], executed=3, second=4)
    add("two fills, first sum saturates, record empty", fills=[Fill(9, MASK[8], MASK[8]), Fill(9, 1, 0)])
    add("two fills, second sum saturates, record empty", fills=[Fill(9, 1, MASK[8]), Fill(9, 1, 1)])
    add("two fills, exact top", fills=[Fill(9, MASK[8] - 1, MASK[8] - 1), Fill(9, 1, 1)], executed=0)
    add("three fills, saturate early", fills=[Fill(9, MASK[8], MASK[8]), Fill(9, 5, 5), Fill(9, 6, 6)], executed=3, second=4)
    add("executed saturates", fills=[Fill(9, 10, 20)], executed=MASK[8] - 5, second=0)
    add("second saturates", fills=[Fill(9, 10, 20)], executed=0, second=MASK[8] - 5)
    add("both saturate", fills=[Fill(9, 10, 20)], executed=MASK[8] - 5, second=MASK[8] - 5)
    add("executed reaches top", fills=[Fill(9, 10, 20)], executed=MASK[8] - 10, second=MASK[8] - 20)
    add("sign bit amounts", fills=[Fill(9, 1 << 63, 1 << 63)], executed=1 << 63, second=1 << 62)
    for tag in range(TAG_COUNT):
        add("rejected tag %d" % tag, status=STATUS_REJECTED, word=NICHE_BIT | tag, executed=11, second=22, fills=[Fill(9, 100, 200)])
    for tag in (24, 31, 32, 63, 64, 67, 128, 1 << 40):
        add("rejected tag %d past the table" % tag, status=STATUS_REJECTED, word=NICHE_BIT | tag, executed=11, second=22) if not terminal(tag) else None
    for word in (0, 1, 2, 3, 24, 1 << 40, NICHE_BIT - 1):
        add("rejected, plain word %#x" % word, status=STATUS_REJECTED, word=word, executed=11, second=22)
    for status in (0, 1, 2, 0xC3, 0xC5, 0x185, 0x187, 0x400, 0xFFFF):
        add("status %#x" % status, status=status, executed=11, second=22)
    add("tag 3 with a neighbour order", status=STATUS_REJECTED, word=NICHE_BIT | 3, orders=(2, 9))
    add("tag 3 last order of the user", status=STATUS_REJECTED, word=NICHE_BIT | 3)
    add("tag 3 removal finds nothing", status=STATUS_REJECTED, word=NICHE_BIT | 3, gone=True)
    add("tag 3 removal finds nothing with neighbours", status=STATUS_REJECTED, word=NICHE_BIT | 3, gone=True, orders=(2,))
    add("user removal gives none", status=7, user_value=False)
    add("user removal gives an empty map", status=7, user_root=False)
    add("user removal, three drop steps", status=7, drop_steps=3)
    add("row grows", status=7, capacity=1, filled=1)
    add("row grows from empty", status=STATUS_REJECTED, word=NICHE_BIT | 9, capacity=0, filled=0)
    add("row appended at a later index", status=7, capacity=9, filled=3)
    add("display fails", status=STATUS_REJECTED, word=NICHE_BIT | 3, write_fails=True)
    add("format fails", status=STATUS_REJECTED, word=NICHE_BIT | 6, write_fails=True)
    add("asset in the last market", status=7, asset=29999, markets=3)
    add("asset on the market bound", status=7, asset=30000, markets=3)
    add("asset past the market bound", status=7, asset=99999, markets=3)
    add("asset bound with a rejected tag", status=STATUS_REJECTED, word=NICHE_BIT | 3, asset=30000, markets=3)
    add("asset zero with one market", status=7, asset=0, markets=1)
    add("no markets", status=7, asset=0, markets=0)
    add("order not stored", order_missing=True, status=7)
    add("order not stored, success", order_missing=True, fills=[Fill(9, 1, 2)], orders=(2, 9))
    add("order not stored, rejected", order_missing=True, status=STATUS_REJECTED, word=NICHE_BIT | 3)
    add("user not stored", users_missing=True, status=7)
    add("user not stored, success", users_missing=True, fills=[Fill(9, 1, 2)], others=(2, 3, 4))
    add("user not stored, other users", users_missing=True, status=STATUS_REJECTED, word=NICHE_BIT | 8, others=(2, 3))
    for width, count in ((1, 7), (2, 26), (11, 40)):
        keys = tuple(oid * 3 + 2 for oid in range(count))
        for oid in (keys[0] - 1, keys[count // 2] + 1, keys[-1] + 1, keys[0], keys[count // 3], keys[-1]):
            rest = tuple(key for key in keys if key != oid)
            add("order walk, width %d, order %d" % (width, oid), oid=oid, orders=rest, width=width, fills=[Fill(9, 3, 4)], others=(2, 3, 4, 5, 6, 7, 8))
            add("order walk ends the slice, width %d, order %d" % (width, oid), oid=oid, orders=rest, width=width, status=7, others=(2, 3, 4, 5, 6, 7, 8))
    for user in (2, 3, 5, 6, 7, 9):
        add("user walk, user %d" % user, user=user, others=tuple(other for other in range(1, 10) if other != user), width=1, status=7)
        add("user walk, success, user %d" % user, user=user, others=tuple(other for other in range(1, 10) if other != user), width=2, fills=[Fill(9, 3, 4)])
    return cases


class CallerCase:
    def __init__(self, label, now=(5, 6, 7), limit=(5, 6, 7), height=10, height_limit=10, markets=3, dexes=3, perp=(), spot=(), gate=0, alloc_fails=False):
        self.label, self.now, self.limit, self.height, self.height_limit = label, now, limit, height, height_limit
        self.markets, self.dexes, self.perp, self.spot, self.gate, self.alloc_fails = markets, dexes, perp, spot, gate, alloc_fails


def signed32(value):
    return value - (1 << 32) if value & SIGN[4] else value


def spec_flag(case):
    now = (signed32(case.now[0]), case.now[1], case.now[2])
    limit = (signed32(case.limit[0]), case.limit[1], case.limit[2])
    return int(now < limit or case.height < case.height_limit)


def market_id(index):
    return 0x7100000000 + index * 0x1357


def result_record(entry):
    asset, oid, user = entry
    data = bytearray(ramp(RESULT_STRIDE, oid, 11))
    data[RESULT_ASSET:RESULT_ASSET + 8] = struct.pack("<Q", asset)
    data[RESULT_OID:RESULT_OID + 8] = struct.pack("<Q", oid)
    data[RESULT_USER:RESULT_USER + 20] = user_id(user)
    return bytes(data)


def spec_caller(row, case):
    events = []
    outcome = {"events": events}
    flag = spec_flag(case)
    now = struct.pack("<III", *case.now)
    if case.markets:
        events.append(("alloc", case.markets * 8))
        if case.alloc_fails:
            outcome["stop"] = ("alloc", 8, case.markets * 8)
            return outcome
    ids = tuple(market_id(index) for index in range(case.markets))
    events.append(("collect", ids, EXCHANGE, EXCHANGE + row["books"], now, flag))
    events.append(("map perp", COLLECTED, EXCHANGE))
    for at, entry in enumerate(case.perp):
        dex = entry[0] // DIVISOR
        if dex >= case.dexes:
            outcome["stop"] = ("unwrap", LOCATION_DEX, UNWRAP_TEXT, UNWRAP_SIZE, ERROR_WORD)
            return outcome
        events.append(("drop", ERROR_WORD))
        record = PERP_RESULTS + at * RESULT_STRIDE
        events.append(("handler", row["perp"], DEXES + dex * DEX_STRIDE + DEX_TRACKER_FIELD, user_id(entry[2]), entry[1], record, EXCHANGE, 8))
        events.append(("flush perp", 8, dex, EXCHANGE))
    if case.gate:
        outcome["spot"] = (0, 8, 0)
    else:
        events.append(("spot drain", row["drain"], EXCHANGE + row["spot_tracker"], now, flag, EXCHANGE + row["spot_books"], EXCHANGE))
        events.append(("flush spot", 8, EXCHANGE))
        events.append(("map spot", DRAINED, EXCHANGE))
        for at, entry in enumerate(case.spot):
            record = SPOT_RESULTS + at * RESULT_STRIDE
            events.append(("handler", row["spot"], EXCHANGE + row["spot_tracker"], user_id(entry[2]), entry[1], record, EXCHANGE, 8))
            events.append(("flush spot", 8, EXCHANGE))
        outcome["spot"] = (len(case.spot), SPOT_RESULTS, len(case.spot))
    outcome["perp"] = (len(case.perp), PERP_RESULTS, len(case.perp))
    return outcome


def caller_cases():
    cases = []

    def add(label, **options):
        cases.append(CallerCase(label, **options))

    one = ((20003, 7, 1),)
    two = ((3, 7, 1), (20003, 8, 2))
    add("empty block")
    for count in (0, 1, 2, 3, 4, 5, 7, 8, 9):
        add("%d markets" % count, markets=count)
    add("one perp result", perp=one)
    add("two perp results", perp=two)
    add("three perp results in other dexes", perp=((29999, 7, 1), (0, 1, 3), (10000, 4, 5)))
    add("perp result on the dex bound", perp=((30000, 7, 1),))
    add("perp result past the dex bound", perp=two + ((99999, 7, 1),))
    add("dex bound 1", perp=((9999, 7, 1),), dexes=1)
    add("dex bound 0", perp=((0, 7, 1),), dexes=0)
    add("one spot result", spot=one)
    add("two spot results", spot=two)
    add("both kinds", perp=two, spot=two + one)
    add("gate set", gate=1, perp=two, spot=two)
    add("gate byte 0x80", gate=0x80, spot=one)
    add("gate set, no perp", gate=1)
    add("allocation fails", alloc_fails=True, markets=2)
    add("date before", now=(4, 9, 9))
    add("date after", now=(6, 0, 0))
    add("second before", now=(5, 5, 9))
    add("second after", now=(5, 7, 0))
    add("nano before", now=(5, 6, 6))
    add("nano after", now=(5, 6, 8))
    add("date before by sign", now=(0xFFFFFFFF, 6, 7), limit=(1, 6, 7))
    add("date after by sign", now=(1, 6, 7), limit=(0xFFFFFFFF, 6, 7))
    add("second by unsigned", now=(5, 0xFFFFFFFF, 7), limit=(5, 1, 7))
    add("nano by unsigned", now=(5, 6, 0xFFFFFFFF), limit=(5, 6, 1))
    add("height before", height=9)
    add("height after", height=11)
    add("height one below the top", height=(1 << 63) - 1, height_limit=1 << 63)
    add("height unsigned", height=1 << 63, height_limit=1)
    add("date before, height after", now=(4, 9, 9), height=11)
    add("date after, height before", now=(6, 0, 0), height=9)
    add("second after, height before", now=(5, 7, 0), height=9)
    add("nano after, height before", now=(5, 6, 8), height=9)
    return cases


TRACKER = HEAP_BASE + 0x3000
RESULT = HEAP_BASE + 0x3300
PAYLOAD = RESULT + 8
STRING_AT = HEAP_BASE + 0x3400
FORMATTER = HEAP_BASE + 0x3440
USER_AT = HEAP_BASE + 0x3640
SLOT_ENTRY = HEAP_BASE + 0x3680
ROWS = HEAP_BASE + 0x36C0
RECORDS = HEAP_BASE + 0x8000
TEXTS = HEAP_BASE + 0x9800
FILLS = HEAP_BASE + 0xA000
COLLECTED = HEAP_BASE + 0xE000
DRAINED = HEAP_BASE + 0xE100
PERP_RESULTS = HEAP_BASE + 0xE200
SPOT_RESULTS = HEAP_BASE + 0xF200
MARKET_ARRAY = HEAP_BASE + 0x10000
DEXES = HEAP_BASE + 0x18000
EXCHANGE = HEAP_BASE + 0x20000
NODES = HEAP_BASE + 0x40000
MARKETS = 0x640000000
LEAF_EDGE = 0x4242424242424200
HISTORY = HEAP_BASE + 0x3A00
HISTORY_TEXT = HEAP_BASE + 0x3B00
BUFFER = HEAP_BASE + 0x3C00
BUFFER_BYTES = HEAP_BASE + 0x3D00
BUFFER_HOLDER = HEAP_BASE + 0x3C20
FIELD_STATE_AT = HEAP_BASE + 0x3C40
USER_TREE = HEAP_BASE + 0x3800
USER_HEIGHT = 5
USER_COUNT = 9
TIME_WORDS = (0x12345678, 0x9ABCDEF, 0x7654321)
TIME_BYTES = struct.pack("<III", *TIME_WORDS)


def tree_height(count, width):
    height = 0
    while (width + 1) ** (height + 1) - 1 < count:
        height += 1
    return height


def chunks(keys, width, height):
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
        self.relative = relative
        for slot in (SLOT_DISPLAY, SLOT_FORMAT, SLOT_RECORDER, SLOT_UNWRAP, SLOT_FREE, SLOT_ALLOC, SLOT_ALLOC_FAILED, SLOT_GROW_PERP, SLOT_GROW_SPOT,
                     STRING_VTABLE + WRITE_STR_FIELD, SLOT_JSON_ERROR, SLOT_ASSERT):
            machine.memory.statics[slot] = relative[slot]
        machine.memory.statics[SLOT_F64_DISPLAY] = relative[SLOT_F64_DISPLAY]
        machine.memory.statics[SLOT_MEMCMP] = FAKE_MEMCMP
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
        machine.slots = {relative[STRING_VTABLE + WRITE_STR_FIELD]: self.on_write, relative[SLOT_FORMAT]: self.on_format, relative[SLOT_RECORDER]: self.on_recorder,
                         relative[SLOT_UNWRAP]: self.on_unwrap, relative[SLOT_FREE]: self.on_free, relative[SLOT_ALLOC]: self.on_alloc,
                         relative[SLOT_ALLOC_FAILED]: self.on_alloc_failed, relative[SLOT_GROW_PERP]: self.on_grow_perp,
                         relative[SLOT_GROW_SPOT]: self.on_grow_spot, FAKE_MEMCMP: self.on_memcmp, FAKE_MEMCPY: self.on_memcpy,
                         relative[SLOT_JSON_ERROR]: self.on_json_error, relative[SLOT_ASSERT]: self.on_assert}
        machine.calls = {DROP_ERROR: self.on_drop, DROP_FAILED: self.on_drop_failed, STATUS_TEXT: self.on_status}
        for family in (PERP, SPOT):
            machine.calls[CONVERT[family]] = self.on_convert
            machine.calls[ORDER_REMOVE[family]] = self.on_remove_order
            machine.calls[USER_REMOVE[family]] = self.on_remove_user
            machine.calls[USER_DROP[family]] = self.on_user_drop
            machine.calls[USER_ENTRY[family]] = self.on_entry
        for row in HANDLERS:
            machine.calls[row["advance"]] = self.hook_advance(row["advance"])
        for row in CALLERS:
            machine.calls[row["perp"]] = self.hook_handler(row["perp"])
            machine.calls[row["spot"]] = self.hook_handler(row["spot"])
            machine.calls[row["drain"]] = self.hook_drain(row["drain"])
            machine.calls[row["collect"]] = self.on_collect
            machine.calls[row["map_perp"]] = self.on_map_perp
            machine.calls[row["map_spot"]] = self.on_map_spot
            machine.calls[row["flush_perp"]] = self.on_flush_perp
            machine.calls[row["flush_spot"]] = self.on_flush_spot
        machine.calls.update({STR_WRITE: self.on_str_write, VEC_GROW: self.on_vec_grow, FIELD_TIME: self.hook_field("time", TIME_JSON, False),
                              FIELD_ID: self.hook_field("twap_id", ID_JSON, True), FIELD_STATE: self.hook_field("state", STATE_JSON, True),
                              STRUCT_END: self.on_struct_end})
        self.used = HEAP_SIZE
        self.brk = NODES

    def reset(self):
        self.machine.memory.reset(self.used)
        self.used = NODES - HEAP_BASE
        self.events = []
        self.brk = NODES
        self.text_at = TEXTS
        self.serial = None
        self.machine.real = frozenset()
        self.machine.jump_low, self.machine.jump_high = self.image.exact_fde(DISPLAY)

    def carve(self, size):
        at = self.brk
        self.brk += (size + 15) & ~15
        self.used = max(self.used, self.brk - HEAP_BASE)
        return at

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def build_tree(self, at, keys, shape, width, write_key, write_value=None):
        keys = list(keys)
        if not keys:
            self.word(at, 0)
            self.word(at + 8, 0)
            self.word(at + 0x10, 0)
            return

        def make(items, parent, slot, level):
            node = self.carve(shape["size"])
            self.machine.memory.put_bytes(node, bytes(shape["size"]))
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

    def install_users(self, case):
        users = {}
        if not case.users_missing:
            orders = {oid: ramp(0x60, oid, 13) for oid in case.orders}
            if not case.order_missing:
                orders[case.oid] = order_body(case.oid, case.asset, case.executed, case.second)
            users[case.user] = orders
        for other in case.others:
            users.setdefault(other, {3: bytes(0x60)})
        self.body_slot = None

        def write_user(at, user):
            self.machine.memory.put_bytes(at, user_id(user))

        def write_orders(at, user):
            orders = users[user]

            def write_body(slot, oid):
                self.machine.memory.put_bytes(slot, orders[oid])
                if user == case.user and oid == case.oid:
                    self.body_slot = slot

            if user == case.user:
                self.map_slot = at
            self.build_tree(at, sorted(orders), ORDER_NODE, case.width, lambda key_at, oid: self.word(key_at, oid), write_body)

        # User keys compare as bytes, and user_id is not monotonic in its number.
        self.build_tree(TRACKER + 0x18, sorted(users, key=user_id), USER_NODE, case.width, write_user, write_orders)

    def run_result(self, row, case):
        self.reset()
        self.case = case
        self.family = row["family"]
        machine = self.machine
        memory = machine.memory
        machine.real = frozenset((DISPLAY,))
        self.write_fails = case.write_fails
        self.install_users(case)
        memory.put_bytes(USER_AT, user_id(case.user))
        memory.put_bytes(RESULT, ramp(0x60, 0x31, 5))
        self.word(RESULT, case.status, 2)
        self.word(RESULT + 8, case.word)
        stride, key_at = FILL_STRIDE[self.family], FILL_KEY[self.family]
        if case.status == STATUS_OK or case.fills:
            self.word(RESULT + 0x10, FILLS)
            self.word(RESULT + 0x18, len(case.fills) if case.status == STATUS_OK else 0)
        memory.put_bytes(FILLS, ramp(stride * max(len(case.fills), 1), 0x5B, 3))
        for index, fill in enumerate(case.fills):
            base = FILLS + index * stride + key_at
            self.word(base, fill.key)
            self.word(base + 8, fill.first)
            self.word(base + 0x10, fill.second)
        if self.family == PERP:
            self.word(EXCHANGE + row["markets"], MARKETS)
            self.word(EXCHANGE + row["count"], case.markets)
        self.word(EXCHANGE + TIME_FIELD, TIME_WORDS[0] | TIME_WORDS[1] << 32)
        self.word(EXCHANGE + TIME_FIELD + 8, TIME_WORDS[2], 4)
        self.word(ROWS, case.capacity)
        self.word(ROWS + 8, RECORDS)
        self.word(ROWS + 0x10, case.filled)
        stop = None
        try:
            machine.run(row["start"], {RDI: TRACKER, RSI: USER_AT, RDX: case.oid, RCX: RESULT, R8: EXCHANGE, R9: ROWS})
        except Panicked as panic:
            stop = panic.args[0]
        outcome = {"events": self.events, "count": memory.read(ROWS + 0x10, 8),
                   "body": memory.bytes_at(self.body_slot, 0x60) if self.body_slot else None}
        if stop:
            outcome["stop"] = stop
        elif outcome["count"] != case.filled:
            at = memory.read(ROWS + 8, 8) + case.filled * RECORD_SIZE[self.family]
            size, pointer, length = memory.read(at + 0x60, 8), memory.read(at + 0x68, 8), memory.read(at + 0x70, 8)
            if size < length:
                raise Halt("row text is longer than its capacity")
            outcome["row"] = (memory.bytes_at(at, 0x60), memory.bytes_at(pointer, length), memory.bytes_at(at + 0x78, ROW_PREFIX - 0x78))
        return outcome

    def run_display(self, word, fails=False):
        self.reset()
        machine = self.machine
        self.write_fails = fails
        self.word(PAYLOAD, word)
        self.word(PAYLOAD + 8, 0x1111222233334444)
        self.word(PAYLOAD + 0x10, 0x5555666677778888)
        self.word(STRING_AT, 0)
        self.word(STRING_AT + 8, 1)
        self.word(STRING_AT + 0x10, 0)
        self.word(FORMATTER, STRING_AT)
        self.word(FORMATTER + 8, STRING_VTABLE)
        result = machine.run(DISPLAY, {RDI: PAYLOAD, RSI: FORMATTER}) & 0xFF
        length = machine.memory.read(STRING_AT + 0x10, 8)
        return {"events": self.events, "text": machine.memory.bytes_at(machine.memory.read(STRING_AT + 8, 8), length), "result": result}

    def serialize(self, at, capacity=0x200):
        """Run the history serializer on the record at `at`, into a fresh buffer."""
        machine = self.machine
        machine.real = frozenset((SERIAL_FIELD, SERIAL_STATUS))
        machine.jump_low, machine.jump_high = self.image.exact_fde(SERIAL_STATUS)
        self.word(BUFFER, capacity)
        self.word(BUFFER + 8, BUFFER_BYTES)
        self.word(BUFFER + 0x10, 0)
        self.word(BUFFER_HOLDER, BUFFER)
        self.outcome = None
        result = machine.run(SERIAL_RECORD, {RDI: at, RSI: BUFFER_HOLDER})
        length = machine.memory.read(BUFFER + 0x10, 8)
        if length > machine.memory.read(BUFFER, 8):
            raise Halt("buffer overrun")
        return {"events": self.events, "text": machine.memory.bytes_at(BUFFER_BYTES, length), "result": result}

    def run_serial(self, case):
        self.reset()
        self.serial = case
        memory = self.machine.memory
        memory.put_bytes(HISTORY, ramp(0x88, 0x17, 9))
        self.word(HISTORY + HISTORY_STATUS, case.word)
        self.word(HISTORY + HISTORY_STATUS + 8, HISTORY_TEXT)
        self.word(HISTORY + HISTORY_STATUS + 0x10, len(case.text))
        if case.text:
            memory.put_bytes(HISTORY_TEXT, case.text)
        return self.serialize(HISTORY, case.capacity)

    def run_field(self, case):
        """Run the field wrapper alone, which can see the first-field state the record never gives it."""
        self.reset()
        self.serial = SerialCase("field")
        memory = self.machine.memory
        self.word(FIELD_STATE_AT, case.error | case.position << 8, 2)
        self.word(FIELD_STATE_AT + 8, BUFFER_HOLDER)
        self.word(BUFFER, case.capacity)
        self.word(BUFFER + 8, BUFFER_BYTES)
        self.word(BUFFER + 0x10, 0)
        self.word(BUFFER_HOLDER, BUFFER)
        self.word(HISTORY, case.word)
        self.word(HISTORY + 8, HISTORY_TEXT)
        self.word(HISTORY + 0x10, len(case.text))
        memory.put_bytes(HISTORY_TEXT, case.text or b"\0")
        machine = self.machine
        machine.real = frozenset((SERIAL_STATUS,))
        machine.jump_low, machine.jump_high = self.image.exact_fde(SERIAL_STATUS)
        try:
            result = machine.run(SERIAL_FIELD, {RDI: FIELD_STATE_AT, RSI: STATUS_KEY, RDX: len(b"status"), RCX: HISTORY})
        except Panicked as panic:
            return {"stop": panic.args[0]}
        return {"result": result, "text": memory.bytes_at(BUFFER_BYTES, memory.read(BUFFER + 0x10, 8)), "position": memory.read(FIELD_STATE_AT + 1, 1)}

    def run_chain(self, row, case):
        """Handler first, then its own row bytes through the real serializer."""
        outcome = self.run_result(row, case)
        memory = self.machine.memory
        at = memory.read(ROWS + 8, 8) + case.filled * RECORD_SIZE[row["family"]]
        memory.put_bytes(HISTORY, memory.bytes_at(at + 8, ROW_BODY))
        self.serial = SerialCase("chain")
        self.events = []
        return outcome, self.serialize(HISTORY)

    def run_caller(self, row, case):
        self.reset()
        self.case = case
        self.caller = row
        machine = self.machine
        memory = machine.memory
        self.alloc_fails = case.alloc_fails
        self.word(EXCHANGE + TIME_FIELD, case.now[0] | case.now[1] << 32)
        self.word(EXCHANGE + TIME_FIELD + 8, case.now[2], 4)
        self.word(EXCHANGE + HEIGHT_FIELD, case.height)
        self.word(EXCHANGE + row["limit"], case.limit[0] | case.limit[1] << 32)
        self.word(EXCHANGE + row["limit"] + 8, case.limit[2], 4)
        self.word(EXCHANGE + row["height"], case.height_limit)
        self.word(EXCHANGE + row["markets"], MARKET_ARRAY)
        self.word(EXCHANGE + row["count"], case.markets)
        for index in range(case.markets):
            self.word(MARKET_ARRAY + index * MARKET_STRIDE + MARKET_ID_FIELD, market_id(index))
        self.word(EXCHANGE + row["dex_ptr"], DEXES)
        self.word(EXCHANGE + row["dex_count"], case.dexes)
        self.word(EXCHANGE + row["gate"], case.gate, 1)
        for at, entry in enumerate(case.perp):
            memory.put_bytes(PERP_RESULTS + at * RESULT_STRIDE, result_record(entry))
        for at, entry in enumerate(case.spot):
            memory.put_bytes(SPOT_RESULTS + at * RESULT_STRIDE, result_record(entry))
        stop = None
        out = HEAP_BASE + 0x3700
        try:
            machine.run(row["start"], {RDI: out, RSI: EXCHANGE})
        except Panicked as panic:
            stop = panic.args[0]
        outcome = {"events": self.events}
        if stop:
            outcome["stop"] = stop
        else:
            words = [memory.read(out + index * 8, 8) for index in range(6)]
            outcome["perp"], outcome["spot"] = tuple(words[:3]), tuple(words[3:])
        return outcome

    def hook_field(self, name, text, comma):
        def hook(machine):
            regs = machine.regs
            memory = machine.memory
            if memory.bytes_at(regs[RSI], regs[RDX]) != name.encode():
                raise Halt("field key changed")
            self.events.append((name, regs[RCX]))
            buffer = memory.read(memory.read(regs[RDI] + 8, 8), 8)
            if memory.read(regs[RDI], 1) != 0 or memory.read(regs[RDI] + 1, 1) != (2 if comma else 1):
                raise Halt("serializer state changed")
            self.push_bytes(buffer, (b"," if comma else b"") + text)
            memory.write(regs[RDI] + 1, 1, 2)
            regs[RAX] = 0
            if self.serial.fail == name:
                regs[RAX] = 0xE0
            elif self.serial.state_flag == name:
                memory.write(regs[RDI], 1, 1)
        return hook

    def on_assert(self, machine):
        regs = machine.regs
        raise Panicked(("assert", regs[RDI], regs[RSI], regs[RDX]))

    def on_json_error(self, machine):
        self.events.append(("json error", machine.memory.read(machine.regs[RDI], 8)))
        machine.regs[RAX] = 0xE1

    def push_bytes(self, buffer, data):
        memory = self.machine.memory
        length = memory.read(buffer + 0x10, 8)
        if memory.read(buffer + 8, 8) != BUFFER_BYTES:
            raise Halt("buffer pointer changed")
        while memory.read(buffer, 8) < length + len(data):
            memory.write(buffer, 8, memory.read(buffer, 8) + 1)
        memory.put_bytes(BUFFER_BYTES + length, data)
        memory.write(buffer + 0x10, 8, length + len(data))

    def on_str_write(self, machine):
        regs = machine.regs
        self.push_bytes(regs[RDI], self.machine.memory.bytes_at(regs[RSI], regs[RDX]))

    def on_vec_grow(self, machine):
        regs = machine.regs
        memory = machine.memory
        if regs[RDX] != 1 or regs[RCX] != 1 or regs[R8] != 1 or regs[RSI] != memory.read(regs[RDI] + 0x10, 8):
            raise Halt("reserve arguments changed")
        if memory.read(regs[RDI], 8) != regs[RSI]:
            raise Halt("reserve on a buffer with room")
        memory.write(regs[RDI], 8, memory.read(regs[RDI], 8) + 1)

    def on_struct_end(self, machine):
        regs = machine.regs
        self.events.append(("end",))
        memory = machine.memory
        self.push_bytes(memory.read(memory.read(regs[RDI] + 8, 8), 8), b"}")
        regs[RAX] = 0

    def hook_advance(self, target):
        def hook(machine):
            regs = machine.regs
            self.events.append(("advance", target, regs[RDI], machine.memory.bytes_at(regs[RSI], 20), regs[RDX], regs[RCX], regs[R8]))
        return hook

    def hook_handler(self, target):
        def hook(machine):
            regs = machine.regs
            rows = machine.memory.read(regs[R9] + 8, 8)
            if machine.memory.read(regs[R9], 8) != 0 or machine.memory.read(regs[R9] + 0x10, 8) != 0:
                raise Halt("handler rows are not empty")
            self.events.append(("handler", target, regs[RDI], machine.memory.bytes_at(regs[RSI], 20), regs[RDX], regs[RCX], regs[R8], rows))
            self.last_handled = regs[RCX]
        return hook

    def hook_drain(self, target):
        def hook(machine):
            regs = machine.regs
            memory = machine.memory
            rows = memory.read(regs[RSP] + 8, 8)
            self.events.append(("spot drain", target, regs[RSI], memory.bytes_at(regs[RDX], 12), regs[RCX] & 0xFF, regs[R8], regs[R9]))
            if memory.read(rows, 8) != 0 or memory.read(rows + 0x10, 8) != 0 or memory.read(rows + 8, 8) != 8:
                raise Halt("drain rows are not empty")
            memory.write(regs[RDI], 8, 0x77)
            memory.write(regs[RDI] + 8, 8, DRAINED)
            memory.write(regs[RDI] + 0x10, 8, 2)
        return hook

    def on_collect(self, machine):
        regs = machine.regs
        memory = machine.memory
        words = [memory.read(regs[RSI] + index * 8, 8) for index in range(8)]
        ids = tuple(memory.read(words[1] + index * 8, 8) for index in range((words[3] - words[1]) // 8))
        if words[0] != words[1] or words[2] != len(ids) or (not ids and words[0] != 8):
            raise Halt("collector vector changed")
        if memory.read(regs[RSI] + 0x40, 8) or memory.read(regs[RSI] + 0x60, 8):
            raise Halt("collector inner iterators are not empty")
        self.events.append(("collect", ids, words[4], words[5], memory.bytes_at(words[6], 12), memory.read(words[7], 1)))
        memory.write(regs[RDI], 8, 0x55)
        memory.write(regs[RDI] + 8, 8, COLLECTED)
        memory.write(regs[RDI] + 0x10, 8, 3)

    def on_map_perp(self, machine):
        regs = machine.regs
        memory = machine.memory
        words = [memory.read(regs[RSI] + index * 8, 8) for index in range(5)]
        if words[0] != COLLECTED or words[1] != COLLECTED or words[2] != 0x55 or words[3] != COLLECTED + 3 * 0x70:
            raise Halt("perp map input changed")
        self.events.append(("map perp", words[0], words[4]))
        memory.write(regs[RDI], 8, len(self.case.perp))
        memory.write(regs[RDI] + 8, 8, PERP_RESULTS)
        memory.write(regs[RDI] + 0x10, 8, len(self.case.perp))

    def on_map_spot(self, machine):
        regs = machine.regs
        memory = machine.memory
        words = [memory.read(regs[RSI] + index * 8, 8) for index in range(5)]
        if words[0] != DRAINED or words[1] != DRAINED or words[2] != 0x77 or words[3] != DRAINED + 2 * 0x70:
            raise Halt("spot map input changed")
        self.events.append(("map spot", words[0], words[4]))
        memory.write(regs[RDI], 8, len(self.case.spot))
        memory.write(regs[RDI] + 8, 8, SPOT_RESULTS)
        memory.write(regs[RDI] + 0x10, 8, len(self.case.spot))

    def on_flush_perp(self, machine):
        regs = machine.regs
        self.events.append(("flush perp", machine.memory.read(regs[RDI] + 8, 8), regs[RSI], regs[RDX]))

    def on_flush_spot(self, machine):
        regs = machine.regs
        self.events.append(("flush spot", machine.memory.read(regs[RDI] + 8, 8), regs[RSI]))

    def on_alloc(self, machine):
        regs = machine.regs
        self.events.append(("alloc", regs[RDI]))
        regs[RAX] = 0 if self.alloc_fails else self.carve(regs[RDI])

    def on_alloc_failed(self, machine):
        raise Panicked(("alloc", machine.regs[RDI], machine.regs[RSI]))

    def append_text(self, target, data):
        memory = self.machine.memory
        if not memory.read(target, 8):
            if memory.read(target + 8, 8) != 1:
                raise Halt("empty text has the wrong pointer")
            memory.write(target + 8, 8, self.text_at)
            memory.write(target, 8, 0x100)
            self.text_at += 0x100
        pointer, length = memory.read(target + 8, 8), memory.read(target + 0x10, 8)
        memory.put_bytes(pointer + length, data)
        memory.write(target + 0x10, 8, length + len(data))

    def on_write(self, machine):
        regs = machine.regs
        data = machine.memory.bytes_at(regs[RSI], regs[RDX])
        self.events.append(("write", data))
        self.append_text(regs[RDI], data)
        regs[RAX] = int(self.write_fails)

    def on_format(self, machine):
        regs = machine.regs
        memory = machine.memory
        if regs[RSI] != STRING_VTABLE:
            raise Halt("format target changed")
        text = decode_template(self.image.blob, self.image.offset(regs[RDX]))
        args = tuple((memory.read(regs[RCX] + index * 16, 8), memory.read(regs[RCX] + index * 16 + 8, 8)) for index in range(text.count("{}")))
        # The Display passes some arguments by reference to a stack slot holding the pointer.
        args = tuple((memory.read(value, 8), shown) if self.machine.memory.locate(value, 8)[0] is memory.stack else (value, shown) for value, shown in args)
        self.events.append(("format", regs[RDX], args))
        self.append_text(regs[RDI], text.encode())
        regs[RAX] = int(self.write_fails)

    def on_status(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("status text", regs[RSI], regs[RDX] & 0xFFFFFFFF))
        text = status_text(memory.read(regs[RSI], 2))
        memory.write(regs[RDI], 8, 0)
        memory.write(regs[RDI] + 8, 8, 1)
        memory.write(regs[RDI] + 0x10, 8, 0)
        self.append_text(regs[RDI], text)

    def on_recorder(self, machine):
        self.events.append(("recorder", machine.regs[RDI], machine.regs[RSI]))
        machine.regs[RAX] = POISON

    def on_unwrap(self, machine):
        regs = machine.regs
        word = self.machine.memory.read(regs[RDX], 2) if regs[RDI] == UNWRAP_TEXT else None
        raise Panicked(("unwrap", regs[R8], regs[RDI], regs[RSI], word))

    def on_free(self, machine):
        self.events.append(("free", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_drop(self, machine):
        self.events.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_entry(self, machine):
        regs = machine.regs
        memory = machine.memory
        words = (memory.read(regs[RSI], 8), memory.read(regs[RSI] + 0x10, 8), memory.read(regs[RDX], 8), memory.read(regs[RDX] + 0x10, 8))
        self.events.append(("entry", USER_ENTRY[self.family], memory.bytes_at(regs[RSI] + 0x20, 20)) + words)
        memory.write(regs[RDI], 8, SLOT_ENTRY)
        memory.write(regs[RDI] + 0x10, 8, 0)
        memory.write(SLOT_ENTRY + 8, 8, 0)

    def on_remove_order(self, machine):
        regs = machine.regs
        memory = machine.memory
        oid = memory.read(regs[RDX], 8)
        if regs[RSI] != self.map_slot:
            raise Halt("order removal from the wrong map")
        self.events.append(("remove order", ORDER_REMOVE[self.family], oid))
        memory.write(regs[RSI] + 0x10, 8, len(self.case.orders))
        body = bytearray(removed_value(oid))
        if self.case.gone:
            body[0x22] = 2
        memory.put_bytes(regs[RDI], bytes(body))

    def on_remove_user(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("remove user", USER_REMOVE[self.family], memory.bytes_at(regs[RDX], 20)))
        case = self.case
        memory.write(regs[RDI], 8, int(case.user_value))
        memory.write(regs[RDI] + 8, 8, USER_TREE if case.user_root else 0)
        memory.write(regs[RDI] + 0x10, 8, USER_HEIGHT)
        memory.write(regs[RDI] + 0x18, 8, USER_COUNT)
        self.drop_left = case.drop_steps
        self.drop_step = 0

    def on_user_drop(self, machine):
        regs = machine.regs
        memory = machine.memory
        if self.family == PERP:
            words = [memory.read(regs[RSI] + index * 8, 8) for index in range(9)]
            if not words[0]:
                words = [words[0], words[4], words[8]]
            self.events.append(("user drop", self.drop_step) + tuple(words))
            self.drop_left -= 1
            memory.write(regs[RDI], 8, 1 if self.drop_left > 0 else 0)
        else:
            self.events.append(("user drop", self.drop_step, memory.read(regs[RDI], 8)))
        self.drop_step += 1

    def on_convert(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("convert", CONVERT[self.family], regs[RDX], memory.bytes_at(regs[RSI], 0x60)))
        memory.put_bytes(regs[RDI], converted(self.case.oid))

    def on_drop_failed(self, machine):
        self.events.append(("drop failed", machine.memory.read(machine.regs[RDI], 2)))

    def on_grow_perp(self, machine):
        self.grow(RECORD_SIZE[PERP])

    def on_grow_spot(self, machine):
        self.grow(RECORD_SIZE[SPOT])

    def grow(self, stride):
        self.events.append(("grow", self.family))
        machine = self.machine
        machine.memory.write(machine.regs[RDI], 8, 4)
        machine.memory.write(machine.regs[RDI] + 8, 8, RECORDS)

    def on_memcmp(self, machine):
        regs = machine.regs
        left = machine.memory.bytes_at(regs[RDI], regs[RDX])
        right = machine.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_memcpy(self, machine):
        regs = machine.regs
        self.events.append(("copy", regs[RDX]))
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]


def status_json(word, text):
    """The JSON of one status slot, from the rules alone."""
    if word & NICHE_BIT:
        return {0: b'"activated"', 1: b'"terminated"', 2: b'"finished"'}[word ^ NICHE_BIT]
    return b'{"error":"' + text + b'"}'


class SerialCase:
    def __init__(self, label, word=NICHE_BIT, text=b"", capacity=0x200, fail=None, state_flag=None):
        self.label, self.word, self.text, self.capacity, self.fail, self.state_flag = label, word, text, capacity, fail, state_flag


def serial_cases():
    cases = []
    for name, word in (("activated", NICHE_BIT), ("terminated", HALT_WORD), ("finished", FINISH_WORD)):
        cases.append(SerialCase(name, word=word))
        cases.append(SerialCase(name + ", tight buffer", word=word, capacity=0))
    for word in (0, 5, 0x100, NICHE_BIT - 1):
        cases.append(SerialCase("error text, capacity word %#x" % word, word=word, text=b"Insufficient margin to place order."))
    cases.append(SerialCase("error text, tight buffer", word=0x23, text=b"Halted", capacity=0))
    cases.append(SerialCase("empty error text", word=0, text=b""))
    for name in ("time", "twap_id", "state"):
        cases.append(SerialCase("field %s fails" % name, fail=name, word=FINISH_WORD))
    for name in ("time", "twap_id", "state"):
        cases.append(SerialCase("field %s leaves a bad state" % name, state_flag=name, word=FINISH_WORD))
    return cases


class FieldCase:
    def __init__(self, label, position=2, error=0, word=FINISH_WORD, text=b"", capacity=0x200):
        self.label, self.position, self.error, self.word, self.text, self.capacity = label, position, error, word, text, capacity


def field_cases():
    cases = []
    for position, name in ((1, "first field"), (2, "later field"), (0, "state 0"), (3, "state 3")):
        cases.append(FieldCase(name, position=position))
        cases.append(FieldCase(name + ", tight buffer", position=position, capacity=0))
    cases.append(FieldCase("error text", word=6, text=b"Halted"))
    cases.append(FieldCase("error state", error=1))
    return cases


def spec_field(case):
    if case.error == 1:
        return {"stop": ("assert", UNREACHABLE_TEXT, UNREACHABLE_SIZE, UNREACHABLE_LOCATION)}
    text = (b"" if case.position == 1 else b",") + b'"status":' + status_json(case.word, case.text)
    return {"result": 0, "text": text, "position": 2}


TIME_JSON = b'"time":"T"'
ID_JSON = b'"twap_id":77'
STATE_JSON = b'"state":{}'


def spec_serial(case, at):
    """Bytes and events for one history record at `at`."""
    text, events = b"{", []
    for index, (name, offset, piece) in enumerate((("time", HISTORY_TIME, TIME_JSON), ("twap_id", HISTORY_ID, ID_JSON), ("state", 0, STATE_JSON))):
        text += (b"," if index else b"") + piece
        events.append((name, at + offset))
        if case.fail == name:
            return {"events": events, "text": text, "result": 0xE0}
        if case.state_flag == name:
            return {"events": events + [("json error", 0xA)], "text": text, "result": 0xE1}
    return {"events": events + [("end",)], "text": text + b',"status":' + status_json(case.word, case.text) + b"}", "result": 0}


def compare(actual, expected, label):
    """Empty when the two outcomes agree, else the first difference."""
    if actual.get("stop") != expected.get("stop"):
        return "%s: stop %r, want %r" % (label, actual.get("stop"), expected.get("stop"))
    if actual["events"] != expected["events"]:
        for index, (left, right) in enumerate(zip(actual["events"], expected["events"])):
            if left != right:
                return "%s: event %d %r, want %r" % (label, index, left, right)
        return "%s: %d events, want %d" % (label, len(actual["events"]), len(expected["events"]))
    return ""


def guarded(run, *args):
    try:
        return run(*args), ""
    except Exception as stop:
        return None, "%s %s" % (type(stop).__name__, stop)


def compare_result(harness, row, case):
    actual, trouble = guarded(harness.run_result, row, case)
    if trouble:
        return "%s: %s" % (case.label, trouble)
    expected = spec_result(row, case, harness.relative)
    found = compare(actual, expected, case.label)
    if found:
        return found
    for key in ("count", "body", "row"):
        if actual.get(key) != expected.get(key):
            return "%s: %s %r, want %r" % (case.label, key, actual.get(key), expected.get(key))
    return ""


def compare_caller(harness, row, case):
    actual, trouble = guarded(harness.run_caller, row, case)
    if trouble:
        return "%s: %s" % (case.label, trouble)
    expected = spec_caller(row, case)
    found = compare(actual, expected, case.label)
    if found or "stop" in expected:
        return found
    for key in ("perp", "spot"):
        if actual[key] != expected[key]:
            return "%s: %s %r, want %r" % (case.label, key, actual[key], expected[key])
    return ""


def compare_display(harness, _row, case):
    word, label = case
    actual, trouble = guarded(harness.run_display, word)
    if trouble:
        return "%s: %s" % (label, trouble)
    events, text = display_events(tag_of(word), PAYLOAD, harness.relative)
    if actual["events"] != events or actual["text"] != text or actual["result"] != 0:
        return "%s: %r, want %r" % (label, actual, (events, text))
    return ""


def compare_serial(harness, _row, case):
    actual, trouble = guarded(harness.run_serial, case)
    if trouble:
        return "%s: %s" % (case.label, trouble)
    expected = spec_serial(case, HISTORY)
    for key in ("events", "text", "result"):
        if actual[key] != expected[key]:
            return "%s: %s %r, want %r" % (case.label, key, actual[key], expected[key])
    return ""


def compare_field(harness, _row, case):
    actual, trouble = guarded(harness.run_field, case)
    if trouble:
        return "%s: %s" % (case.label, trouble)
    expected = spec_field(case)
    if actual != expected:
        return "%s: %r, want %r" % (case.label, actual, expected)
    return ""


def compare_json(harness, row, case):
    return (compare_field if isinstance(case, FieldCase) else compare_serial)(harness, row, case)


def display_cases():
    return [(NICHE_BIT | tag, "tag %d" % tag) for tag in range(TAG_COUNT)] + [(0, "plain word 0"), (1 << 40, "plain word 2^40")]


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


def find_once(image, start, pattern):
    """The one place a byte pattern occurs inside a function."""
    begin, end = image.exact_fde(start)
    data = bytes(image.blob[image.offset(begin):image.offset(begin) + end - begin])
    at = data.find(pattern)
    if at < 0 or data.find(pattern, at + 1) >= 0:
        raise EvidenceError("pattern %s is not unique in %#x" % (pattern.hex(), start))
    return begin + at


# Each pattern must occur exactly once inside every handler.
HANDLER_PINS = (
    ("cmp eax, 0xc4: the rejected status", b"\x3d\xc4\x00\x00\x00"),
    ("cmp eax, 0x186: the success status", b"\x3d\x86\x01\x00\x00"),
    ("mov ecx, 0xfc02f9 then bt rcx, rax: the terminal test", b"\xb9\xf9\x02\xfc\x00\x48\x0f\xa3\xc1"),
    ("mov eax, 2: a tag word without the top bit is tag 2", b"\xb8\x02\x00\x00\x00\x48\x0f\x48\xc1"),
    ("mov [rsp+0xf0], 0x60000020: the formatter options of the text", b"\x48\xc7\x84\x24\xf0\x00\x00\x00\x20\x00\x00\x60"),
)


def handler_pins(image):
    rows = []
    for row in HANDLERS:
        for meaning, pattern in HANDLER_PINS:
            rows.append({"function": "%#x" % row["start"], "va": "%#x" % find_once(image, row["start"], pattern), "bytes": pattern.hex(), "meaning": meaning})
    return rows


def word_sites(image, starts, word):
    """Where each function loads a word that its row puts in the status slot."""
    pattern = struct.pack("<Q", word)
    rows = []
    for start in starts:
        begin, end = image.exact_fde(start)
        data = bytes(image.blob[image.offset(begin):image.offset(begin) + end - begin])
        at = data.find(pattern)
        if at < 0 or data.find(pattern, at + 1) >= 0:
            raise EvidenceError("word %#x is not unique in %#x" % (word, start))
        rows.append({"function": "%#x" % begin, "word_at": "%#x" % (begin + at)})
    return rows


def serial_table(image):
    """The four arms of the status serializer, read until an entry leaves the function."""
    begin, end = image.exact_fde(SERIAL_STATUS)
    targets = []
    while True:
        target = SERIAL_TABLE + struct.unpack_from("<i", image.blob, image.offset(SERIAL_TABLE) + len(targets) * 4)[0]
        if not begin <= target < end:
            return targets
        targets.append(target)


def flush_body(image):
    """Tag 4 in the row flush: the third table entry starts by copying the row body."""
    target = FLUSH_TABLE + struct.unpack_from("<i", image.blob, image.offset(FLUSH_TABLE) + (RECORD_TAG - 2) * 4)[0]
    begin, end = image.exact_fde(FLUSH_START)
    if not begin <= target < end:
        raise EvidenceError("flush table entry leaves the function: %#x" % target)
    expected = b"\xba" + struct.pack("<I", ROW_BODY)
    data = bytes(image.blob[image.offset(target):image.offset(target) + 5])
    if data != expected:
        raise EvidenceError("flush arm at %#x starts with %s" % (target, data.hex()))
    return {"table": "%#x" % FLUSH_TABLE, "index": RECORD_TAG - 2, "arm": "%#x" % target, "bytes": data.hex(), "copied": "%#x" % ROW_BODY}


def display_table(image):
    """The jump table of the Display, read until an entry leaves the function."""
    begin, end = image.exact_fde(DISPLAY)
    targets = []
    while True:
        target = DISPLAY_TABLE + struct.unpack_from("<i", image.blob, image.offset(DISPLAY_TABLE) + len(targets) * 4)[0]
        if not begin <= target < end:
            return targets
        targets.append(target)


def check_pairing(image):
    """Each caller reaches its two handlers, and each handler its advance."""
    pairs = []
    sites = direct_sites(image, [row[key] for row in CALLERS for key in ("perp", "spot", "drain")] + [row["advance"] for row in HANDLERS])
    links = []
    for row in CALLERS:
        links += [(row["start"], row["perp"]), (row["start"], row["spot"]), (row["start"], row["drain"])]
    links += [(row["start"], row["advance"]) for row in HANDLERS]
    for source, target in links:
        begin, end = image.exact_fde(source)
        inside = [va for va, _ in sites[target] if begin <= va < end]
        if not inside:
            raise EvidenceError("%#x does not reach %#x" % (source, target))
        pairs.append({"from": "%#x" % source, "to": "%#x" % target, "sites": ["%#x" % va for va in sorted(inside)]})
    return pairs


# ---- mutation pass ----

MUTATED = (HANDLERS[0]["start"], HANDLERS[2]["start"], CALLERS[0]["start"], DISPLAY, SERIAL_RECORD, SERIAL_FIELD, SERIAL_STATUS)


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


def run_mutants(image, seen, verbose=False):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    choices = {HANDLERS[0]["start"]: (HANDLERS[0], result_cases(), compare_result), HANDLERS[2]["start"]: (HANDLERS[2], result_cases(), compare_result),
               CALLERS[0]["start"]: (CALLERS[0], caller_cases(), compare_caller), DISPLAY: (None, display_cases(), compare_display),
               SERIAL_RECORD: (None, serial_cases(), compare_serial), SERIAL_FIELD: (None, field_cases() + serial_cases(), compare_json),
               SERIAL_STATUS: (None, field_cases() + serial_cases(), compare_json)}
    for start in MUTATED:
        row, cases, check = choices[start]
        rows = decode_range(image, *image.exact_fde(start))
        for va, at, kind in mutation_targets(image, rows):
            if va not in seen:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            for index, case in enumerate(cases):
                failed = check(harness, row, case)
                if failed:
                    cases.insert(0, cases.pop(index))
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

STATUS_ARMS = ("activated", "terminated", "finished", "error")
LOCATIONS = (LOCATION_MARKET, LOCATION_DEX, LOCATION_STRING, LOCATION_SUM_FIRST, LOCATION_SUM_SECOND, LOCATION_ADD_FIRST, LOCATION_ADD_SECOND)
ROW_MAP = (
    (0x00, 8, "tag, constant 4"),
    (0x08, 0x58, "the first 0x58 bytes the convert helper writes for the schedule record"),
    (0x60, 0x18, "text: capacity, pointer, length"),
    (0x78, 8, "order id"),
    (0x80, 12, "exchange +0x60, the same time word the callers compare"),
    (0x8C, 20, "user"),
)
RESULT_MAP = (
    (0x00, 2, "status: 0x186 success, 0xc4 rejected with a tag, anything else ends the order"),
    (0x08, 8, "tag word on 0xc4: top bit set gives the low bits as the tag, otherwise tag 2 and the word starts the tag 2 text"),
    (0x10, 8, "fill pointer on 0x186"),
    (0x18, 8, "fill count on 0x186"),
    (0x60, 8, "asset, read by the caller for the dex index"),
    (0x68, 8, "order id"),
    (0x70, 20, "user"),
)
FILL_MAP = (
    ("key", "%#x" % FILL_KEY[PERP], "%#x" % FILL_KEY[SPOT], "all fills of the result must agree, or both sums are dropped"),
    ("first", "%#x" % (FILL_KEY[PERP] + 8), "%#x" % (FILL_KEY[SPOT] + 8), "sum goes to record +0x28, recorder line 827 of l1/src/qtys/mod.rs"),
    ("second", "%#x" % (FILL_KEY[PERP] + 0x10), "%#x" % (FILL_KEY[SPOT] + 0x10), "sum goes to record +0x30, recorder line 829 of l1/src/qtys/mod.rs"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/time.rs:173-174", "claim": "fields filled_or_progress at +0x28 and secondary_progress at +0x30",
     "bytes": "agrees on the offsets: these are the only two record fields a success adds to"},
    {"reference": "l1/time.rs:156-159", "claim": "TwapAdvanceDecision is EmitNow or Defer",
     "bytes": "the handler is one step earlier: it picks advance or end before any such decision exists"},
    {"reference": "node/aux.rs:8", "claim": "an output named node_twap_statuses",
     "bytes": "the same name is at 0x6fd940 in the file; no link from these rows to that output is traced here"},
    {"reference": "whole tree", "claim": "none of the 24 rejection texts and no mention of the mask 0xfc02f9 or of the four status arms",
     "bytes": "this packet supplies the texts and the split from the bytes"},
)
DEAD_WALK = "second walk of a user the first walk found, in the same function with no write between, so a miss has no input"
PINNED_OPTIONS = "formatter options word: only core::fmt padding reads it, and that code is not run here; handler_pins fixes the bytes instead"
EQUIVALENT = {0x42ED623: PINNED_OPTIONS, 0x42ECD91: PINNED_OPTIONS, 0x42ED848: DEAD_WALK, 0x42ED8D7: DEAD_WALK, 0x42ECF35: DEAD_WALK, 0x42ECFC8: DEAD_WALK}
UNREACHED_GROUPS = ((0x42EDC86, 0x42EDCED, "unwind cleanup"), (0x42ED2BA, 0x42ED2FF, "unwind cleanup"), (0x4CE0C1A, 0x4CE0CBE, "unwind cleanup"))
UNREACHED_SINGLE = {}


def count_outcomes(evaluated):
    table = {}
    for name in evaluated:
        table[name] = table.get(name, 0) + 1
    return dict(sorted(table.items()))


def name_outcome(spec):
    kinds = [event[0] for event in spec["events"]]
    if "stop" in spec:
        return "panic"
    if "remove user" in kinds:
        return "ended, user removed"
    if "drop failed" in kinds:
        return "ended, removal found nothing"
    if "copy" in kinds:
        return "ended, user kept"
    if "advance" in kinds:
        return "kept"
    return "nothing"


def analyse(image, full=True, verbose=False):
    harness = Harness(image)
    results, callers, displays, serials, fields = result_cases(), caller_cases(), display_cases(), serial_cases(), field_cases()
    mismatches = []
    outcomes = []
    for row in HANDLERS:
        for case in results:
            trouble = compare_result(harness, row, case)
            if trouble:
                mismatches.append(trouble)
            outcomes.append("handler %s" % name_outcome(spec_result(row, case, harness.relative)))
    for row in CALLERS:
        for case in callers:
            trouble = compare_caller(harness, row, case)
            if trouble:
                mismatches.append(trouble)
            outcomes.append("caller %s" % ("panic" if "stop" in spec_caller(row, case) else "returns"))
    for case in displays:
        trouble = compare_display(harness, None, case)
        if trouble:
            mismatches.append(trouble)
    for case in serials:
        trouble = compare_serial(harness, None, case)
        if trouble:
            mismatches.append(trouble)
    for case in fields:
        trouble = compare_field(harness, None, case)
        if trouble:
            mismatches.append(trouble)
    chains = []
    for row in HANDLERS:
        for label, word in (("tag 3", NICHE_BIT | 3), ("tag 23", NICHE_BIT | 23)):
            case = ResultCase(label, status=STATUS_REJECTED, word=word)
            _, shown = harness.run_chain(row, case)
            text = LITERALS[word ^ NICHE_BIT]
            if shown["text"].split(b',"status":')[1] != b'{"error":"' + text + b'"}}':
                mismatches.append("%s: chain %r" % (label, shown["text"]))
            chains.append({"handler": "%#x" % row["start"], "tag": word ^ NICHE_BIT, "json": shown["text"].decode("ascii")})
    seen = set(harness.machine.seen)
    steps = harness.machine.steps
    relative = harness.relative
    functions = []
    for role, starts in (("handler", [row["start"] for row in HANDLERS]), ("caller", [row["start"] for row in CALLERS]), ("display", [DISPLAY]),
                         ("history serializer", [SERIAL_RECORD]), ("field wrapper", [SERIAL_FIELD]), ("status serializer", [SERIAL_STATUS])):
        for start in starts:
            begin, end = image.exact_fde(start)
            rows = decode_range(image, begin, end)
            functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows),
                              "instructions_stepped": sum(1 for row in rows if row.va in seen)})
    table = display_table(image)
    if len(table) != TAG_COUNT:
        raise EvidenceError("Display table has %d entries" % len(table))
    arms = serial_table(image)
    if len(arms) != len(STATUS_ARMS):
        raise EvidenceError("status table has %d entries" % len(arms))
    statuses = []
    for index, name in enumerate(STATUS_ARMS):
        word = NICHE_BIT | index if index < 3 else 0
        shown = harness.run_serial(SerialCase(name, word=word, text=b"TEXT"))
        statuses.append({"arm": index, "target": "%#x" % arms[index], "word": "%#x" % word if index < 3 else "any word without the top bit", "json": shown["text"].split(b',"status":')[1][:-1].decode("ascii")})
    classes = []
    for tag, target in enumerate(table):
        shown = harness.run_display(NICHE_BIT | tag)
        kind = shown["events"][0][0]
        classes.append({"tag": tag, "target": target, "class": "ends the order" if terminal(tag) else "keeps the order",
                        "kind": "literal" if kind == "write" else "template", "text": shown["text"].decode("ascii"),
                        "template": "%#x" % shown["events"][0][1] if kind == "format" else ""})
    called = [row["start"] for row in HANDLERS] + [row["start"] for row in CALLERS]
    sites = direct_sites(image, called)
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    differences = copy_differences(image, HANDLERS[0]["start"], HANDLERS[1]["start"])
    differences += copy_differences(image, HANDLERS[2]["start"], HANDLERS[3]["start"])
    differences += copy_differences(image, CALLERS[0]["start"], CALLERS[1]["start"])
    results_rows = run_mutants(image, seen, verbose) if full else []
    tally = {key: sum(1 for row in results_rows if row["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "handlers": [{key: ("%#x" % value if isinstance(value, int) else value) for key, value in row.items()} for row in HANDLERS],
        "callers": [{key: "%#x" % value for key, value in row.items()} for row in CALLERS],
        "pairing": check_pairing(image),
        "constants": {"status_rejected": "%#x" % STATUS_REJECTED, "status_ok": "%#x" % STATUS_OK, "terminal_mask": "%#x" % TERMINAL_MASK,
                      "keep_tags": [tag for tag in range(TAG_COUNT) if not terminal(tag)], "end_tags": [tag for tag in range(TAG_COUNT) if terminal(tag)],
                      "row_tag": RECORD_TAG, "record_size": {key: "%#x" % value for key, value in RECORD_SIZE.items()},
                      "fill_stride": {key: "%#x" % value for key, value in FILL_STRIDE.items()}, "result_stride": "%#x" % RESULT_STRIDE,
                      "dex_stride": "%#x" % DEX_STRIDE, "dex_tracker_field": "%#x" % DEX_TRACKER_FIELD, "divisor": DIVISOR},
        "float_arguments": {"%#x" % va: struct.unpack_from("<d", image.blob, image.offset(va))[0] for va in (F64_TEN, F64_HUNDREDTH)},
        "slots": {"%#x" % slot: "%#x" % relative[slot] for slot in (SLOT_DISPLAY, SLOT_FORMAT, SLOT_F64_DISPLAY, STRING_VTABLE + WRITE_STR_FIELD, SLOT_RECORDER)},
        "handler_pins": handler_pins(image),
        "status_slot": {"finish_word": "%#x" % FINISH_WORD, "finish_sites": word_sites(image, [row["advance"] for row in HANDLERS], FINISH_WORD),
                        "halt_word": "%#x" % HALT_WORD, "halt_sites": word_sites(image, HALT_ROWS, HALT_WORD), "arms": statuses},
        "flush_tag_4": flush_body(image),
        "history_keys": {"time": "%#x" % HISTORY_TIME, "twap_id": "%#x" % HISTORY_ID, "state": "0x0", "status": "%#x" % HISTORY_STATUS},
        "chains": chains,
        "stream_name": {"va": "%#x" % STREAM_NAME, "text": bytes(image.blob[image.offset(STREAM_NAME):image.offset(STREAM_NAME) + len(STREAM_TEXT)]).decode("ascii")},
        "locations": [{"slot": "%#x" % slot, "path": image.location(slot, relative)[0], "line": image.location(slot, relative)[1],
                       "column": image.location(slot, relative)[2]} for slot in LOCATIONS],
        "row_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in ROW_MAP],
        "result_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in RESULT_MAP],
        "fill_map": [{"field": field, "perp": perp, "spot": spot, "meaning": meaning} for field, perp, spot, meaning in FILL_MAP],
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"handler": len(results), "caller": len(callers), "display": len(displays), "serial": len(serials), "field": len(fields)},
        "outcomes": count_outcomes(outcomes),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_differences": differences, "_results": results_rows, "_classes": classes,
    }


def reason_for(row):
    if row["result"] == "survived":
        return EQUIVALENT.get(row["va"], "")
    if row["result"] == "unreached":
        for low, high, reason in UNREACHED_GROUPS:
            if low <= row["va"] < high:
                return reason
        return UNREACHED_SINGLE.get(row["va"], "")
    return ""


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    differences = evidence.pop("_differences")
    results = evidence.pop("_results")
    classes = evidence.pop("_classes")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["tag\ttarget\tclass\tkind\ttemplate\ttext"]
    lines += ["%d\t%#x\t%s\t%s\t%s\t%s" % (row["tag"], row["target"], row["class"], row["kind"], row["template"], row["text"].replace("\x40", "[at]")) for row in classes]
    files["error_classes.tsv"] = "\n".join(lines) + "\n"
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
