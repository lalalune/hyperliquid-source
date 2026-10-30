#!/usr/bin/env python3
"""Pin the node #94 user-wide book cancel path from ELF bytes.

Four wrappers find one user in a book's user map, collect that user's order keys, sort them,
hand each key to a removal routine, and can drop the map entry. The real bytes of the wrappers,
the collectors and the B-tree helpers run in a Python evaluator; only the removal routine, the
map removal, the entry drop, the allocator and libc are stubbed. A separately written
specification predicts every stub call. Every conditional is then flipped and every immediate
perturbed to show the run can tell. No objdump or readelf output is parsed, and the binary is
never executed. Standard library only.
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

# name, wrapper, dispatch, chain builder, single builder, chain collect, removal, map removal, entry drop,
# whether the wrapper copies the user to its stack before each removal
Family = collections.namedtuple("Family", "name wrapper dispatch chained single collect remove unmap drop copies_user")
FAMILIES = (
    Family("a", 0x4303B30, 0x431DB10, 0x4451540, 0x4451E80, 0x4886370, 0x42F7890, 0x4945B50, 0x4351D30, True),
    Family("b", 0x43038B0, 0x431DB10, 0x4451540, 0x4451E80, 0x4886370, 0x42F8840, 0x4945B50, 0x4351D30, True),
    Family("c", 0x4303650, 0x431DC50, 0x4450680, 0x4451FF0, 0x486BD50, 0x42F97F0, 0x4942A30, 0x4351C00, False),
    Family("d", 0x4303DB0, 0x431DC50, 0x4450680, 0x4451FF0, 0x486BD50, 0x42FA880, 0x4942A30, 0x4351C00, False),
)
FILTER_COLLECT = 0x48713F0
NEXT_FIRST = 0x4893A20
NEXT_SECOND = 0x4895660
FROM_SORTED = 0x49273C0
BULK_PUSH = 0x4298270
DYING_NEXT = 0x4948F30
RAW_GROW = 0x454F5D0
STATUS_TABLE = 0x7038DC
STATUS_FN = 0x4A9A1A0
BUILDER = 0x4303460
BUILDER_ABSENT = 2
GOT_MALLOC = 0x576DFD8
GOT_FREE = 0x576E010
GOT_MEMCPY = 0x576DFE0
GOT_MEMMOVE = 0x576E0E0
GOT_MEMCMP = 0x576E488
GOT_SORT = 0x5774F50
GOT_PANIC = 0x576E470
GOT_NOUNWIND = 0x576E128
GOT_ALLOC_ERROR = (0x576DFB8, 0x576E020, 0x576E108)
LOCATION_UNWRAP_PARENT = 0x5733F50
LOCATION_NO_FRONT = 0x5732F80
LOCATION_BOOKS = 0x5742338
USER_SIZE = 20
SLOT_STRIDE = 0xF8
BOOK_STRIDE = 0xD8
VACANT = 2
SKIP_FLAG = 1
NONE_WORD = 0x8000000000000000
INSERTION_LIMIT = 20
USER_MAP = 0xB8
SECOND_TREE_VALUE = 0xB8
# Closures that walk books; start, wrapper, whether a post call follows
CLOSURES = ((0x4C63F20, 0x4303650), (0x4C64080, 0x4303B30), (0x4C641C0, 0x43038B0), (0x4C64300, 0x4303DB0))
POST_CALL = 0x42F4680

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x400000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 4000000
# A flipped loop condition can spin; no mutation case comes near this many steps.
MUTANT_STEP_LIMIT = 20000
TALL_STEP_LIMIT = 300000
TALL_PICKS = 3


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
        self.fresh = (b"\xa5" * STACK_SIZE, b"\xa5" * HEAP_SIZE)
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


# ---- memory layout of one case ----

Shape = collections.namedtuple("Shape", "parent keys key_size values value_size parent_index length edges")
SET_SHAPE = Shape(0x0, 0x8, 8, 0x60, 0, 0x60, 0x62, 0x68)
MAP_SHAPE = Shape(0x0, 0x8, 8, 0x60, SECOND_TREE_VALUE, 0x848, 0x84A, 0x850)
USER_SHAPE = Shape(0x370, 0x378, USER_SIZE, 0x0, 0x50, 0x454, 0x456, 0x458)
FANOUT = 12
EDGE_BYTES = FANOUT * 8
BOOK = HEAP_BASE
SLAB = HEAP_BASE + 0x100
USER_ADDR = HEAP_BASE + 0x40
ENTRY_FIRST = 0x20
ENTRY_SECOND = 0x38


def min_keys(height):
    return (1 << (height + 1)) - 1


def max_keys(height):
    return FANOUT ** (height + 1) - 1


def fan_for(count, height, width):
    least, most = min_keys(height - 1), max_keys(height - 1)
    fan = 2
    while count - (fan - 1) > fan * most:
        fan += 1
    widest = min(FANOUT, (count + 1) // (least + 1))
    return max(fan, min(widest, width))


class Entry:
    """One user map value: a set of slot indexes and a second tree keyed by u64."""
    __slots__ = ("user", "first", "first_height", "second", "second_height", "first_len", "second_len", "stale_len")

    def __init__(self, user, first=(), second=(), first_height=0, second_height=0, first_len=None, second_len=None,
                 stale_len=0):
        self.user = user
        self.first = sorted(first)
        self.second = sorted(second)
        self.first_height, self.second_height = first_height, second_height
        self.first_len, self.second_len = first_len, second_len
        self.stale_len = stale_len


class Case:
    __slots__ = ("label", "slab", "entries", "map_height", "width", "target", "flag", "reason", "rcx", "r8",
                 "unmapped", "clobber", "stale_target")

    def __init__(self, label, target, entries=(), slab=(), **fields):
        self.label, self.target = label, target
        self.entries = sorted(entries, key=lambda item: item.user)
        self.slab = list(slab)
        self.map_height, self.width = 0, 2
        self.flag, self.reason = 1, 2
        self.rcx, self.r8 = 0x1234567890ABCDEF, 0xFEDCBA0987654321
        self.unmapped = 7
        self.clobber, self.stale_target = False, False
        for name, value in fields.items():
            setattr(self, name, value)


class Harness:
    """Lay one case out in memory, stub the edges of the path and run the real bytes."""

    def __init__(self, image, family, patches=None):
        self.family = family
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((family.wrapper, family.dispatch, family.chained, family.single, family.collect,
                                  FILTER_COLLECT, NEXT_FIRST, NEXT_SECOND, FROM_SORTED, BULK_PUSH, DYING_NEXT))
        machine.calls = {family.remove: self.on_remove, family.unmap: self.on_unmap, family.drop: self.on_drop,
                         RAW_GROW: self.on_grow}
        machine.slots = {GOT_MALLOC: self.on_malloc, GOT_FREE: self.on_free, GOT_MEMCPY: self.on_copy,
                         GOT_MEMMOVE: self.on_copy, GOT_MEMCMP: self.on_compare, GOT_SORT: self.on_sort,
                         GOT_PANIC: self.on_panic, GOT_NOUNWIND: self.on_panic}
        for slot in GOT_ALLOC_ERROR:
            machine.slots[slot] = self.on_panic
        machine.memory.statics = {slot: slot for slot in machine.slots}
        self.case = None
        self.brk = HEAP_BASE + HEAP_SIZE
        self.live = {}
        self.trace = {}

    def carve(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise EvidenceError("case does not fit the heap")
        return at

    def place(self, shape, items, height, parent, index, stale, fill, width):
        memory = self.machine.memory
        node = self.carve(shape.edges + (EDGE_BYTES if height else 0))
        memory.write(node + shape.parent, 8, parent)
        memory.write(node + shape.parent_index, 2, index)
        own, kids = items, []
        if height:
            fan = fan_for(len(items), height, width)
            base, extra = divmod(len(items) - (fan - 1), fan)
            own, at = [], 0
            for child in range(fan):
                size = base + (1 if child < extra else 0)
                kids.append(items[at:at + size])
                at += size
                if child < fan - 1:
                    own.append(items[at])
                    at += 1
        memory.write(node + shape.length, 2, len(own))
        for at, (key, value) in enumerate(own):
            memory.put_bytes(node + shape.keys + at * shape.key_size, key)
            if fill:
                fill(node + shape.values + at * shape.value_size, value)
        if stale is not None:
            for at in range(len(own), FANOUT - 1):
                memory.put_bytes(node + shape.keys + at * shape.key_size, stale)
        for at, kid in enumerate(kids):
            memory.write(node + shape.edges + at * 8, 8, self.place(shape, kid, height - 1, node, at, stale, fill, width))
        return node

    def tree(self, at, shape, keys, height, field, stale_len, width):
        """Write (root, height, len) at `at` for u64 keys; an empty tree has no root."""
        memory = self.machine.memory
        if not keys:
            memory.write(at, 8, 0)
            memory.write(at + 8, 8, 0x55)
            memory.write(at + 16, 8, stale_len)
            return
        items = [(key.to_bytes(8, "little"), None) for key in keys]
        root = self.place(shape, items, height, 0, 0xFFFF, (0).to_bytes(8, "little"), None, width)
        memory.write(at, 8, root)
        memory.write(at + 8, 8, height)
        memory.write(at + 16, 8, len(keys) if field is None else field)

    def fill_entry(self, at, entry):
        self.tree(at + ENTRY_FIRST, SET_SHAPE, entry.first, entry.first_height, entry.first_len, entry.stale_len,
                  self.case.width)
        self.tree(at + ENTRY_SECOND, MAP_SHAPE, entry.second, entry.second_height, entry.second_len, entry.stale_len,
                  self.case.width)

    def install(self, case):
        self.case = case
        memory = self.machine.memory
        memory.reset(self.brk - HEAP_BASE)
        self.brk = SLAB
        self.live = {}
        self.trace = {"removes": [], "unmapped": [], "dropped": [], "first_alloc": None, "sorts": 0, "panic": None}
        slab = self.carve(SLOT_STRIDE * max(1, len(case.slab)))
        memory.write(BOOK + 0x8, 8, slab)
        memory.write(BOOK + 0x10, 8, len(case.slab))
        for index, (tag, skip, key) in enumerate(case.slab):
            at = slab + index * SLOT_STRIDE
            memory.write(at, 8, tag)
            memory.write(at + 0xB0, 1, skip)
            memory.write(at + 0xD8, 8, key)
        memory.put_bytes(USER_ADDR, case.target)
        if case.entries:
            stale = case.target if case.stale_target else None
            root = self.place(USER_SHAPE, [(item.user, item) for item in case.entries], case.map_height, 0, 0xFFFF,
                              stale, self.fill_entry, case.width)
            memory.write(BOOK + USER_MAP, 8, root)
            memory.write(BOOK + USER_MAP + 8, 8, case.map_height)
            memory.write(BOOK + USER_MAP + 16, 8, len(case.entries))
        else:
            memory.write(BOOK + USER_MAP, 8, 0)

    def run(self, case):
        self.install(case)
        args = {RDI: BOOK, RSI: USER_ADDR, RDX: case.flag, RCX: case.rcx, R8: case.r8, R9: case.reason}
        try:
            self.machine.run(self.family.wrapper, args)
        except Panicked as stop:
            self.trace["panic"] = stop.args[0]
        self.trace["leaked"] = 0 if self.trace["panic"] else len(self.live)
        return self.trace

    # ---- stubs ----

    def on_remove(self, machine):
        regs = machine.regs
        if regs[RDI] != BOOK:
            raise Halt("removal called with another book")
        at_stack = STACK_TOP - STACK_SIZE <= regs[RDX] < STACK_TOP
        if at_stack != self.family.copies_user:
            raise Halt("user passed the wrong way")
        user = machine.memory.bytes_at(regs[RDX], USER_SIZE)
        self.trace["removes"].append((regs[RSI], user, regs[RCX], regs[R8], regs[R9]))
        if self.case.clobber:
            self.scramble(machine)

    def scramble(self, machine):
        """Destroy every source of the collected keys: later removals must not read them."""
        memory = machine.memory
        slab = memory.read(BOOK + 0x8, 8)
        for index in range(len(self.case.slab)):
            memory.write(slab + index * SLOT_STRIDE, 8, VACANT)
            memory.write(slab + index * SLOT_STRIDE + 0xD8, 8, 0)
        memory.write(BOOK + 0x10, 8, 0)
        memory.write(BOOK + USER_MAP, 8, 0)

    def on_unmap(self, machine):
        regs = machine.regs
        if regs[RSI] != BOOK + USER_MAP:
            raise Halt("map removal on another map")
        self.trace["unmapped"].append(machine.memory.bytes_at(regs[RDX], USER_SIZE))
        machine.memory.write(regs[RDI], 8, self.case.unmapped)
        regs[RAX] = regs[RDI]

    def on_drop(self, machine):
        self.trace["dropped"].append(machine.memory.read(machine.regs[RDI], 8))

    def allocate(self, size):
        at = self.carve(size)
        self.live[at] = size
        return at

    def on_malloc(self, machine):
        size = machine.regs[RDI]
        machine.regs[RAX] = self.allocate(size)
        if self.trace["first_alloc"] is None:
            self.trace["first_alloc"] = size

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free of %#x with size %#x does not match an allocation" % (at, size))

    def on_grow(self, machine):
        """Capacity contract only: at least double and at least room for the request."""
        regs, memory = machine.regs, machine.memory
        vector, length, more = regs[RDI], regs[RSI], regs[RDX]
        capacity, old = memory.read(vector, 8), memory.read(vector + 8, 8)
        wanted = max(capacity * 2, length + more, 4)
        fresh = self.allocate(wanted * 8)
        memory.copy(fresh, old, length * 8)
        if self.live.pop(old, None) != capacity * 8:
            raise Halt("vector buffer was not an allocation")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    def on_copy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_compare(self, machine):
        regs = machine.regs
        left = machine.memory.bytes_at(regs[RDI], regs[RDX])
        right = machine.memory.bytes_at(regs[RSI], regs[RDX])
        difference = next((x - y for x, y in zip(left, right) if x != y), 0)
        regs[RAX] = (POISON & ~MASK[4] | (difference & MASK[4])) & MASK[8]

    def on_sort(self, machine):
        regs, memory = machine.regs, machine.memory
        at, count = regs[RDI], regs[RSI]
        values = sorted(memory.read(at + index * 8, 8) for index in range(count))
        for index, value in enumerate(values):
            memory.write(at + index * 8, 8, value)
        self.trace["sorts"] += 1

    def on_panic(self, machine):
        raise Panicked(machine.regs[RDI])


# ---- specification, written from the claim and not from the evaluator ----

def spec(case):
    """Predict the stub trace of the whole path for one case."""
    result = {"removes": [], "unmapped": [], "dropped": [], "first_alloc": None, "sorts": 0, "panic": None, "leaked": 0}
    entry = next((item for item in case.entries if item.user == case.target), None)
    if entry is None:
        return result
    wipe = case.flag & 0xFF != 0
    first_field = len(entry.first) if entry.first_len is None else entry.first_len
    second_field = len(entry.second) if entry.second_len is None else entry.second_len
    if not entry.first:
        first_field = 0
    if not entry.second:
        second_field = 0
    if first_field > len(entry.first) or (wipe and second_field > len(entry.second)):
        result["panic"] = LOCATION_UNWRAP_PARENT
        return result
    collected = []
    for slot in entry.first[:first_field]:
        if slot >= len(case.slab):
            continue
        tag, skip, key = case.slab[slot]
        if tag & MASK[4] == VACANT or (not wipe and skip & 0xFF == SKIP_FLAG):
            continue
        collected.append(key)
    from_first = len(collected)
    if wipe:
        collected += entry.second[:second_field]
    if collected:
        if wipe:
            left = second_field if from_first else second_field - 1
            result["first_alloc"] = 8 * max(4, left + 1)
        else:
            result["first_alloc"] = 0x20
    if len(collected) > INSERTION_LIMIT:
        result["sorts"] = 1
    result["removes"] = [(key, case.target, case.rcx, case.r8, case.reason & 0xFF) for key in sorted(set(collected))]
    if wipe:
        result["unmapped"] = [case.target]
        if case.unmapped != NONE_WORD:
            result["dropped"] = [case.unmapped]
    return result


# ---- cases ----

def user_bytes(index, variant=0):
    """Distinct users; the order of the index is the order of the bytes."""
    return bytes([0x10 + index % 200, index >> 8 & 0xFF]) + bytes((variant + index * 31 + at) & 0xFF for at in range(18))


def order_key(index, salt=1):
    return (index * 0x9E3779B97F4A7C15 + salt) & MASK[8]


def plain_slab(count, salt=1):
    return [(0, 0, order_key(index + 1, salt)) for index in range(count)]


def height_for(count, wanted=None):
    """A valid height for count keys, the wanted one when it fits."""
    if wanted is not None and min_keys(wanted) <= count <= max_keys(wanted):
        return wanted
    height = 0
    while count > max_keys(height):
        height += 1
    return height


def simple_entry(user, slots, second=()):
    return Entry(user, slots, second, height_for(len(slots)), height_for(len(second)))


def lookup_cases():
    rows = []
    slab = plain_slab(4)
    target = user_bytes(5)
    rows.append(Case("empty user map", target, [], slab))
    for count, height in ((1, 0), (2, 0), (11, 0), (12, 1), (13, 1), (40, 1), (130, 1), (150, 2), (300, 2)):
        users = [user_bytes(index * 2 + 1) for index in range(count)]
        for width in (2, FANOUT):
            base = "user map %d height %d width %d" % (count, height, width)
            for probe in sorted({0, min(1, count - 1), count // 2, count - 1, min(5, count - 1), min(10, count - 1)}):
                entries = [simple_entry(user, [0, 1], [probe + 100]) for user in users]
                rows.append(Case(base + " hit", users[probe], entries, slab, map_height=height, width=width))
                below = user_bytes(probe * 2)
                rows.append(Case(base + " miss below", below, entries, slab, map_height=height, width=width))
                above = user_bytes(probe * 2 + 2)
                rows.append(Case(base + " miss above", above, entries, slab, map_height=height, width=width,
                                 stale_target=True))
    # Users that differ only in one byte: the compare must cover all 20.
    for at in (0, 1, 15, 16, 18, 19):
        left = bytearray(user_bytes(9))
        right = bytearray(left)
        left[at], right[at] = 0x7F, 0x80
        for wanted, other in ((bytes(left), bytes(right)), (bytes(right), bytes(left))):
            entries = [simple_entry(other, [0]), simple_entry(wanted, [1])]
            rows.append(Case("users differ at byte %d" % at, wanted, entries, slab))
            rows.append(Case("absent user differs at byte %d" % at, wanted, [simple_entry(other, [0])], slab))
    for low, high in ((0x00, 0xFF), (0xFF, 0x00)):
        left = bytes([low]) + bytes(19)
        right = bytes([high]) + bytes(19)
        rows.append(Case("byte compare is unsigned", left, [simple_entry(right, [0]), simple_entry(left, [1])], slab))
    # Literal users seen at four call sites.
    for user in (bytes([0xFF]) * USER_SIZE, bytes([0xFE]) * USER_SIZE):
        rows.append(Case("literal user", user, [simple_entry(user, [0, 1, 2], [9])], slab))
    return rows


def argument_cases():
    rows = []
    user = user_bytes(3)
    slab = [(0, index % 2, order_key(index + 1)) for index in range(6)]
    for flag in (0, 1, 2, 0x80, 0xFF, 0x100, 0x101, 0xFFFFFF00, 0xFFFFFFFF):
        rows.append(Case("flag %#x" % flag, user, [simple_entry(user, range(6), [5, 3])], slab, flag=flag))
        rows.append(Case("flag %#x, no second" % flag, user, [simple_entry(user, range(6))], slab, flag=flag))
        rows.append(Case("flag %#x, all skipped" % flag, user, [simple_entry(user, [1, 3, 5])], slab, flag=flag))
        rows.append(Case("flag %#x, nothing" % flag, user, [simple_entry(user, ())], slab, flag=flag))
    for reason in list(range(0x12)) + [0x7F, 0x80, 0xFF, 0x100, 0xABCD1202]:
        rows.append(Case("reason %#x" % reason, user, [simple_entry(user, [0, 2])], slab, reason=reason))
    for word in (NONE_WORD, 0, 1, 7, MASK[8] >> 1, NONE_WORD + 1, MASK[8]):
        rows.append(Case("map removal word %#x" % word, user, [simple_entry(user, [0, 2])], slab, unmapped=word))
    return rows


def size_cases():
    rows = []
    user = user_bytes(4)
    sizes = (0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 20, 21, 22, 23, 24, 25, 35, 36, 60, 100, 137, 160)
    for count in sizes:
        slab = plain_slab(max(count, 1), salt=count + 3)
        for width in (2, FANOUT):
            heights = sorted({height_for(count), height_for(count, 1), height_for(count, 2), height_for(count, 3)})
            for height in heights:
                base = "first %d height %d width %d" % (count, height, width)
                entry = Entry(user, range(count), (), height, 0)
                rows.append(Case(base + " wipe", user, [entry], slab, width=width))
                rows.append(Case(base + " keep", user, [entry], slab, width=width, flag=0))
                second = [order_key(index + 1, count + 90) for index in range(count)]
                entry = Entry(user, (), second, 0, height)
                rows.append(Case("second %d height %d width %d" % (count, height, width), user, [entry], slab, width=width))
                entry = Entry(user, range(count), second[:count // 2 + 1], height, height_for(count // 2 + 1))
                rows.append(Case("both %d height %d width %d" % (count, height, width), user, [entry], slab, width=width))
    for left, right in ((3, 4), (4, 0), (0, 4), (1, 3), (2, 2), (5, 0), (20, 0), (21, 0), (20, 1), (10, 11)):
        slab = plain_slab(max(left, 1), salt=left + right)
        second = [order_key(index + 1, 500 + right) for index in range(right)]
        rows.append(Case("split %d %d" % (left, right), user, [simple_entry(user, range(left), second)], slab))
    return rows


def filter_cases():
    rows = []
    user = user_bytes(6)
    slab = plain_slab(4)
    for wipe in (1, 0):
        rows.append(Case("slot at slab length", user, [simple_entry(user, [3, 4])], slab, flag=wipe))
        rows.append(Case("slot past slab length", user, [simple_entry(user, [0, 5, MASK[8]])], slab, flag=wipe))
        rows.append(Case("only stale slots", user, [simple_entry(user, [4, 5])], slab, flag=wipe))
        rows.append(Case("empty slab", user, [simple_entry(user, [0, 1])], [], flag=wipe))
        for tag in (0, 1, 2, 3, 0x100000000, 0x100000002, 0x200000002, 0xFFFFFFFF00000002):
            custom = list(slab)
            custom[1] = (tag, 0, slab[1][2])
            rows.append(Case("slot tag %#x" % tag, user, [simple_entry(user, range(4))], custom, flag=wipe))
            custom = list(slab)
            custom[0] = (tag, 0, slab[0][2])
            rows.append(Case("first slot tag %#x" % tag, user, [simple_entry(user, range(4))], custom, flag=wipe))
        for skip in (0, 1, 2, 3, 0x81, 0xFF):
            custom = list(slab)
            custom[2] = (0, skip, slab[2][2])
            rows.append(Case("slot flag %#x" % skip, user, [simple_entry(user, range(4))], custom, flag=wipe))
            custom = list(slab)
            custom[0] = (0, skip, slab[0][2])
            rows.append(Case("first slot flag %#x" % skip, user, [simple_entry(user, range(4))], custom, flag=wipe))
        same = [(0, 0, 42), (0, 0, 42), (0, 0, 41), (0, 0, 42)]
        rows.append(Case("same key in slots", user, [simple_entry(user, range(4))], same, flag=wipe))
        rows.append(Case("key sort is unsigned", user, [simple_entry(user, range(4))],
                         [(0, 0, NONE_WORD), (0, 0, 1), (0, 0, MASK[8]), (0, 0, NONE_WORD - 1)], flag=wipe))
        rows.append(Case("keys fall as slots rise", user, [simple_entry(user, range(4))],
                         [(0, 0, 40), (0, 0, 30), (0, 0, 20), (0, 0, 10)], flag=wipe))
        rows.append(Case("key zero", user, [simple_entry(user, range(2))], [(0, 0, 0), (0, 0, 5)], flag=wipe))
    rows.append(Case("key in both trees", user, [simple_entry(user, [0, 1], [slab[0][2], 5])], slab))
    rows.append(Case("slot flag ignored by wipe", user, [simple_entry(user, [0, 1])], [(0, 1, 9), (0, 1, 8)]))
    rows.append(Case("second tree keys pass no filter", user, [simple_entry(user, (), [MASK[8], 0])], []))
    rows.append(Case("wider second tree needs no slab", user, [simple_entry(user, (), list(range(30)))], []))
    return rows


def field_cases():
    rows = []
    user = user_bytes(7)
    slab = plain_slab(30)
    for wipe in (1, 0):
        rows.append(Case("first len shorter", user, [Entry(user, range(12), (), 1, 0, first_len=5)], slab, flag=wipe))
        rows.append(Case("first len zero", user, [Entry(user, range(6), (), 0, 0, first_len=0)], slab, flag=wipe))
        rows.append(Case("first len longer", user, [Entry(user, range(6), (), 0, 0, first_len=7)], slab, flag=wipe))
        rows.append(Case("no first root, stale len", user, [Entry(user, (), (), stale_len=9)], slab, flag=wipe))
        rows.append(Case("second len longer", user, [Entry(user, [0], [1, 2], second_len=3)], slab, flag=wipe))
    rows.append(Case("second len shorter", user, [Entry(user, [0], range(10), second_len=4)], slab))
    rows.append(Case("second len zero", user, [Entry(user, [0], range(10), second_len=0)], slab))
    rows.append(Case("no second root, stale len", user, [Entry(user, [0], (), stale_len=9)], slab))
    for count in (3, 8, 21):
        rows.append(Case("source destroyed by the first removal", user, [simple_entry(user, range(count), [100, 99])],
                         slab, clobber=True))
    return rows


def tall_cases():
    rows = []
    user = user_bytes(8)
    for height in (8, 9):
        count = min_keys(height)
        slab = plain_slab(count, salt=height)
        rows.append(Case("tall first %d" % height, user, [Entry(user, range(count), (), height, 0)], slab))
        rows.append(Case("tall first keep %d" % height, user, [Entry(user, range(count), (), height, 0)], slab, flag=0))
        second = [order_key(index + 1, height + 7) for index in range(count)]
        rows.append(Case("tall second %d" % height, user, [Entry(user, (), second, 0, height)], slab))
        rows.append(Case("tall both %d" % height, user, [Entry(user, [0], second, 0, height)], slab))
        rows.append(Case("tall first and one second %d" % height, user,
                         [Entry(user, range(count), second[:1], height, 0)], slab))
    return rows


def random_cases(count):
    draw = lcg(0x301616)
    rows = []
    for index in range(count):
        users = sorted({user_bytes(next(draw) % 60 * 2 + 1) for _ in range(1 + next(draw) % 40)})
        slab = []
        for slot in range(next(draw) % 40):
            pick = next(draw) % 8
            slab.append((VACANT if pick == 0 else pick % 2, 1 if pick < 3 else 0, order_key(next(draw) % 50 + 1)))
        entries = []
        for user in users:
            first = sorted({next(draw) % 50 for _ in range(next(draw) % 30)})
            second = sorted({order_key(next(draw) % 50 + 1) for _ in range(next(draw) % 16)})
            entries.append(Entry(user, first, second, height_for(len(first)), height_for(len(second))))
        target = users[next(draw) % len(users)] if next(draw) % 5 else user_bytes(next(draw) % 120 + 1)
        rows.append(Case("random %d" % index, target, entries, slab, map_height=height_for(len(users)),
                         width=2 + next(draw) % 11, flag=next(draw) % 3, reason=next(draw) % 0x11,
                         unmapped=NONE_WORD if next(draw) % 2 else 3, clobber=next(draw) % 4 == 0))
    return rows


def all_cases(random_count=200):
    return lookup_cases() + argument_cases() + size_cases() + filter_cases() + field_cases() + tall_cases() + \
        random_cases(random_count)


def compare(harness, case):
    predicted = spec(case)
    try:
        actual = harness.run(case)
    except (Halt, EvidenceError) as error:
        return "%s: machine stopped: %s" % (case.label, error)
    for key, value in predicted.items():
        if key == "first_alloc" and predicted["panic"]:
            continue
        if actual[key] != value:
            return "%s: %s differs: %r, predicted %r" % (case.label, key, actual[key], value)
    return None


def run_family(image, family, cases, stop_first=False, patches=None):
    harness = Harness(image, family, patches)
    failures = []
    for case in cases:
        failure = compare(harness, case)
        if failure:
            failures.append(failure)
            if stop_first:
                break
    return failures, harness.machine.seen, harness.machine.steps


# ---- book-walking closures ----

ClosureCase = collections.namedtuple("ClosureCase", "label mode key books post reason")
CLOSURE_HOST = HEAP_BASE + 0x2000
CLOSURE_BOOKS = HEAP_BASE + 0x3000
CLOSURE_LIST = HEAP_BASE + 0x100
CLOSURE_POST_ARG = 0x4444444444444444
CLOSURE_CTX = (0x5555555555555555, 0x6666666666666666)
CLOSURE_USER = bytes(range(0x30, 0x30 + USER_SIZE))
CLOSURE_MODULO = {0x4C63F20: 10000, 0x4C64300: 10000}
CLOSURE_POST = {0x4C63F20: 0x42F4000, 0x4C64080: POST_CALL, 0x4C641C0: 0x42F4BF0, 0x4C64300: 0x42F5160}


class ClosureRun:
    """One closure under one set of patches; the machine is reused across cases."""

    def __init__(self, image, start, wrapper, patches=None):
        self.start = start
        self.calls = []
        self.machine = Machine(image, patches)
        self.machine.calls = {wrapper: self.on_wrapper, CLOSURE_POST[start]: self.on_post}
        self.machine.slots = {GOT_PANIC: self.on_panic}
        self.machine.memory.statics = {GOT_PANIC: GOT_PANIC}

    def on_wrapper(self, host):
        regs = host.regs
        self.calls.append(("wrapper", regs[RDI], host.memory.bytes_at(regs[RSI], USER_SIZE), regs[RDX] & MASK[4], regs[RCX],
                           regs[R8], regs[R9]))

    def on_post(self, host):
        regs = host.regs
        self.calls.append(("post", regs[RDI], host.memory.bytes_at(regs[RSI], USER_SIZE), regs[RDX], regs[RCX], regs[R8], regs[R9]))

    def on_panic(self, host):
        raise Panicked(host.regs[RDI])

    def run(self, case):
        memory = self.machine.memory
        self.calls = []
        memory.reset()
        memory.write(CLOSURE_LIST + 0x8, 8, CLOSURE_BOOKS)
        memory.write(CLOSURE_LIST + 0x10, 8, case.books)
        fields = (case.mode, case.key, CLOSURE_LIST, CLOSURE_POST_ARG, CLOSURE_CTX[0], CLOSURE_CTX[1])
        for index, value in enumerate(fields):
            memory.write(CLOSURE_HOST + index * 8, 8, value)
        memory.put_bytes(CLOSURE_HOST + 0x30, CLOSURE_USER)
        memory.write(CLOSURE_HOST + 0x44, 1, case.post)
        memory.write(CLOSURE_HOST + 0x45, 1, case.reason)
        try:
            self.machine.run(self.start, {RDI: CLOSURE_HOST})
        except Panicked as stop:
            return self.calls, stop.args[0]
        return self.calls, None


def spec_closure(start, case):
    calls = []
    modulo = CLOSURE_MODULO.get(start)
    if case.mode == 1:
        index = case.key % modulo if modulo else case.key
        if index >= case.books:
            return [], LOCATION_BOOKS
        chosen = [index]
    else:
        chosen = range(case.books)
    for index in chosen:
        calls.append(("wrapper", CLOSURE_BOOKS + index * BOOK_STRIDE, CLOSURE_USER, 1, CLOSURE_CTX[0], CLOSURE_CTX[1], case.reason))
    if case.post:
        calls.append(("post", CLOSURE_POST_ARG, CLOSURE_USER, case.mode, case.key, CLOSURE_CTX[0], CLOSURE_CTX[1]))
    return calls, None


def closure_cases():
    rows = []
    for mode in (0, 1, 2, 3):
        for books in (0, 1, 2, 5):
            for key in (0, 1, 4, 5, 9999, 10000, 10001, 10004, 20003, 2 ** 40 + 2):
                for post in (0, 1, 2):
                    rows.append(ClosureCase("mode %d books %d key %d post %d" % (mode, books, key, post), mode, key, books, post,
                                            0xC + post))
    return rows


def compare_closures(image, start, wrapper, cases, patches=None, stop_first=False):
    failures = []
    run = ClosureRun(image, start, wrapper, patches)
    if patches:
        run.machine.step_limit = MUTANT_STEP_LIMIT
    for case in cases:
        try:
            actual = run.run(case)
        except (Halt, EvidenceError) as error:
            actual = ("stopped", str(error))
        if actual != spec_closure(start, case):
            failures.append(case.label)
            if stop_first:
                break
    return failures


# ---- the filtered builder outside the wrappers ----

def read_set(memory, root, height):
    """In-order keys of a produced u64 set."""
    count = memory.read(root + SET_SHAPE.length, 2)
    keys = []
    for index in range(count + 1):
        if height:
            keys += read_set(memory, memory.read(root + SET_SHAPE.edges + index * 8, 8), height - 1)
        if index < count:
            keys.append(memory.read(root + SET_SHAPE.keys + index * 8, 8))
    return keys


def run_builder(harness, case):
    """Run 0x4303460 for one case. Return a tuple of what it produced."""
    harness.install(case)
    out = harness.carve(0x70)
    memory = harness.machine.memory
    try:
        harness.machine.run(BUILDER, {RDI: out, RSI: BOOK, RDX: USER_ADDR})
    except Panicked as stop:
        return ("panic", stop.args[0])
    tag = memory.read(out, 8)
    if tag == BUILDER_ABSENT:
        return ("absent",)
    root, height, size = memory.read(out + 0x10, 8), memory.read(out + 0x18, 8), memory.read(out + 0x40, 8)
    if (memory.read(out + 0x8, 8), memory.read(out + 0x28, 8), memory.read(out + 0x20, 8)) != (0, 0, tag):
        return ("bad handles",)
    if (memory.read(out + 0x30, 8), memory.read(out + 0x38, 8)) != (root, height):
        return ("bad back handle",)
    keys = read_set(memory, root, height) if root else []
    return ("found", tag, keys, size, memory.read(out + 0x48, 8), memory.bytes_at(out + 0x50, USER_SIZE))


def spec_builder(case):
    entry = next((item for item in case.entries if item.user == case.target), None)
    if entry is None:
        return ("absent",)
    field = len(entry.first) if entry.first_len is None else entry.first_len
    if entry.first and field > len(entry.first):
        return ("panic", LOCATION_UNWRAP_PARENT)
    keys = set()
    for slot in entry.first[:field]:
        if slot < len(case.slab):
            tag, skip, key = case.slab[slot]
            if tag & MASK[4] != VACANT and skip & 0xFF != SKIP_FLAG:
                keys.add(key)
    return ("found", 1 if keys else 0, sorted(keys), len(keys), BOOK, case.target)


def builder_cases():
    return lookup_cases() + filter_cases() + field_cases() + size_cases()[:160] + random_cases(120)


def compare_builder(harness, case):
    try:
        actual = run_builder(harness, case)
    except (Halt, EvidenceError) as error:
        return "%s: machine stopped: %s" % (case.label, error)
    if actual != spec_builder(case):
        return "%s: builder differs" % case.label
    return None


def builder_harness(image, patches=None):
    harness = Harness(image, FAMILIES[2], patches)
    harness.machine.real = harness.machine.real | {BUILDER}
    return harness


# ---- static census ----

CHEAP_STEPS = 3000
CHEAP_CASES = 40
FAMILY_CASE_STEPS = 3000
# Jumps out of the four peer-cancel routines, for one more reading of the reason byte.
PEER_SITES = (0x4305055, 0x43051A5, 0x43052F5, 0x4305445)
NONE_WORD_MOV = b"\x00\x00\x00\x00\x00\x00\x00\x80"


def none_word_loads(image, start):
    """Count movabs of the none word in one FDE."""
    begin, end = image.exact_fde(start)
    body = bytes(image.blob[image.offset(begin):image.offset(end)])
    count, at = 0, body.find(NONE_WORD_MOV)
    while at >= 0:
        count += at >= 2 and body[at - 2] in (0x48, 0x49) and 0xB8 <= body[at - 1] <= 0xBF
        at = body.find(NONE_WORD_MOV, at + 1)
    return count


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


# Bytes that build a literal user just before a call; each pair is (va, hex bytes).
LITERAL_USERS = {
    0x42D3E06: ("all 0xff", ((0x42D3DCC, "660f76c0"), (0x42D3DD9, "c78424e0000000ffffffff"))),
    0x42D2846: ("all 0xff", ((0x42D280C, "660f76c0"), (0x42D2819, "c78424e0000000ffffffff"))),
    0x42E0B95: ("all 0xfe", ((0x42E0B72, "c7442450fefefefe"),)),
    0x42E1675: ("all 0xfe", ((0x42E1652, "c7442450fefefefe"),)),
}
LITERAL_CONSTANT = 0x206BE0


def literal_user(image, site):
    item = LITERAL_USERS.get(site)
    if item is None:
        return ""
    for va, expected in item[1]:
        at = image.offset(va)
        if bytes(image.blob[at:at + len(expected) // 2]).hex() != expected:
            raise EvidenceError("literal user bytes differ at %#x" % va)
    return item[0]


def census(image):
    roles = [(item.wrapper, "wrapper " + item.name) for item in FAMILIES]
    roles += [(0x431DB10, "dispatch a b"), (0x431DC50, "dispatch c d"), (0x4451540, "chain builder a b"),
              (0x4450680, "chain builder c d"), (0x4451E80, "filter builder a b"), (0x4451FF0, "filter builder c d"),
              (BUILDER, "filtered builder"), (0x4886370, "chain collect a b"), (0x486BD50, "chain collect c d"), (FILTER_COLLECT, "filter collect")]
    targets = [target for target, _ in roles]
    sites = direct_sites(image, targets)
    refs = rip_references(image, targets)
    rows, edges = [], []
    for target, role in roles:
        edges.append({"target": target, "role": role, "direct_sites": len(sites[target]), "address_refs": refs[target],
                      "fdes": sorted({image.fde(site)[0] for site, _ in sites[target]})})
    for family in FAMILIES:
        for site, opcode in sites[family.wrapper]:
            flag_at, flag = last_writer(image, site, RDX)
            reason_at, reason = last_writer(image, site, R9)
            start, end = image.fde(site)
            rows.append({"wrapper": family.name, "site": site, "opcode": opcode, "fde": start, "fde_end": end,
                         "flag_at": flag_at, "flag": flag, "reason_at": reason_at, "reason": reason,
                         "user": literal_user(image, site)})
    return rows, edges


# ---- status names, for reading the reason bytes ----

def status_names(image, table=STATUS_TABLE):
    """Follow the jump table of the status serializer: byte value to (arm, name)."""
    start, end = image.exact_fde(STATUS_FN)
    base = image.offset(table)

    def read(va, count):
        at = image.offset(va)
        return bytes(image.blob[at:at + count])

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
        rows.append({"value": len(rows), "arm": arm, "name": read(text, following.b[1]).decode("ascii")})
    return rows


# ---- structure of the bytes ----

def normalized_hash(image, start, rows):
    """Hash the body with rel32 fields and rip-relative displacements zeroed."""
    body = bytearray(image.blob[image.offset(start):image.offset(rows[-1].next)])
    for row in rows:
        if row.op in ("call", "jmp", "jcc") and row.imm_size == 4:
            at = row.va - start + row.imm_at
            body[at:at + 4] = bytes(4)
        if row.rip_at is not None:
            at = row.va - start + row.rip_at
            body[at:at + 4] = bytes(4)
    return hashlib.sha256(bytes(body)).hexdigest()


FUNCTION_ROLES = (
    (0x4303650, "wrapper c"), (0x43038B0, "wrapper b"), (0x4303B30, "wrapper a"), (0x4303DB0, "wrapper d"),
    (BUILDER, "filtered builder"), (0x431DB10, "dispatch a b"), (0x431DC50, "dispatch c d"), (0x4451540, "chain builder a b"),
    (0x4450680, "chain builder c d"), (0x4451E80, "filter builder a b"), (0x4451FF0, "filter builder c d"),
    (0x4886370, "chain collect a b"), (0x486BD50, "chain collect c d"), (FILTER_COLLECT, "filter collect"),
    (NEXT_FIRST, "first tree next"), (NEXT_SECOND, "second tree next"), (FROM_SORTED, "set from sorted vector"),
    (BULK_PUSH, "B-tree bulk push"), (DYING_NEXT, "set into_iter next"),
)
MUTATED = (0x4303B30, 0x431DB10, 0x4451540, 0x4451E80, 0x4886370, FILTER_COLLECT)


def decode_functions(image):
    decoded = {}
    for start, role in FUNCTION_ROLES:
        begin, end = image.exact_fde(start)
        decoded[start] = (role, end, decode_range(image, begin, end))
    return decoded


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


def run_mutants(image, family, tiers, decoded, reachable, shared):
    """Try the small tier on every mutant, then the tall tier on code only that tier reaches."""
    (cheap, cheap_seen), (tall, tall_seen) = tiers
    cheap, tall = list(cheap), list(tall)
    results = []
    harness = Harness(image, family)
    machine = harness.machine
    machine.cache = dict(shared)
    for start in MUTATED:
        for va, at, kind in mutation_targets(decoded[start][2]):
            if va in reachable and va in cheap_seen:
                cases, machine.step_limit = cheap, MUTANT_STEP_LIMIT
            elif va in reachable and va in tall_seen:
                cases, machine.step_limit = tall, TALL_STEP_LIMIT
            else:
                results.append({"va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            original = machine.cache.pop(va, None)
            machine.patches = mutate_patch(image, va, at)
            # A mutant may write past the last case's heap use, so its first and next runs start clean.
            harness.brk = HEAP_BASE + HEAP_SIZE
            failed = None
            for index, case in enumerate(cases):
                failed = compare(harness, case)
                if failed:
                    # The next mutant is often near this one, so it tries this case first.
                    cases.insert(0, cases.pop(index))
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            if original is not None:
                machine.cache[va] = original
            harness.brk = HEAP_BASE + HEAP_SIZE
            results.append({"va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed.split(":")[0] if failed else ""})
    return results


def closure_mutant_cases():
    """A spread of every mode, then single-book calls so the stride and the modulo decide the result."""
    rows = closure_cases()
    return rows[::21] + [case for case in rows if case.mode == 1 and case.books == 5 and case.post == 0]


def closure_mutants(image):
    results = []
    cases = closure_mutant_cases()
    for start, wrapper in CLOSURES:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        for va, at, kind in mutation_targets(rows):
            failed = compare_closures(image, start, wrapper, cases, mutate_patch(image, va, at), True)
            results.append({"va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed[0] if failed else ""})
    return results


def mutation_tiers(image, cases, costs):
    """Split the cases: a cheap wide tier first, cheapest of each label group leading, then the tall ones."""
    ranked = sorted(range(len(cases)), key=lambda index: (costs[index], index))
    first, rest, seen = [], [], set()
    for index in ranked:
        key = " ".join(cases[index].label.split()[:2])
        (rest if key in seen else first).append(index)
        seen.add(key)
    allowed = [index for index in rest if costs[index] <= CHEAP_STEPS]
    room = max(0, CHEAP_CASES - len(first))
    spread = allowed[::max(1, len(allowed) // max(1, room))][:room]
    cheap = [cases[index] for index in first + spread]
    harness = Harness(image, FAMILIES[0])
    for case in cheap:
        compare(harness, case)
    # Walks past the first leaf need taller trees: the cheapest of each flag, then every height 8 and 9 tree.
    above = [index for index in ranked if costs[index] > CHEAP_STEPS]
    keep = [index for index in above if cases[index].flag == 0][:TALL_PICKS]
    wipe = [index for index in above if cases[index].flag == 1][:TALL_PICKS]
    named = [index for index in above if cases[index].label.startswith("tall ")]
    tall = [cases[index] for index in sorted(set(keep + wipe + named), key=lambda index: (costs[index], index))]
    second = Harness(image, FAMILIES[0])
    for case in tall:
        compare(second, case)
    return (cheap, harness.machine.seen), (tall, second.machine.seen)


def analyse(image, full=True):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    decoded = decode_functions(image)
    cases = all_cases() if full else lookup_cases()[:40] + argument_cases()[:40] + filter_cases()[:40]
    seen = set()
    totals = {"steps": 0, "mismatches": 0, "cases": {}}
    costs = {}
    shared = {}
    for position, family in enumerate(FAMILIES):
        chosen = cases if position == 0 else [case for index, case in enumerate(cases)
                                              if costs[index] <= FAMILY_CASE_STEPS]
        harness = Harness(image, family)
        failures = []
        for index, case in enumerate(chosen):
            before = harness.machine.steps
            failure = compare(harness, case)
            if failure:
                failures.append(failure)
            if position == 0:
                costs[index] = harness.machine.steps - before
        if failures:
            raise EvidenceError("family %s: %d mismatches, first %s" % (family.name, len(failures), failures[0]))
        seen |= harness.machine.seen
        totals["steps"] += harness.machine.steps
        totals["cases"][family.name] = len(chosen)
        if position == 0:
            shared = harness.machine.cache
    closures = []
    for start, wrapper in CLOSURES:
        failed = compare_closures(image, start, wrapper, closure_cases())
        if failed:
            raise EvidenceError("closure %#x: %d mismatches, first %s" % (start, len(failed), failed[0]))
        begin, end = image.exact_fde(start)
        closures.append({"start": begin, "end": end, "wrapper": wrapper, "post": CLOSURE_POST[start],
                         "modulo": CLOSURE_MODULO.get(start, 0), "cases": len(closure_cases())})
    harness = builder_harness(image)
    chosen = builder_cases() if full else builder_cases()[:60]
    found = collections.Counter()
    for case in chosen:
        failure = compare_builder(harness, case)
        if failure:
            raise EvidenceError("builder: " + failure)
        found[spec_builder(case)[0]] += 1
    seen |= harness.machine.seen
    totals["steps"] += harness.machine.steps
    totals["builder"] = dict(sorted(found.items()))
    functions = []
    for start, (role, end, rows) in decoded.items():
        begin = image.offset(start)
        functions.append({"role": role, "start": start, "end": end, "size": end - start, "instructions": len(rows),
                          "executed": sum(1 for row in rows if row.va in seen),
                          "sha256": hashlib.sha256(bytes(image.blob[begin:begin + end - start])).hexdigest(),
                          "normalized_sha256": normalized_hash(image, start, rows)})
    mutations = []
    tier_sizes = {}
    if full:
        tiers = mutation_tiers(image, cases, costs)
        tier_sizes = {"small": len(tiers[0][0]), "tall": len(tiers[1][0]), "closure": len(closure_mutant_cases())}
        mutations = run_mutants(image, FAMILIES[0], tiers, decoded, seen, shared)
        mutations += closure_mutants(image)
    calls, edges = census(image)
    names = status_names(image)
    peers = {"%#x" % site: hex_or_blank(last_writer(image, site, R9)[1]) for site in PEER_SITES}
    none_loads = {"%#x" % start: none_word_loads(image, start) for start in (0x4945B50, 0x4942A30)}
    locations = {"%#x" % slot: "%s:%d:%d" % image.location(slot, relative)
                 for slot in (LOCATION_UNWRAP_PARENT, LOCATION_NO_FRONT, LOCATION_BOOKS)}
    constant = bytes(image.blob[image.offset(LITERAL_CONSTANT):image.offset(LITERAL_CONSTANT) + 16]).hex()
    return {"functions": functions, "closures": closures, "calls": calls, "edges": edges, "totals": totals,
            "mutations": mutations, "tiers": tier_sizes, "locations": locations, "literal_constant": constant, "names": names,
            "none_loads": none_loads, "peers": peers}


def unreached_group(va):
    for first, last, reason in UNREACHED_GROUPS:
        if first <= va <= last:
            return reason
    raise EvidenceError("unreached mutant outside every known group: %#x" % va)


def hex_or_blank(value):
    return "" if value is None else "%#x" % value


def render(evidence):
    files = {}
    rows = ["role\tstart\tend\tsize\tinstructions\texecuted\tsha256\tnormalized_sha256"]
    for item in evidence["functions"]:
        rows.append("\t".join((item["role"], "%#x" % item["start"], "%#x" % item["end"], str(item["size"]),
                               str(item["instructions"]), str(item["executed"]), item["sha256"], item["normalized_sha256"])))
    files["functions.tsv"] = "\n".join(rows) + "\n"
    names = {item["value"]: item["name"] for item in evidence["names"]}
    rows = ["wrapper\tcall_site\topcode\tcaller_fde\tcaller_fde_end\tflag_write_at\tflag\treason_write_at\treason\tstatus_name_at_that_value\tliteral_user"]
    for item in evidence["calls"]:
        rows.append("\t".join((item["wrapper"], "%#x" % item["site"], "%#x" % item["opcode"], "%#x" % item["fde"],
                               "%#x" % item["fde_end"], hex_or_blank(item["flag_at"]), hex_or_blank(item["flag"]),
                               hex_or_blank(item["reason_at"]),
                               hex_or_blank(item["reason"]) if item["reason"] is not None else "register",
                               names.get(item["reason"], ""), item["user"])))
    files["callers.tsv"] = "\n".join(rows) + "\n"
    rows = ["target\trole\tdirect_sites\taddress_refs\tcaller_fdes"]
    for item in evidence["edges"]:
        rows.append("\t".join(("%#x" % item["target"], item["role"], str(item["direct_sites"]), str(item["address_refs"]),
                               ",".join("%#x" % value for value in item["fdes"]))))
    files["edges.tsv"] = "\n".join(rows) + "\n"
    rows = ["value\tarm\tname"]
    for item in evidence["names"]:
        rows.append("\t".join(("%#x" % item["value"], "%#x" % item["arm"], item["name"])))
    files["status_names.tsv"] = "\n".join(rows) + "\n"
    rows = ["closure\tend\twrapper\tpost_call\tindex_modulo\tcases"]
    for item in evidence["closures"]:
        rows.append("\t".join(("%#x" % item["start"], "%#x" % item["end"], "%#x" % item["wrapper"], "%#x" % item["post"],
                               str(item["modulo"]), str(item["cases"]))))
    files["closures.tsv"] = "\n".join(rows) + "\n"
    rows = ["va\tkind\tresult\tfirst_detecting_case\tnote"]
    for item in evidence["mutations"]:
        note = unreached_group(item["va"]) if item["result"] == "unreached" else ""
        rows.append("\t".join(("%#x" % item["va"], item["kind"], item["result"], item["by"], note)))
    files["mutations.tsv"] = "\n".join(rows) + "\n"
    summary = {key: 0 for key in ("killed", "survived", "unreached")}
    for item in evidence["mutations"]:
        summary[item["result"]] += 1
    flags = collections.Counter(hex_or_blank(item["flag"]) for item in evidence["calls"])
    reasons = collections.Counter(hex_or_blank(item["reason"]) if item["reason"] is not None else "register"
                                  for item in evidence["calls"])
    document = {
        "target": {"path": "artifacts/node/94/hl-node", "sha256": SHA256},
        "cases_per_family": evidence["totals"]["cases"],
        "builder_cases": evidence["totals"]["builder"],
        "instructions_stepped": evidence["totals"]["steps"],
        "mismatches": evidence["totals"]["mismatches"],
        "call_sites": len(evidence["calls"]),
        "flag_values": dict(sorted(flags.items())),
        "reason_values": dict(sorted(reasons.items())),
        "mutations": summary,
        "mutation_case_tiers": evidence["tiers"],
        "mutated_functions": ["%#x" % start for start in MUTATED] + ["%#x" % row[0] for row in CLOSURES],
        "locations": evidence["locations"],
        "literal_constant_0x206be0": evidence["literal_constant"],
        "none_word_loads_in_map_removal": evidence["none_loads"],
        "reason_at_peer_cancel_jumps": evidence["peers"],
        "tree_shapes": {name: {field: "%#x" % value for field, value in shape._asdict().items()}
                        for name, shape in (("set", SET_SHAPE), ("second_map", MAP_SHAPE), ("user_map", USER_SHAPE))},
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
    evidence = analyse(load_image())
    files = render(evidence)
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
