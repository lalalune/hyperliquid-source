#!/usr/bin/env python3
"""Static #94 Decimal division replay; decoder adapted from decimal_scaled_u64.py (MIT)."""
import argparse,bisect,collections,csv,hashlib,json,pathlib,re,struct,sys
from fractions import Fraction
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index, fde_extents
U64=(1<<64)-1
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI=range(8)
R8,R9,R10,R11,R12,R13,R14,R15=range(8,16)
CALLEE_SAVED=(RBX,RBP,R12,R13,R14,R15)
STACK=0x6f000000
RETURN_MARK=0x60000000
MAX_STEPS=20000
CALLER_SAVED=(RAX,RCX,RDX,RSI,RDI,R8,R9,R10,R11)
class ToolError(Exception): pass
def fail(message): raise ToolError(message)
class Done(Exception):
 def __init__(self, how, where): self.how,self.where=how,where
class Image:
 def __init__(self,data):
  self.data=data; s=elf_index.sections(data); self.sections={x["name"]:(x["address"],x["offset"],x["size"]) for x in s if x["type"]!=8}; self.text_va,self.text_off,self.text_size=self.sections[".text"]; self.rodata=self.sections[".rodata"]; _, f=fde_extents.eh_frame_records(data,s); self.fde_details={x["start"]:x for x in f}; self.fdes=sorted((x["start"],x["end"]) for x in f); self.starts=[x[0] for x in self.fdes]; _,off,size=self.sections[".rela.dyn"];self.slots={a:v for a,i,v in struct.iter_unpack("<QQq",data[off:off+size]) if i&0xffffffff==8};self.panic_targets={self.slots[x] for x in (0x576e098,0x576e118,0x576e150,0x576e1b0,0x576e1b8,0x576e470)};self.note_target=0;self.cache={}
 def fde_of(self,va):
  i=bisect.bisect_right(self.starts,va)-1
  if i<0 or va>=self.fdes[i][1]:fail("no fde")
  return self.fdes[i]
 def fetch(self,va):
  if self.fde_of(va)[0] not in (0x4eae280,0x4eae400,0x4eafb60): fail(f"execution outside selected FDEs at {va:#x}")
  if va not in self.cache:self.cache[va]=decode(self.data,va-self.text_va+self.text_off,va)
  return self.cache[va]
 def read_only(self,va):
  a,o,n=self.rodata
  return self.data[va-a+o] if a<=va<a+n else None
def modrm_length(data, p):
    modrm = data[p]
    mod, rm = modrm >> 6, modrm & 7
    length = 1
    if mod == 3:
        return length
    if rm == 4:
        length += 1
        if mod == 0 and data[p + 1] & 7 == 5:
            length += 4
    if mod == 0 and rm == 5:
        length += 4
    elif mod == 1:
        length += 1
    elif mod == 2:
        length += 4
    return length


MODRM_ONE = (set(range(0x00, 0x04)) | set(range(0x08, 0x0c)) | set(range(0x10, 0x14)) | set(range(0x18, 0x1c))
             | set(range(0x20, 0x24)) | set(range(0x28, 0x2c)) | set(range(0x30, 0x34)) | set(range(0x38, 0x3c))
             | set(range(0x84, 0x90)) | set(range(0xd8, 0xe0)) | {0x63, 0xd0, 0xd1, 0xd2, 0xd3, 0xfe, 0xff})
PLAIN_ONE = (set(range(0x50, 0x60)) | set(range(0x90, 0xa0))
             | {0xa4, 0xa5, 0xa6, 0xa7, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xc3, 0xc9, 0xcb, 0xcc, 0xcf,
                0xf4, 0xf5, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd})
PLAIN_TWO = {0x05, 0x06, 0x08, 0x09, 0x0b, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x77, 0xa0, 0xa1, 0xa2, 0xa8,
             0xa9, 0xaa} | set(range(0xc8, 0xd0))
PREFIXES = {0x66, 0x67, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0xf0}


class Insn:
    """One decoded instruction: position, opcode key, REX byte and ModRM offset."""

    __slots__ = ("va", "off", "size", "key", "rex", "modrm", "target", "wide16", "rep")

    def __init__(self, va, off, size, key, rex, modrm, target, wide16, rep):
        self.va, self.off, self.size, self.key = va, off, size, key
        self.rex, self.modrm, self.target, self.wide16, self.rep = rex, modrm, target, wide16, rep


def decode(data, off, va):
    """Decode the length of one 64-bit instruction, or raise on an unknown form."""
    p = off
    wide16 = False
    rep = 0
    while data[p] in PREFIXES:
        wide16 = wide16 or data[p] == 0x66
        if data[p] in (0xf2, 0xf3):
            rep = data[p]
        p += 1
    rex = 0
    if 0x40 <= data[p] <= 0x4f:
        rex = data[p]
        p += 1
    op = data[p]
    p += 1
    iz = 2 if wide16 else 4

    def done(end, key, modrm=None, rel=None):
        size = end - off
        target = None if rel is None else va + size + rel
        return Insn(va, off, size, key, rex, modrm, target, wide16, rep)

    if op in (0xc4, 0xc5, 0x62):
        if op == 0xc5:
            space = 1
            p += 1
        elif op == 0xc4:
            space = data[p] & 0x1f
            p += 2
        else:
            space = data[p] & 7
            p += 3
        code = data[p]
        p += 1
        if space == 1 and code == 0x77:
            return done(p, ("vex", code))
        p += modrm_length(data, p)
        if space == 3 or (space == 1 and code in (0x70, 0x71, 0x72, 0x73, 0xc2, 0xc4, 0xc5, 0xc6)):
            p += 1
        return done(p, ("vex", code))
    if op == 0x0f:
        two = data[p]
        p += 1
        if two in (0x38, 0x3a):
            three = data[p]
            p += 1
            modrm = p
            p += modrm_length(data, p) + (1 if two == 0x3a else 0)
            return done(p, (0x0f, two, three), modrm)
        if 0x80 <= two <= 0x8f:
            return done(p + 4, (0x0f, two), rel=struct.unpack_from("<i", data, p)[0])
        if two in PLAIN_TWO:
            return done(p, (0x0f, two))
        modrm = p
        p += modrm_length(data, p)
        if two in (0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
            p += 1
        return done(p, (0x0f, two), modrm)
    if op in MODRM_ONE:
        modrm = p
        return done(p + modrm_length(data, p), op, modrm)
    if op in (0x69, 0x81, 0xc7):
        modrm = p
        return done(p + modrm_length(data, p) + iz, op, modrm)
    if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6):
        modrm = p
        return done(p + modrm_length(data, p) + 1, op, modrm)
    if op in (0xf6, 0xf7):
        modrm = p
        imm = 0
        if (data[p] >> 3) & 7 in (0, 1):
            imm = 1 if op == 0xf6 else iz
        return done(p + modrm_length(data, p) + imm, op, modrm)
    if (op < 0x40 and op & 7 == 4) or op in (0xa8, 0x6a, 0xcd) or 0xb0 <= op <= 0xb7:
        return done(p + 1, op)
    if (op < 0x40 and op & 7 == 5) or op in (0xa9, 0x68):
        return done(p + iz, op)
    if op in PLAIN_ONE:
        return done(p, op)
    if 0xb8 <= op <= 0xbf:
        return done(p + (8 if rex & 8 else iz), op)
    if 0x70 <= op <= 0x7f or op in (0xeb, 0xe0, 0xe1, 0xe2, 0xe3):
        return done(p + 1, op, rel=struct.unpack_from("<b", data, p)[0])
    if op in (0xe8, 0xe9):
        return done(p + 4, op, rel=struct.unpack_from("<i", data, p)[0])
    if op == 0xc2:
        return done(p + 2, op)
    if op in (0xa0, 0xa1, 0xa2, 0xa3):
        return done(p + 8, op)
    fail(f"unknown opcode {op:#x} at {va:#x}")


def sweep(image, start, end):
    """Linear sweep of one FDE range. Must stop exactly on the FDE end."""
    rows = []
    va = start
    delta = image.text_off - image.text_va
    while va < end:
        insn = decode(image.data, va + delta, va)
        rows.append(insn)
        va += insn.size
    if va != end:
        fail(f"sweep of {start:#x} ended at {va:#x}, FDE ends at {end:#x}")
    return rows


COND = {0: lambda f: f[3], 1: lambda f: not f[3], 2: lambda f: f[0], 3: lambda f: not f[0],
        4: lambda f: f[1], 5: lambda f: not f[1], 6: lambda f: f[0] or f[1], 7: lambda f: not (f[0] or f[1]),
        8: lambda f: f[2], 9: lambda f: not f[2], 12: lambda f: f[2] != f[3], 13: lambda f: f[2] == f[3],
        14: lambda f: f[1] or f[2] != f[3], 15: lambda f: not f[1] and f[2] == f[3]}
USES = {0: (3,), 1: (3,), 2: (0,), 3: (0,), 4: (1,), 5: (1,), 6: (0, 1), 7: (0, 1), 8: (2,), 9: (2,),
        12: (2, 3), 13: (2, 3), 14: (1, 2, 3), 15: (1, 2, 3)}


class Machine:
    """Concrete evaluator. Registers carry a known-bit mask; anything unknown stays unknown."""

    def __init__(self, image):
        self.image = image
        self.regs = [0] * 16
        self.known = [0] * 16
        self.mem = {}
        self.xmm = [None] * 16
        self.flags = [None, None, None, None]
        self.pc = 0
        self.notes = 0
        self.seen = set()
        self.edges = set()
        self.steps = 0

    def set_reg(self, reg, value):
        self.regs[reg] = value & U64
        self.known[reg] = U64

    def get(self, reg, bits, rex=1):
        if bits == 8 and not rex and 4 <= reg <= 7:
            reg -= 4
            if self.known[reg] & 0xff00 != 0xff00:
                return None
            return (self.regs[reg] >> 8) & 0xff
        mask = (1 << bits) - 1
        if self.known[reg] & mask != mask:
            return None
        return self.regs[reg] & mask

    def put(self, reg, bits, value, rex=1):
        """Write a value, or unknown when value is None."""
        if bits == 8 and not rex and 4 <= reg <= 7:
            reg -= 4
            mask = 0xff00
            self.known[reg] &= ~mask & U64
            if value is not None:
                self.regs[reg] = (self.regs[reg] & ~mask) | ((value & 0xff) << 8)
                self.known[reg] |= mask
            return
        if bits >= 32:
            full = U64 if bits == 64 else 0xffffffff
            self.known[reg] = 0
            if value is not None:
                self.regs[reg] = value & full
                self.known[reg] = U64
            return
        mask = (1 << bits) - 1
        self.known[reg] &= ~mask & U64
        if value is not None:
            self.regs[reg] = (self.regs[reg] & ~mask) | (value & mask)
            self.known[reg] |= mask

    def move_reg(self, dest, src, bits):
        """A full-width move keeps partly known registers partly known."""
        mask = U64 if bits == 64 else 0xffffffff
        self.regs[dest] = self.regs[src] & mask
        self.known[dest] = self.known[src] & mask
        if bits == 32:
            self.known[dest] |= U64 ^ 0xffffffff

    def operand(self, insn):
        data = self.image.data
        modrm = data[insn.modrm]
        mod, rm = modrm >> 6, modrm & 7
        rexb, rexx = (insn.rex & 1) << 3, (insn.rex & 2) << 2
        if mod == 3:
            return ("r", rm | rexb)
        p = insn.modrm + 1
        base, index, scale = None, None, 1
        if rm == 4:
            sib = data[p]
            p += 1
            scale = 1 << (sib >> 6)
            if ((sib >> 3) & 7) | rexx != 4:
                index = ((sib >> 3) & 7) | rexx
            if sib & 7 == 5 and mod == 0:
                return ("m", None, index, scale, struct.unpack_from("<i", data, p)[0])
            base = (sib & 7) | rexb
        elif mod == 0 and rm == 5:
            return ("m", None, None, 1, insn.va + insn.size + struct.unpack_from("<i", data, p)[0])
        else:
            base = rm | rexb
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", data, p)[0]
        elif mod == 2:
            disp = struct.unpack_from("<i", data, p)[0]
        return ("m", base, index, scale, disp)

    def address(self, operand):
        _, base, index, scale, disp = operand
        total = disp
        for reg, factor in ((base, 1), (index, scale)):
            if reg is None:
                continue
            value = self.get(reg, 64)
            if value is None:
                fail(f"address uses an unknown register at {self.pc:#x}")
            total += value * factor
        return total & U64

    def load(self, at, size):
        out = 0
        for i in range(size):
            byte = self.mem.get(at + i)
            if byte is None:
                byte = self.image.read_only(at + i)
            if byte is None:
                return None
            out |= byte << (8 * i)
        return out

    def store(self, at, size, value):
        if not (STACK-0x10000 <= at and at+size <= STACK or 0x70000000 <= at and at+size <= 0x70000014): fail(f"write outside output/stack at {at:#x}")
        if value is None:
            for i in range(size):
                self.mem.pop(at + i, None)
            return
        for i in range(size):
            self.mem[at + i] = (value >> (8 * i)) & 0xff

    def spill(self, at, reg, size):
        if not (STACK-0x10000 <= at and at+size <= STACK or 0x70000000 <= at and at+size <= 0x70000014): fail(f"spill outside output/stack at {at:#x}")
        """Store a register byte by byte, so partly known registers stay partly known."""
        for i in range(size):
            if (self.known[reg] >> (8 * i)) & 0xff == 0xff:
                self.mem[at + i] = (self.regs[reg] >> (8 * i)) & 0xff
            else:
                self.mem.pop(at + i, None)

    def reload(self, reg, at, size):
        """Load a register byte by byte. A 32-bit load clears the top half."""
        value, known = 0, U64 << (8 * size) & U64
        for i in range(size):
            byte = self.mem.get(at + i)
            if byte is None:
                byte = self.image.read_only(at + i)
            if byte is not None:
                value |= byte << (8 * i)
                known |= 0xff << (8 * i)
        self.regs[reg], self.known[reg] = value, known

    def read(self, operand, bits, rex=1):
        if operand[0] == "r":
            return self.get(operand[1], bits, rex)
        return self.load(self.address(operand), bits // 8)

    def write(self, operand, bits, value, rex=1):
        if operand[0] == "r":
            self.put(operand[1], bits, value, rex)
        else:
            self.store(self.address(operand), bits // 8, value)

    def alu(self, kind, left, right, bits):
        """kind: 0 add 1 or 2 adc 3 sbb 4 and 5 sub 6 xor 7 cmp. Returns the result."""
        if left is None or right is None:
            self.flags = [None, None, None, None]
            return None
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        carry = 0
        if kind in (2, 3):
            carry = self.flags[0]
            if carry is None:
                fail(f"carry is unknown at {self.pc:#x}")
            carry = int(carry)
        if kind in (0, 2):
            full = left + right + carry
            res = full & mask
            self.flags = [full > mask, res == 0, bool(res & sign), bool(~(left ^ right) & (left ^ res) & sign)]
            return res
        if kind in (3, 5, 7):
            full = left - right - carry
            res = full & mask
            self.flags = [full < 0, res == 0, bool(res & sign), bool((left ^ right) & (left ^ res) & sign)]
            return res
        res = {1: left | right, 4: left & right, 6: left ^ right}[kind]
        self.flags = [False, res == 0, bool(res & sign), False]
        return res

    def logic_flags(self, res, bits):
        self.flags = [False, res == 0, bool(res >> (bits - 1)), False]

    def shift(self, kind, value, count, bits):
        if value is None or count is None:
            self.flags = [None, None, None, None]
            return None
        count &= 63 if bits == 64 else 31
        if count == 0:
            return value
        mask = (1 << bits) - 1
        if kind == 4:
            res = (value << count) & mask
            carry = bool((value >> (bits - count)) & 1) if count <= bits else False
        elif kind == 5:
            res = value >> count
            carry = bool((value >> (count - 1)) & 1)
        elif kind == 7:
            signed = value - (1 << bits) if value >> (bits - 1) else value
            res = (signed >> count) & mask
            carry = bool((signed >> (count - 1)) & 1)
        else:
            fail(f"rotate kind {kind} at {self.pc:#x} is not modelled")
        self.flags = [carry, res == 0, bool(res >> (bits - 1)), None]
        return res

    def condition(self, code):
        if code not in COND:
            fail(f"condition {code} at {self.pc:#x} is not modelled")
        if any(self.flags[i] is None for i in USES[code]):
            return None
        return COND[code](self.flags)

    def immediate(self, insn, size, bits):
        at = insn.off + insn.size - size
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i"}[size], self.image.data, at)[0]
        return value & ((1 << bits) - 1)

    def call(self, target, where):
        if target == self.image.note_target:
            self.notes += 1
            for reg in CALLER_SAVED:
                self.put(reg, 64, None)
            self.flags = [None, None, None, None]
            return
        if target in self.image.panic_targets:
            raise Done("panic", where)
        sp = self.get(RSP, 64) - 8
        self.set_reg(RSP, sp)
        self.store(sp, 8, where + self.image.fetch(where).size)
        self.pc = target

    def run(self, start):
        self.pc = start
        while True:
            self.steps += 1
            if self.steps > MAX_STEPS:
                fail(f"no stop from {start:#x}")
            before = self.pc
            insn = self.image.fetch(before)
            self.step()
            if (isinstance(insn.key, int) and 0x70 <= insn.key <= 0x7f) or (isinstance(insn.key, tuple) and len(insn.key) == 2 and insn.key[0] == 0x0f and 0x80 <= insn.key[1] <= 0x8f):
                self.edges.add((before, self.pc))

    def step(self):
        insn = self.image.fetch(self.pc)
        self.seen.add(self.pc)
        data = self.image.data
        key = insn.key
        here = self.pc
        bits = 64 if insn.rex & 8 else 16 if insn.wide16 else 32
        rexr = (insn.rex & 4) << 1
        rex = insn.rex
        self.pc = here + insn.size
        if isinstance(key, tuple):
            self.two_byte(insn, key, bits, rexr, here)
            return
        if key == 0x90 and not insn.rex & 1:
            return
        if 0x50 <= key <= 0x57:
            reg = (key & 7) | ((rex & 1) << 3)
            sp = self.get(RSP, 64) - 8
            self.set_reg(RSP, sp)
            self.spill(sp, reg, 8)
            return
        if 0x58 <= key <= 0x5f:
            reg = (key & 7) | ((rex & 1) << 3)
            sp = self.get(RSP, 64)
            self.reload(reg, sp, 8)
            self.set_reg(RSP, sp + 8)
            return
        if key in (0x89, 0x8b, 0x88, 0x8a):
            width = bits if key in (0x89, 0x8b) else 8
            operand = self.operand(insn)
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            if operand[0] == "r" and width >= 32:
                if key == 0x89:
                    self.move_reg(operand[1], reg, width)
                else:
                    self.move_reg(reg, operand[1], width)
            elif operand[0] == "m" and width >= 32:
                if key == 0x89:
                    self.spill(self.address(operand), reg, width // 8)
                else:
                    self.reload(reg, self.address(operand), width // 8)
            elif key in (0x89, 0x88):
                self.write(operand, width, self.get(reg, width, rex), rex)
            else:
                self.put(reg, width, self.read(operand, width, rex), rex)
            return
        if key in (0xc7, 0xc6):
            width = bits if key == 0xc7 else 8
            size = 2 if width == 16 else 1 if width == 8 else 4
            self.write(self.operand(insn), width, self.immediate(insn, size, width), rex)
            return
        if 0xb8 <= key <= 0xbf:
            reg = (key & 7) | ((rex & 1) << 3)
            size = 8 if rex & 8 else 2 if insn.wide16 else 4
            value = int.from_bytes(data[insn.off + insn.size - size:insn.off + insn.size], "little")
            self.put(reg, size * 8, value)
            return
        if 0xb0 <= key <= 0xb7:
            self.put((key & 7) | ((rex & 1) << 3), 8, data[insn.off + insn.size - 1], rex)
            return
        if key == 0x8d:
            operand = self.operand(insn)
            if operand[0] != "m":
                fail(f"lea with a register at {here:#x}")
            self.put(((data[insn.modrm] >> 3) & 7) | rexr, bits, self.address(operand) & ((1 << bits) - 1))
            return
        if key == 0x63:
            value = self.read(self.operand(insn), 32)
            if value is not None and value >> 31:
                value -= 1 << 32
            self.put(((data[insn.modrm] >> 3) & 7) | rexr, bits, None if value is None else value & U64)
            return
        if key in (0x81, 0x83, 0x80):
            operand = self.operand(insn)
            width = 8 if key == 0x80 else bits
            size = 4 if key == 0x81 and width != 16 else 2 if key == 0x81 else 1
            kind = (data[insn.modrm] >> 3) & 7
            res = self.alu(kind, self.read(operand, width, rex), self.immediate(insn, size, width), width)
            if kind != 7:
                self.write(operand, width, res, rex)
            return
        if key < 0x40 and key & 7 < 4:
            width = bits if key & 1 else 8
            operand = self.operand(insn)
            reg = ("r", ((data[insn.modrm] >> 3) & 7) | rexr)
            first, second = (operand, reg) if key & 7 < 2 else (reg, operand)
            kind = key >> 3
            if kind == 6 and first == second:
                self.write(first, width, 0, rex)
                self.flags = [False, True, False, False]
                return
            res = self.alu(kind, self.read(first, width, rex), self.read(second, width, rex), width)
            if kind != 7:
                self.write(first, width, res, rex)
            return
        if key < 0x40 and key & 7 in (4, 5):
            width = bits if key & 1 else 8
            size = 1 if width == 8 else 2 if width == 16 else 4
            kind = key >> 3
            res = self.alu(kind, self.get(RAX, width), self.immediate(insn, size, width), width)
            if kind != 7:
                self.put(RAX, width, res)
            return
        if key in (0x84, 0x85):
            width = bits if key == 0x85 else 8
            left = self.read(self.operand(insn), width, rex)
            right = self.get(((data[insn.modrm] >> 3) & 7) | rexr, width, rex)
            if left is None or right is None:
                self.flags = [None, None, None, None]
            else:
                self.logic_flags(left & right, width)
            return
        if key in (0xa8, 0xa9):
            width = 8 if key == 0xa8 else bits
            imm = self.immediate(insn, 1 if width == 8 else 4, width)
            left = self.get(RAX, width)
            if left is None:
                self.flags = [None, None, None, None]
            else:
                self.logic_flags(left & imm, width)
            return
        if key in (0xc1, 0xd1, 0xd3, 0xc0, 0xd0, 0xd2):
            width = 8 if key in (0xc0, 0xd0, 0xd2) else bits
            operand = self.operand(insn)
            kind = (data[insn.modrm] >> 3) & 7
            if key in (0xc1, 0xc0):
                count = data[insn.off + insn.size - 1]
            elif key in (0xd1, 0xd0):
                count = 1
            else:
                count = self.get(RCX, 8)
            self.write(operand, width, self.shift(kind, self.read(operand, width, rex), count, width), rex)
            return
        if key in (0x69, 0x6b):
            operand = self.operand(insn)
            imm = self.immediate(insn, 4 if key == 0x69 else 1, bits)
            self.signed_multiply(((data[insn.modrm] >> 3) & 7) | rexr, self.read(operand, bits), imm, bits)
            return
        if key in (0xf7, 0xf6):
            self.unary(insn, key, bits, here)
            return
        if key in (0xff, 0xfe):
            kind = (data[insn.modrm] >> 3) & 7
            operand = self.operand(insn)
            width = 8 if key == 0xfe else bits
            if kind in (0, 1):
                carry = self.flags[0]
                res = self.alu(0 if kind == 0 else 5, self.read(operand, width, rex), 1, width)
                self.write(operand, width, res, rex)
                self.flags[0] = carry
                return
            if key == 0xff and kind == 2:
                if operand[0] == "m" and operand[1] is None and operand[2] is None:
                    target = self.image.slots.get(operand[4])
                    if target is None:
                        fail(f"call through unknown slot {operand[4]:#x} at {here:#x}")
                    self.call(target, here)
                    return
                fail(f"indirect call at {here:#x}")
            if key == 0xff and kind == 4 and operand[0] == "r":
                target = self.get(operand[1], 64)
                if target is None:
                    fail(f"jump through unknown register at {here:#x}")
                self.pc = target
                return
            fail(f"group 5 form {kind} at {here:#x}")
        if key == 0xe8:
            self.call(insn.target, here)
            return
        if key in (0xeb, 0xe9):
            self.pc = insn.target
            return
        if 0x70 <= key <= 0x7f:
            self.jump(key - 0x70, insn, here)
            return
        if key == 0xc3:
            sp = self.get(RSP, 64)
            mark = self.load(sp, 8)
            if mark is None:
                fail(f"return to an unknown address at {here:#x}")
            self.set_reg(RSP, sp + 8)
            if mark == RETURN_MARK:
                raise Done("ret", here)
            self.pc = mark
            return
        if key == 0xcc:
            fail(f"int3 reached at {here:#x}")
        fail(f"instruction {key:#x} at {here:#x} is not modelled")

    def signed_multiply(self, reg, left, right, bits):
        if left is None or right is None:
            self.put(reg, bits, None)
            self.flags = [None, None, None, None]
            return
        sign = 1 << bits
        a = left - sign if left >> (bits - 1) else left
        b = right - sign if right >> (bits - 1) else right
        full = a * b
        res = full & (sign - 1)
        wide = res - sign if res >> (bits - 1) else res
        self.put(reg, bits, res)
        self.flags = [wide != full, None, None, wide != full]

    def unary(self, insn, key, bits, here):
        kind = (self.image.data[insn.modrm] >> 3) & 7
        operand = self.operand(insn)
        width = 8 if key == 0xf6 else bits
        value = self.read(operand, width, insn.rex)
        if kind == 0:
            imm = self.immediate(insn, 1 if width == 8 else 4, width)
            if value is None:
                self.flags = [None, None, None, None]
            else:
                self.logic_flags(value & imm, width)
            return
        if kind == 2:
            self.write(operand, width, None if value is None else ~value & ((1 << width) - 1), insn.rex)
            return
        if kind == 3:
            res = self.alu(5, 0, value, width)
            self.write(operand, width, res, insn.rex)
            return
        if width < 32:
            fail(f"narrow multiply or divide at {here:#x}")
        low = self.get(RAX, width)
        if kind == 4:
            if low is None or value is None:
                fail(f"mul of an unknown value at {here:#x}")
            full = low * value
            mask = (1 << width) - 1
            self.put(RAX, width, full & mask)
            self.put(RDX, width, full >> width)
            self.flags = [full >> width != 0, None, None, full >> width != 0]
            return
        if kind == 6:
            high = self.get(RDX, width)
            if low is None or value is None or high is None:
                fail(f"div of an unknown value at {here:#x}")
            if value == 0:
                fail(f"divide by zero at {here:#x}")
            q, r = divmod((high << width) | low, value)
            if q >> width:
                fail(f"divide overflow at {here:#x}")
            self.put(RAX, width, q)
            self.put(RDX, width, r)
            self.flags = [None, None, None, None]
            return
        fail(f"unary form {kind} at {here:#x}")

    def jump(self, code, insn, here):
        taken = self.condition(code)
        if taken is None:
            fail(f"branch on unknown flags at {here:#x}")
        if taken:
            self.pc = insn.target

    def two_byte(self, insn, key, bits, rexr, here):
        data = self.image.data
        two = key[1]
        rex = insn.rex
        if len(key) == 3:
            fail(f"instruction {key} at {here:#x} is not modelled")
        if 0x80 <= two <= 0x8f:
            self.jump(two - 0x80, insn, here)
            return
        if two == 0x1f:
            return
        if 0x40 <= two <= 0x4f:
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            taken = self.condition(two - 0x40)
            src = self.read(self.operand(insn), bits)
            old = self.get(reg, bits)
            self.put(reg, bits, None if taken is None else src if taken else old)
            return
        if 0x90 <= two <= 0x9f:
            taken = self.condition(two - 0x90)
            self.write(self.operand(insn), 8, None if taken is None else int(taken), rex)
            return
        if two in (0xb6, 0xb7):
            value = self.read(self.operand(insn), 8 if two == 0xb6 else 16, rex)
            self.put(((data[insn.modrm] >> 3) & 7) | rexr, bits, value)
            return
        if two == 0xaf:
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            self.signed_multiply(reg, self.get(reg, bits), self.read(self.operand(insn), bits), bits)
            return
        if two in (0xa4, 0xa5, 0xac, 0xad):
            operand = self.operand(insn)
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            count = data[insn.off + insn.size - 1] if two in (0xa4, 0xac) else self.get(RCX, 8)
            value, fill = self.read(operand, bits), self.get(reg, bits)
            if value is None or fill is None or count is None:
                fail(f"double shift of an unknown value at {here:#x}")
            count &= 63 if bits == 64 else 31
            if count:
                mask = (1 << bits) - 1
                if two in (0xa4, 0xa5):
                    res = ((value << count) | (fill >> (bits - count))) & mask
                else:
                    res = ((value >> count) | (fill << (bits - count))) & mask
                self.write(operand, bits, res)
                self.flags = [None, res == 0, bool(res >> (bits - 1)), None]
            return
        if two == 0xbd or two == 0xbc:
            value = self.read(self.operand(insn), bits)
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            if value is None:
                fail(f"bit scan of an unknown value at {here:#x}")
            if insn.rep == 0xf3:
                count = bits if value == 0 else bits - value.bit_length() if two == 0xbd else (value & -value).bit_length() - 1
                self.put(reg, bits, count)
                self.flags = [value == 0, count == 0, False, False]
                return
            if value == 0:
                # 0x4eae576 presets the destination, so a zero source keeps it.
                self.flags = [None, True, None, None]
                return
            self.put(reg, bits, value.bit_length() - 1 if two == 0xbd else (value & -value).bit_length() - 1)
            self.flags = [None, False, None, None]
            return
        if two in (0x10, 0x11, 0x28, 0x29, 0x6f, 0x7f, 0x57):
            if two in (0x6f, 0x7f) and not (insn.wide16 or insn.rep == 0xf3):
                fail(f"mmx move at {here:#x}")
            if two in (0x10, 0x11) and insn.rep:
                fail(f"scalar float move at {here:#x}")
            reg = ((data[insn.modrm] >> 3) & 7) | rexr
            operand = self.operand(insn)
            if two == 0x57:
                if operand != ("r", reg):
                    fail(f"xor of two xmm registers at {here:#x}")
                self.xmm[reg] = bytes(16)
                return
            if operand[0] == "r":
                if two in (0x10, 0x28, 0x6f):
                    self.xmm[reg] = self.xmm[operand[1]]
                else:
                    self.xmm[operand[1]] = self.xmm[reg]
                return
            at = self.address(operand)
            if two in (0x10, 0x28, 0x6f):
                low, high = self.load(at, 8), self.load(at + 8, 8)
                self.xmm[reg] = None if low is None or high is None else struct.pack("<QQ", low, high)
            else:
                value = self.xmm[reg]
                if value is None:
                    self.store(at, 8, None)
                    self.store(at + 8, 8, None)
                else:
                    low, high = struct.unpack("<QQ", value)
                    self.store(at, 8, low)
                    self.store(at + 8, 8, high)
            return
        fail(f"instruction {key} at {here:#x} is not modelled")



SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET = ROOT / 'artifacts/node/94/hl-node'
ENTRY = 0x4eafb60
STARTS = (0x4eae280, 0x4eae400, ENTRY)
OUT, LEFT, RIGHT = 0x70000000, 0x71000000, 0x72000000
MAX96 = (1 << 96) - 1


def verified_data(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('target SHA-256 mismatch')
    return data


def pack(mantissa, scale, sign):
    if not (0 <= mantissa <= MAX96 and 0 <= scale <= 28 and sign in (0, 1)):
        raise ValueError('invalid Decimal test input')
    return struct.pack('<IIII', (scale << 16) | (sign << 31), mantissa >> 64,
                       mantissa & 0xffffffff, (mantissa >> 32) & 0xffffffff)


def evaluate(image, left, right):
    machine = Machine(image)
    machine.set_reg(RSP, STACK - 8)
    machine.store(STACK - 8, 8, RETURN_MARK)
    for reg in CALLEE_SAVED:
        machine.set_reg(reg, 0x1111111100000000 + reg)
    saved = [machine.regs[reg] for reg in CALLEE_SAVED]
    for i in range(20):
        machine.mem[OUT + i] = 0xa5
    for base, raw in ((LEFT, left), (RIGHT, right)):
        for i, byte in enumerate(raw):
            machine.mem[base + i] = byte
    for reg, value in ((RDI, OUT), (RSI, LEFT), (RDX, RIGHT)):
        machine.set_reg(reg, value)
    try:
        machine.run(ENTRY)
    except Done as done:
        if done.how != 'ret':
            fail(f'unexpected panic at {done.where:#x}')
    if [machine.regs[reg] for reg in CALLEE_SAVED] != saved or machine.get(RSP, 64) != STACK:
        fail('callee-saved register or stack was not restored')
    raw = bytes(machine.mem[OUT + i] for i in range(20))
    status = struct.unpack_from('<I', raw)[0]
    if status not in (0, 1, 2):
        fail(f'unrecognised status {status}')
    if status != 0:
        if raw[4:] != bytes([0xa5]) * 16:
            fail('error path changed output payload')
        return status, None, machine
    flags, hi, lo, mid = struct.unpack_from('<IIII', raw, 4)
    if flags & 0x7f00ffff or ((flags >> 16) & 255) > 28:
        fail('success flags outside normal Decimal domain')
    return status, (flags, (hi << 64) | (mid << 32) | lo), machine


def ideal(left, right):
    """Independent rational oracle: nearest representable value, with ties to even."""
    a, sa, na = left
    b, sb, nb = right
    if b == 0:
        return 2, None
    numerator = a * 10**sb
    denominator = b * 10**sa
    for scale in range(28, -1, -1):
        q, r = divmod(numerator * 10**scale, denominator)
        q += int(2*r > denominator or (2*r == denominator and q & 1))
        if q <= MAX96:
            value = Fraction(-q if na ^ nb else q, 10**scale)
            return 0, value
    return 1, None


def numeric(result):
    flags, mantissa = result
    scale = (flags >> 16) & 255
    return Fraction(-mantissa if flags >> 31 else mantissa, 10**scale)


def stimuli():
    """A fixed grid, including all legal scale pairs and 96-bit carry boundaries."""
    rows = []
    for sa in range(29):
        for sb in range(29):
            for a, b in ((1, 3), (7, 2), (MAX96, 7), (0, 1)):
                rows.append(((a, sa, (sa + sb) & 1), (b, sb, sa & 1)))
    values = (0, 1, 2, 3, 5, 9, 10, 11, 99, 100, (1 << 32)-1,
              1 << 32, (1 << 64)-1, 1 << 64, MAX96-1, MAX96)
    scales = (0, 1, 7, 14, 27, 28)
    for i, a in enumerate(values):
        for j, b in enumerate(values):
            for k in range(4):
                rows.append(((a, scales[(i+k) % len(scales)], k & 1),
                             (b, scales[(j+k*3) % len(scales)], (k >> 1) & 1)))
    # Tiny rationals at the representable boundary and explicit exact quotients.
    rows += [((a, sa, s), (b, sb, t))
             for a, b in ((1, 2), (1, 3), (5, 2), (7, 2), (1, 1),
                          (1, MAX96), (MAX96, 1), (0, 0), (0, 1))
             for sa, sb in ((0, 0), (28, 0), (0, 28))
             for s in (0, 1) for t in (0, 1)]
    # Ties in each of the three divisor-width paths.
    rows += [((b//2*a, 28, sign), (b, 0, 0))
             for b in (2, 1 << 32, 1 << 64)
             for a in (1, 3, 5, 7) for sign in (0, 1)]
    # Limb-boundary matrix exercises 32-, 64- and 96-bit division paths.
    boundaries = sorted({x for n in (1, 31, 32, 33, 63, 64, 65, 95) for x in
                         ((1 << n)-1, 1 << n, (1 << n)+1)} | {MAX96-1, MAX96})
    for a in boundaries:
        for b in boundaries:
            for sa, sb in ((0, 0), (28, 0), (0, 28), (14, 14)):
                rows.append(((a, sa, 0), (b, sb, 1)))
    return rows


def function_records(image, seen, edges):
    result = []
    for start in STARTS:
        a, end = image.fde_of(start)
        if a != start:
            fail('selected address does not start an FDE')
        insns = sweep(image, a, end)
        starts = {x.va for x in insns}
        if not {x for x in seen if a <= x < end} <= starts:
            fail('executed instruction is not in the linear sweep')
        branches = [x for x in insns if
                    (isinstance(x.key, int) and 0x70 <= x.key <= 0x7f) or
                    (isinstance(x.key, tuple) and len(x.key) == 2 and x.key[0] == 0x0f and 0x80 <= x.key[1] <= 0x8f)]
        off = image.text_off + a - image.text_va
        result.append({'start_va': hex(a), 'end_va': hex(end), 'fde_va': hex(image.fde_details[a]['fde']), 'file_offset': hex(off),
                       'sha256': hashlib.sha256(image.data[off:off+end-a]).hexdigest(),
                       'instructions': len(insns), 'instructions_reached': len(starts & seen),
                       'conditional_branches': len(branches),
                       'conditional_edges_reached': sum(int((x.va, dst) in edges)
                           for x in branches for dst in (x.va+x.size, x.target))})
    return result


def entry_guard(image):
    """Check the entire entry fragment used for the all-mantissa zero proof."""
    begin, end = 0x4eafb60, 0x4eafbba
    off = image.text_off + begin - image.text_va
    expected = bytes.fromhex(
        '554157415641554154534883ec684989fe8b4a04448b6a088b7a0c4489e809f809c8'
        '750c41c70602000000e9060c00008b4604448b6608448b7e0c4589e04509f84109c0'
        '75140f57c0410f110641c7461000000000e9dc0b0000')
    if image.data[off:off+end-begin] != expected:
        fail('entry zero-test bytes changed')
    epilogue = bytes.fromhex('4c89f04883c4685b415c415d415e415f5dc3')
    ep_off = image.text_off + 0x4eb0796 - image.text_va
    if image.data[ep_off:ep_off+len(epilogue)] != epilogue:
        fail('zero-test return bytes changed')
    return {'start_va': hex(begin), 'end_va': hex(end), 'bytes': expected.hex(),
            'return_va': hex(0x4eb0796), 'return_bytes': epilogue.hex(),
            'denominator_test': 'OR of all three u32 limbs; zero returns tag 2 first',
            'numerator_test': 'OR of all three u32 limbs; zero with nonzero denominator returns 20 zero bytes',
            'domain_argument': 'A bitwise OR of three 32-bit words is zero if and only if each word is zero.'}


def small_round_decision(remainder, divisor, odd, width=32):
    """Decision encoded by the checked compare/parity fragment, for a valid remainder."""
    if width < 2 or not (1 <= divisor < 1 << width and 0 <= remainder < divisor and odd in (0, 1)):
        raise ValueError('invalid remainder, divisor or parity')
    if remainder & (1 << (width-1)):
        return True
    twice = 2 * remainder
    return twice > divisor or (twice == divisor and bool(odd))


def rounding_lemma(image):
    # Conditional proof: the registers hold the indicated quotient/remainder
    # and divisor limbs at entry. These bytes do not prove those preconditions.
    windows = (
        (0x4eb0466, 0x4eb0483, '85db781201db4439eb72704439eb77064183e401746548ff442408755e'),
        (0x4eb02a6, 0x4eb02cf, '48c1e020781e8b4c24184809c84801c04839f0770f0f852002000083e5010f841702000048ff442408'),
        (0x4eb0238, 0x4eb027f, '4585c00f88650200008b4c241c488d041b48c1eb1f895c241c89442418410fa4c80144894424204539d00f97c180d9000f842a0200000fb6c183f8010f842c020000e962020000'),
        (0x4eb0498, 0x4eb04ab, '483b4424307707754083e501743b48ff442408'),
    )
    bound=[]
    for start,end,hex_bytes in windows:
        off=image.text_off+start-image.text_va
        expected=bytes.fromhex(hex_bytes)
        if image.data[off:off+end-start]!=expected:
            fail('rounding fragment changed')
        bound.append({'start_va':hex(start),'end_va':hex(end),'bytes':hex_bytes})
    checked = 0
    for divisor in range(1, 1 << 8):
        for remainder in range(divisor):
            for odd in (0, 1):
                wanted = 2*remainder > divisor or (2*remainder == divisor and odd == 1)
                if small_round_decision(remainder, divisor, odd, 8) != wanted:
                    fail('reduced-width rounding lemma failed')
                checked += 1
    return {'windows':bound,
            'domain':'0 <= remainder < divisor < 2^w, parity in {0,1}, w in {32,64,96}; fragment-entry registers and limbs must hold these values',
            'increment':'2*remainder > divisor or (2*remainder == divisor and parity == 1)',
            'proof':'If the top remainder bit is set then 2*remainder >= 2^w > divisor. Otherwise doubling is exact in w bits. The 32- and 64-bit fragments compare the doubled remainder directly; the 96-bit fragment shifts its three limbs and compares high then low limbs. Equality tests the quotient parity bit.',
            'exhaustive_8bit_remainder_divisor_parity_cases':checked}


def caller_anchor(image):
    # These are data-flow bytes around one caller's divide-by-two arm, not a
    # claim that its complete control flow has been reconstructed here.
    begin, end = 0x3bb843e, 0x3bb846a
    off = image.text_off + begin - image.text_va
    expected = bytes.fromhex('0f28055bb264fc0f298424f00000004889e7488db42420010000488d9424f0000000ff156adebb01833c2400')
    if image.data[off:off+end-begin] != expected or image.slots.get(0x57762d0) != ENTRY:
        fail('caller divide-by-two bytes or relocation changed')
    sections = elf_index.sections(image.data)
    def read_va(va, size):
        candidates = [x for x in sections if x['type'] != 8 and x['address'] <= va and va+size <= x['address']+x['size']]
        if len(candidates) != 1:
            fail('data VA is unmapped or ambiguous')
        x=candidates[0]
        off=x['offset']+va-x['address']
        return image.data[off:off+size]
    constant = read_va(0x2036a0,16)
    if struct.unpack('<IIII',constant) != (0,0,2,0):
        fail('divide-by-two Decimal constant changed')
    powers = struct.unpack('<10I',read_va(0x7c62ec,40))
    if list(powers) != [10**k for k in range(10)]:
        fail('u32 power table changed')
    return {'window_start_va':hex(begin), 'window_end_va':hex(end), 'window_bytes':expected.hex(),
            'call_va':hex(0x3bb8460), 'indirect_slot_va':hex(0x57762d0),
            'slot_target_va':hex(image.slots[0x57762d0]),
            'constant_va':hex(0x2036a0), 'constant_words':list(struct.unpack('<IIII',constant)),
            'pow10_table_va':hex(0x7c62ec), 'pow10_u32':list(powers)}


def generate(data, out):
    verified_data(data)
    image = Image(data)
    guard = entry_guard(image)
    lemma = rounding_lemma(image)
    anchor = caller_anchor(image)
    seen, edges = set(), set()
    first_edge_case = {}
    counts = collections.Counter()
    vector_rows = []
    for index, (left, right) in enumerate(stimuli()):
        status, result, machine = evaluate(image, pack(*left), pack(*right))
        expected_status, expected_value = ideal(left, right)
        if status != expected_status or status == 0 and numeric(result) != expected_value:
            fail(f'quotient/model mismatch at vector {index}: {left} / {right}')
        seen.update(machine.seen)
        edges.update(machine.edges)
        for edge in machine.edges:
            first_edge_case.setdefault(edge, index)
        counts[status] += 1
        flags, mantissa = result if result is not None else (None, None)
        vector_rows.append([index, *left, *right, status,
                            '' if flags is None else f'{flags:#010x}',
                            '' if mantissa is None else str(mantissa),
                            '' if expected_value is None else str(expected_value.numerator),
                            '' if expected_value is None else str(expected_value.denominator)])
    tie_rows = []
    for divisor, site in ((2, 0x4eb0476), (1 << 32, 0x4eb02c1), (1 << 64, 0x4eb04a1)):
        for multiplier in (1, 3, 5, 7):
            for sign in (0, 1):
                left=(divisor//2*multiplier,28,sign)
                right=(divisor,0,0)
                status, result, machine=evaluate(image,pack(*left),pack(*right))
                model_status, value=ideal(left,right)
                if status!=model_status or status!=0 or numeric(result)!=value or site not in machine.seen:
                    fail('a divisor-width tie did not reach its expected parity check')
                tie_rows.append((divisor,multiplier,sign,hex(site),hex(result[0]),result[1],value.numerator,value.denominator))
    records = function_records(image, seen, edges)
    evidence = {'binary_sha256': SHA256, 'coordinates': 'ELF virtual addresses before load bias',
                'guard_proof': guard, 'rounding_lemma': lemma, 'caller_anchor': anchor, 'functions': records,
                'vectors': len(vector_rows), 'status_counts': {str(k): counts[k] for k in (0, 1, 2)},
                'numeric_model_mismatches': 0, 'tie_cases': len(tie_rows),
                'limits': 'Grid comparison is not exhaustive outside the zero-test proof. Inputs assume valid Decimal flags and scale 0..28. The rational model compares numerical value, not result representation.'}
    out.mkdir(parents=True, exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True)+'\n')
    with (out/'vectors.tsv').open('w', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(('case','left_mantissa','left_scale','left_sign','right_mantissa','right_scale','right_sign',
                    'status','result_flags','result_mantissa','model_num','model_den'))
        w.writerows(vector_rows)
    with (out/'ties.tsv').open('w', newline='') as f:
        w=csv.writer(f,delimiter='\t',lineterminator='\n')
        w.writerow(('divisor','odd_multiplier','negative','parity_site_va','result_flags',
                    'result_mantissa','model_num','model_den'))
        w.writerows(tie_rows)
    with (out/'branch-edges.tsv').open('w', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(('function_start_va','branch_va','fallthrough_va','target_va','fallthrough_seen','target_seen','fallthrough_first_case','target_first_case'))
        for start in STARTS:
            for insn in sweep(image, *image.fde_of(start)):
                k=insn.key
                if (isinstance(k,int) and 0x70<=k<=0x7f) or (isinstance(k,tuple) and len(k)==2 and k[0]==0x0f and 0x80<=k[1]<=0x8f):
                    fall=insn.va+insn.size
                    w.writerow((hex(start),hex(insn.va),hex(fall),hex(insn.target),
                                int((insn.va,fall) in edges),int((insn.va,insn.target) in edges),
                                first_edge_case.get((insn.va,fall),''), first_edge_case.get((insn.va,insn.target),'')))
    landmarks = (
        (0x4eafb82, 'denominator zero branch'),
        (0x4eafb84, 'divide-by-zero status'),
        (0x4eafba4, 'numerator zero branch'),
        (0x4eafba9, 'zero success payload'),
        (0x4eafbd1, 'left scale extraction'),
        (0x4eafbde, 'right scale extraction'),
        (0x4eafbe4, 'scale difference'),
        (0x4eafbfb, 'divisor width dispatch'),
        (0x4eafc3c, '64-bit hardware divide'),
        (0x4eafd4a, 'scale limit comparison'),
        (0x4eafd02, 'limb-division helper call'),
        (0x4eafd5c, 'scaling helper call'),
        (0x4eafd68, 'scaling helper failure branch'),
        (0x4eb02c1, 'tie parity test, 33-to-64-bit divisor'),
        (0x4eb02ca, 'round increment, 33-to-64-bit divisor'),
        (0x4eb0314, 'scale limit comparison, small divisor'),
        (0x4eb046a, 'double remainder, small divisor'),
        (0x4eb0471, 'compare doubled remainder'),
        (0x4eb0476, 'tie parity test, small divisor'),
        (0x4eb047a, 'tie even branch, small divisor'),
        (0x4eb047c, 'round increment, small divisor'),
        (0x4eb04a1, 'tie parity test, 65-to-96-bit divisor'),
        (0x4eb04d2, 'arithmetic error status'),
        (0x4eb078f, 'success status'),
    )
    with (out/'landmarks.tsv').open('w', newline='') as f:
        w=csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(('va','file_offset','instruction_bytes','relative_target_va','reached','observation'))
        for va, label in landmarks:
            insn=image.fetch(va)
            raw=image.data[insn.off:insn.off+insn.size]
            w.writerow((hex(va),hex(insn.off),raw.hex(),'' if insn.target is None else hex(insn.target),
                        int(va in seen),label))
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    summary = generate(TARGET.read_bytes(), args.out)
    print(json.dumps({'vectors': summary['vectors'], 'status_counts': summary['status_counts'],
                      'numeric_model_mismatches': summary['numeric_model_mismatches']}, sort_keys=True))


if __name__ == '__main__':
    main()
