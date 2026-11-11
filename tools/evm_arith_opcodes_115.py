#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM arithmetic, comparison and bitwise opcode handlers.

The EVM opcode table of node #115 comes in three RELATIVE copies (0x6485ef8 and 0x6486c60 with the
0x43xxxxx handlers, 0x649eea0 with the 0x546xxxx / 0x4f0xxxx handlers); slot = opcode.  Opcodes
0x01..0x0b (ADD MUL SUB DIV SDIV MOD SMOD ADDMOD MULMOD EXP SIGNEXTEND) and 0x10..0x1e (LT GT SLT
SGT EQ ISZERO AND OR XOR NOT BYTE SHL SHR SAR and the 0x1e leading-zero count) point at stack
handlers with the signature handler(rdi = interpreter, rsi = host) -> al.  The interpreter holds
the stack base at +0x28 (32-byte little-endian words, top = highest index), the stack length at +0x30,
the remaining gas at +0x188 and the spec byte at +0x1a9; the result codes are 0x00 (ok), 0x2c (stack
underflow), 0x2b (opcode not activated in this spec) and 0x20 (EXP out of gas).  SHL/SHR/SAR need
spec >= 5 and 0x1e needs spec >= 0x0d.  EXP charges ((bit_length(exponent) - 1) // 8 + 1) *
[[host + 0x250] + 0x18] gas (nothing for a zero exponent) after it has popped one word, and it
leaves the exponent slot untouched when the charge fails.
The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real
machine code of all 52 handlers (plus the real 256-bit division and power helpers they call) with a
small concrete x86-64 evaluator (no external programs, the binary is never executed) and compares every
case with one pure-Python EVM reconstruction.  Negative controls show that wrong reconstructions,
corrupted handler bytes and bad inputs are detected.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_transient_storage115 as base  # noqa: E402

BINARY, SHA256, M64, M256 = base.BINARY, base.SHA256, base.M64, base.M256
ToolError, Boundary, fail = base.ToolError, base.Boundary, base.fail

TABLES = {"B": (0x6485ef8, 0x6486c60), "C": (0x649eea0,)}
NAMES = {0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD",
         0x08: "ADDMOD", 0x09: "MULMOD", 0x0a: "EXP", 0x0b: "SIGNEXTEND", 0x10: "LT", 0x11: "GT", 0x12: "SLT",
         0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
         0x1a: "BYTE", 0x1b: "SHL", 0x1c: "SHR", 0x1d: "SAR", 0x1e: "CLZ"}
ARITY = {0x08: 3, 0x09: 3, 0x15: 1, 0x19: 1, 0x1e: 1}
GATE = {0x1b: 5, 0x1c: 5, 0x1d: 5, 0x1e: 13}
R_OK, R_OOG, R_NOT_ACTIVATED, R_UNDERFLOW = 0x00, 0x20, 0x2b, 0x2c
I_STACK_PTR, I_STACK_LEN, I_GAS, I_SPEC, H_GASTAB, T_EXPBYTE = 0x28, 0x30, 0x188, 0x1a9, 0x250, 0x18

INT_AT, INT_SIZE = 0x7d00_0000_0000, 0x200
HOST_AT, HOST_SIZE = 0x7d00_0100_0000, 0x300
TAB_AT, TAB_SIZE = 0x7d00_0200_0000, 0x40
STK_AT = 0x7d00_0300_0000
FILL_INT, FILL_HOST, FILL_TAB, FILL_STK = 0x33, 0x44, 0x66, 0x5c
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
SAVED_REGS = (3, 12, 13, 14, 15, 5)

# ---------------------------------------------------------------- decoder / evaluator extensions
SWAP = {0x0faf: 0x0fb7, 0x0feb: 0x0fef, 0x0fbd: 0x0fb7, 0x0fad: 0x0fa5, 0x0fac: 0x0f70, 0x0fa4: 0x0f70,
        0x0f50: 0x0fd7, 0x0fba: 0x0fc6, 0x30: 0x38, 0x04: 0x0c, 0x0f6c: 0x0f60,
        0x0f56: 0x0f57, 0x0f54: 0x0f57, 0x0f55: 0x0f57}
_base_decode = base.decode


def decode(code, va):
    """The base decoder plus imul, por, bsr/lzcnt, shrd, movmskps, bt, neg r/m8, xor r/m8, add al."""
    p = 0
    while code[p] in (0x66, 0x2e, 0xf3, 0xf2, 0x64, 0xf0):
        p += 1
    q = p + (1 if 0x40 <= code[p] <= 0x4f else 0)
    if code[q] == 0xf6 and (code[q + 1] >> 3) & 7 == 3 and code[q + 1] >> 6 == 3:
        c = bytearray(code[:q + 2]) + bytearray([0]) + bytearray(code[q + 2:])
        c[q + 1] &= ~0x38
        form = _base_decode(bytes(c), va)
        form["len"] -= 1
        form["bytes"] = bytes(code[:form["len"]])
        form.pop("imm", None)
        form["reg"] |= 3
        return form
    real = code[q] if code[q] in (0x30, 0x04) else (0x0f00 | code[q + 1] if code[q] == 0x0f else None)
    if real in SWAP:
        c = bytearray(code)
        if real > 0xff:
            c[q + 1] = SWAP[real] & 0xff
        else:
            c[q] = SWAP[real]
        form = _base_decode(bytes(c), va)
        form["op"] = real
        form["bytes"] = bytes(code[:form["len"]])
        return form
    return _base_decode(code, va)


base.decode = decode


class XMachine(base.TraceMachine):
    def flags_logic(self, res, size):
        res = super().flags_logic(res, size)
        self.of = False
        return res

    def cond(self, code, va):
        if code in (0xc, 0xd, 0xe, 0xf):
            less = self.sf != self.of
            return {0xc: less, 0xd: not less, 0xe: less or self.zf, 0xf: not (less or self.zf)}[code]
        return super().cond(code, va)

    def xmm_operand(self, f, va):
        rm = f["rm"]
        if rm[0] == "r":
            return self.xmm[rm[1]]
        at = self.ea(rm, f, va)
        if at % 16:
            fail(f"unaligned 16-byte operand {at:#x} at {va:#x}")
        return self.load(at, 16)

    def step(self, va):
        f = self.fetch(va)
        op, size = f["op"], f["size"]
        nxt = (va + f["len"]) & M64
        handled = True
        if op == 0x0faf:
            a, c = self.reg(f["reg"], size, f), self.get(f["rm"], size, f, va)
            sa, sc = (x - (1 << size) if x >> (size - 1) else x for x in (a, c))
            res = sa * sc & ((1 << size) - 1)
            self.cf = self.of = (res - (1 << size) if res >> (size - 1) else res) != sa * sc
            self.set_reg(f["reg"], size, res, f)
        elif op == 0x0fbd:
            a = self.get(f["rm"], size, f, va)
            self.zf = a == 0
            if f["rep"]:
                self.cf = a == 0
                self.set_reg(f["reg"], size, size - a.bit_length(), f)
            elif a:
                self.set_reg(f["reg"], size, a.bit_length() - 1, f)
        elif op == 0x0f50:
            v = self.xmm[f["rm"][1]]
            self.set_reg(f["reg"], 32, sum(1 << i for i in range(4) if (v >> (32 * i + 31)) & 1), f)
        elif op == 0x0f6e and f["p66"] and f["rex"] & 8:
            self.xmm[f["reg"]] = self.get(f["rm"], 64, f, va)
        elif op in (0x0f56, 0x0f54, 0x0f55):
            src = self.xmm_operand(f, va)
            dst = self.xmm[f["reg"]]
            self.xmm[f["reg"]] = {0x0f56: dst | src, 0x0f54: dst & src, 0x0f55: ~dst & src & ((1 << 128) - 1)}[op]
        elif op == 0x0f6c:
            src = self.xmm_operand(f, va)
            self.xmm[f["reg"]] = (self.xmm[f["reg"]] & M64) | (src & M64) << 64
        elif op == 0x0feb:
            self.xmm[f["reg"]] |= self.xmm_operand(f, va)
        elif op == 0x0fef and f["rm"][0] == "m":
            self.xmm[f["reg"]] ^= self.xmm_operand(f, va)
        elif op in (0x0fad, 0x0fac, 0x0fa4):
            if size != 64:
                fail("shrd/shld width")
            count = (self.regs[1] if op == 0x0fad else f["imm"]) & 63
            a, c = self.get(f["rm"], 64, f, va), self.reg(f["reg"], 64, f)
            if op == 0x0fa4:
                res = ((a << count) | (c >> (64 - count))) & M64 if count else a
            else:
                res = ((a >> count) | (c << (64 - count))) & M64 if count else a
            if count:
                self.flags_logic(res, 64)
            self.put(f["rm"], 64, res, f, va)
        elif op == 0xf6 and f["reg"] & 7 == 3:
            a = self.get(f["rm"], 8, f, va)
            res = self.flags_sub(0, a, 8)
            self.cf = a != 0
            self.put(f["rm"], 8, res, f, va)
        elif op == 0x30:
            a, c = self.get(f["rm"], 8, f, va), self.reg(f["reg"], 8, f)
            self.put(f["rm"], 8, self.flags_logic(a ^ c, 8), f, va)
        elif op == 0x04:
            self.set_reg(0, 8, self.flags_add(self.regs[0] & 0xff, f["imm"], 8), f)
        elif op == 0x0fba:
            a = self.get(f["rm"], size, f, va)
            bit, kind = f["imm"] & (size - 1), f["reg"] & 7
            self.cf = bool((a >> bit) & 1)
            if kind == 5:
                self.put(f["rm"], size, a | (1 << bit), f, va)
            elif kind != 4:
                fail(f"unsupported bt form at {va:#x}")
        elif op == 0xf7 and f["reg"] & 7 in (5, 6):
            a = self.get(f["rm"], size, f, va)
            if f["reg"] & 7 == 6:
                if a == 0:
                    fail("div by zero reached")
                mask = (1 << size) - 1
                q, r = divmod((self.regs[2] & mask) << size | (self.regs[0] & mask), a)
                if q >> size:
                    fail("div overflow reached")
                self.set_reg(0, size, q, f)
                self.set_reg(2, size, r, f)
            elif size != 64:
                fail("one-operand imul width")
            else:
                sa, sx = (x - (1 << 64) if x >> 63 else x for x in (a, self.regs[0]))
                prod = sa * sx
                self.regs[0], self.regs[2] = prod & M64, (prod >> 64) & M64
                self.cf = self.of = (self.regs[0] - (1 << 64) if self.regs[0] >> 63 else self.regs[0]) != prod
        else:
            handled = False
        if not handled:
            return super().step(va)
        self.seen.add(va)
        return nxt


def libc_stubs(m, image):
    def memcpy(mc):
        dst, src, n = mc.regs[7], mc.regs[6], mc.regs[2]
        data = bytes(mc.load(src + i, 1) for i in range(n))
        for i, x in enumerate(data):
            mc.store(dst + i, 1, x)
        mc.regs[0] = dst

    def memset(mc):
        dst, value, n = mc.regs[7], mc.regs[6] & 0xff, mc.regs[2]
        for i in range(n):
            mc.store(dst + i, 1, value)
        mc.regs[0] = dst

    for slot in image.imports:
        name = image.import_name(slot)
        if name in ("memcpy", "memmove"):
            m.stubs[image.relative[slot]] = memcpy
        elif name == "memset":
            m.stubs[image.relative[slot]] = memset


# ---------------------------------------------------------------- reconstruction
def sgn(x):
    return x - (1 << 256) if x >> 255 else x


def exp_cost(exponent, per_byte):
    if exponent == 0:
        return 0
    return ((exponent.bit_length() - 1) // 8 + 1) * per_byte


def apply_op(op, st, spec, mut=frozenset()):
    """EVM result of one handler for stack items st = [top, second, third] (pure, no gas)."""
    a = st[0]
    b = st[1] if len(st) > 1 else 0
    c = st[2] if len(st) > 2 else 0
    if "swap_operands" in mut and op in (0x03, 0x04, 0x10, 0x1b):
        a, b = b, a
    if op == 0x01:
        return (a + b) & M256 if "add_nowrap" not in mut else (a + b) & ((1 << 257) - 1)
    if op == 0x02:
        return a * b & M256
    if op == 0x03:
        return (a - b) & M256
    if op == 0x04:
        return a // b if b else (M256 if "div_zero_max" in mut else 0)
    if op == 0x05:
        if b == 0:
            return 0
        if sgn(a) == -(1 << 255) and sgn(b) == -1:
            return 1 << 255 if "sdiv_overflow_zero" not in mut else 0
        q = abs(sgn(a)) // abs(sgn(b))
        if (sgn(a) < 0) != (sgn(b) < 0) and "sdiv_floor_fix" not in mut:
            q = -q
        elif "sdiv_floor_fix" in mut and (sgn(a) < 0) != (sgn(b) < 0):
            q = -q - (1 if abs(sgn(a)) % abs(sgn(b)) else 0)
        return q & M256
    if op == 0x06:
        return a % b if b else (a if "mod_zero_a" in mut else 0)
    if op == 0x07:
        if b == 0:
            return 0
        r = abs(sgn(a)) % abs(sgn(b))
        neg = sgn(a) < 0 if "smod_divisor_sign" not in mut else sgn(b) < 0
        return (-r if neg else r) & M256
    if op == 0x08:
        if c == 0:
            return 0
        return ((a + b) & M256) % c if "addmod_wrap" in mut else (a + b) % c
    if op == 0x09:
        if c == 0:
            return 0
        return ((a * b) & M256) % c if "mulmod_wrap" in mut else (a * b) % c
    if op == 0x0a:
        return pow(a, b, 1 << 256)
    if op == 0x0b:
        lim = 31 if "signext_30" not in mut else 30
        if a >= lim:
            return b
        bits = 8 * (a + 1) if "signext_off" not in mut else 8 * a + 7
        low = b & ((1 << bits) - 1)
        return (low | (M256 ^ ((1 << bits) - 1))) & M256 if (low >> (bits - 1)) & 1 else low
    if op == 0x10:
        return int(a < b)
    if op == 0x11:
        return int(a > b) if "gt_ge" not in mut else int(a >= b)
    if op == 0x12:
        return int(sgn(a) < sgn(b)) if "slt_unsigned" not in mut else int(a < b)
    if op == 0x13:
        return int(sgn(a) > sgn(b))
    if op == 0x14:
        return int(a == b) if "eq_ne" not in mut else int(a != b)
    if op == 0x15:
        return int(a == 0)
    if op == 0x16:
        return a & b
    if op == 0x17:
        return a | b
    if op == 0x18:
        return a ^ b
    if op == 0x19:
        return M256 ^ a
    if op == 0x1a:
        index = a if "byte_mod256" not in mut else a & 0xff
        return (b >> (8 * (31 - index))) & 0xff if index < 32 else 0
    if op == 0x1b:
        return (b << a) & M256 if a < (256 if "shl_255" not in mut else 255) else 0
    if op == 0x1c:
        return b >> a if a < 256 else 0
    if op == 0x1d:
        if a >= 256:
            return M256 if "sar_big_zero" not in mut and b >> 255 else 0
        return (sgn(b) >> a) & M256 if "sar_logical" not in mut else b >> a
    if op == 0x1e:
        return 256 - a.bit_length() if "clz_257" not in mut else 257 - a.bit_length()
    fail(f"unmodelled opcode {op:#x}")


def model(c, mut=frozenset()):
    """Expected (result code, new stack length, replaced stack words {index: word}, gas)."""
    op, spec, n, st, gas = c["op"], c["spec"], c["n"], c["stack"], c["gas"]
    gate = GATE.get(op)
    if gate is not None:
        gate -= 1 if (op == 0x1e and "gate_clz_12" in mut) or (op != 0x1e and "gate_shift_4" in mut) else 0
        if spec < gate:
            return R_NOT_ACTIVATED, n, {}, gas
    need = ARITY.get(op, 2)
    if "underflow_iszero_2" in mut and op == 0x15:
        need = 2
    if n < need:
        return R_UNDERFLOW, n, {}, gas
    top = list(reversed(st[n - need:]))
    if op == 0x0a:
        cost = exp_cost(top[1], c["per_byte"]) if "exp_bits" not in mut else top[1].bit_length() * c["per_byte"] // 8
        if "exp_plus1" in mut and cost:
            cost += 1
        if "exp_zero_charges" in mut and top[1] == 0:
            cost = c["per_byte"]
        cost = min(cost, M64) if cost >> 64 == 0 else M64
        if cost > gas or ("exp_oog_ge" in mut and cost >= gas):
            return R_OOG, n - 1, {}, gas
        return R_OK, n - 1, {n - 2: apply_op(op, top, spec, mut)}, gas - cost
    res = apply_op(op, top, spec, mut)
    new_n = n - need + 1
    return R_OK, new_n, {new_n - 1: res}, gas


# ---------------------------------------------------------------- cases
POOL_EDGE = [0, 1, 2, 3, 0xff, 0x100, M64, 1 << 64, (1 << 64) + 1, (1 << 128) - 1, 1 << 128, 1 << 255, (1 << 255) - 1,
             (1 << 255) + 1, M256, M256 - 1, 0x80, 0x7f, 0xffff_ffff, 1 << 192]
SHIFTS = [0, 1, 7, 8, 31, 32, 63, 64, 65, 127, 128, 129, 191, 192, 193, 254, 255, 256, 257, 1 << 64, 1 << 255, M256]
INDEXES = [0, 1, 2, 15, 16, 30, 31, 32, 33, 255, 256, 1 << 64, 1 << 255, M256]
PER_BYTE = [50, 50, 50, 10, 0, 1, 2, 300, 1 << 60, M64]
SPECS = [0, 1, 4, 5, 6, 11, 12, 13, 14, 20, 0xff]


def word(s):
    k = s.below(16)
    if k < 5:
        return s.pick(POOL_EDGE)
    if k == 5:
        return 1 << s.below(256)
    if k == 6:
        return (1 << (1 + s.below(256))) - 1
    if k == 7:
        return s.below(300)
    if k == 8:
        return M256 ^ s.below(300)
    if k == 9:
        x = int.from_bytes(s.take(32), "little")
        return x & ~(M64 << (64 * s.below(4))) & M256
    if k == 10:
        return int.from_bytes(s.take(1 + s.below(32)), "little")
    return int.from_bytes(s.take(32), "little")


def operand(s, op, slot):
    """The word for stack slot `slot` (0 = top) of op, biased to the interesting values."""
    k = s.below(3)
    if 0x04 <= op <= 0x09 and s.below(3) == 0 and not (op in (0x08, 0x09) and slot == 2 and k):
        # whole-limb sized values with a random number of leading zero bits exercise every division path
        return int.from_bytes(s.take(8 * (1 + s.below(4))), "little") >> s.below(64)
    if op in (0x1b, 0x1c, 0x1d) and slot == 0:
        return s.pick(SHIFTS) if k else s.below(300)
    if op in (0x0b, 0x1a) and slot == 0:
        return s.pick(INDEXES) if k else s.below(40)
    if op == 0x0a and slot == 1:
        if k == 0:
            return s.pick([0, 1, 2, 0xff, 0x100, 0xffff, 1 << 16, M64])
        return int.from_bytes(s.take(1 + s.below(3 if s.below(8) else 9)), "little")
    if op in (0x08, 0x09) and slot == 2:
        return s.pick([0, 1, 2, M256, M256 - 1, 1 << 255, 3]) if k else word(s)
    if op in (0x04, 0x05, 0x06, 0x07) and slot == 1:
        return s.pick([0, 1, M256, 1 << 255, 2, 3, (1 << 128), M64]) if k == 0 else word(s)
    return word(s)


def make_case(s, fam, op, i):
    arity = ARITY.get(op, 2)
    gate = GATE.get(op)
    spec = s.pick(SPECS)
    if gate is not None and s.below(2):
        spec = s.pick([gate - 1, gate, gate + 1])
    n = s.below(arity) if s.below(8) == 0 else arity + s.pick([0, 0, 0, 1, 2, 5])
    stack = [word(s) for _ in range(n)]
    for slot in range(min(n, arity)):
        stack[n - 1 - slot] = operand(s, op, slot)
    if op in (0x04, 0x05, 0x06, 0x07, 0x1c, 0x1d, 0x10, 0x11, 0x12, 0x13, 0x14) and n >= 2 and s.below(6) == 0:
        stack[n - 2] = stack[n - 1]  # equal operands
    if op == 0x05 and n >= 2 and s.below(6) == 0:
        stack[n - 1], stack[n - 2] = 1 << 255, M256  # the one overflowing signed division
    per_byte = s.pick(PER_BYTE)
    gas = s.pick([0, 1, 21000, M64, 1 << 40]) if s.below(2) else s.below(1 << 24)
    if op == 0x0a and n >= 2:
        cost = exp_cost(stack[n - 2], per_byte)
        if s.below(3):
            gas = max(0, min(M64, cost + s.pick([-1, 0, 1, 2, 1000])))
    return {"fam": fam, "op": op, "spec": spec, "n": n, "stack": stack, "gas": gas, "per_byte": per_byte, "i": i}


COUNTS = {0x0a: 120}
PER_OP = 200


def cases_for(fam, op):
    s = base.Stream(f"evm-arith-{fam}-{op:#x}")
    return [make_case(s, fam, op, i) for i in range(COUNTS.get(op, PER_OP))]


def groups():
    for fam in sorted(TABLES):
        for op in sorted(NAMES):
            yield fam, op


# ---------------------------------------------------------------- handlers
def handler_of(image, fam, op):
    got = {image.relative.get(t + 8 * op) for t in TABLES[fam]}
    if len(got) != 1 or None in got:
        fail(f"opcode tables of family {fam} disagree at slot {op:#x}: {got}")
    return got.pop()


# ---------------------------------------------------------------- execution
def run_case(m, image, c, entry):
    m.reset()
    libc_stubs(m, image)
    n = c["n"]
    cap = n + 2
    stk0 = b"".join(w.to_bytes(32, "little") for w in c["stack"]) + bytes([FILL_STK]) * (32 * (cap - n))
    it = m.add_region(INT_AT, INT_SIZE, bytes([FILL_INT]) * INT_SIZE)
    base.put(it, I_STACK_PTR, 8, STK_AT)
    base.put(it, I_STACK_LEN, 8, n)
    base.put(it, I_GAS, 8, c["gas"])
    it[I_SPEC] = c["spec"]
    host = m.add_region(HOST_AT, HOST_SIZE, bytes([FILL_HOST]) * HOST_SIZE)
    base.put(host, H_GASTAB, 8, TAB_AT)
    tab = m.add_region(TAB_AT, TAB_SIZE, bytes([FILL_TAB]) * TAB_SIZE)
    base.put(tab, T_EXPBYTE, 8, c["per_byte"])
    stk = m.add_region(STK_AT, 32 * cap, stk0)
    before = {"int": bytes(it), "host": bytes(host), "tab": bytes(tab)}
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = INT_AT, HOST_AT
    got = {"stk0": stk0, "before": before}
    try:
        m.run(entry, limit=400000)
    except Boundary as b:
        got["ret"] = ("panic", b.kind)
        return got
    got["ret"] = ("ret", m.regs[0] & 0xff)
    got["regs_ok"] = [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == base.STACK_TOP - 0x100
    got["after"] = {"int": bytes(it), "host": bytes(host), "tab": bytes(tab), "stk": bytes(stk)}
    got["n"] = base.u(it, I_STACK_LEN, 8)
    got["gas"] = base.u(it, I_GAS, 8)
    return got


def expected(c, want, got):
    code, new_n, repl, gas = want
    it = bytearray(got["before"]["int"])
    base.put(it, I_STACK_LEN, 8, new_n)
    base.put(it, I_GAS, 8, gas)
    stk = bytearray(got["stk0"])
    for idx, w in repl.items():
        if not 0 <= w <= M256:  # a mutant produced a value that is no stack word: never equal to the machine
            return None
        stk[32 * idx:32 * idx + 32] = w.to_bytes(32, "little")
    return code, bytes(it), bytes(stk)


def compare(c, want, got):
    if got["ret"][0] != "ret":
        return False
    exp = expected(c, want, got)
    if exp is None:
        return False
    code, it, stk = exp
    a = got["after"]
    return (got["ret"][1] == code and got["regs_ok"] and a["int"] == it and a["stk"] == stk
            and a["host"] == got["before"]["host"] and a["tab"] == got["before"]["tab"])


def evaluate_group(image, entry, cases, machine, mut=frozenset(), stop=False):
    """Run cases through the code at entry; returns (list of (case, want, got, ok), mismatches)."""
    rows, bad = [], 0
    for c in cases:
        try:
            want = model(c, mut)
            got = run_case(machine, image, c, entry)
            ok = compare(c, want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc), "ret": ("error", 0)}, False
        bad += not ok
        rows.append((c, want, got, ok))
        if stop and not ok:
            break
    return rows, bad


def detects(image, entry, cases, mut=frozenset(), override=None):
    m = XMachine(image, override)
    _, bad = evaluate_group(image, entry, cases, m, mut, stop=True)
    return bad > 0


# ---------------------------------------------------------------- static evidence
def handler_table(image):
    return {(fam, op): handler_of(image, fam, op) for fam, op in groups()}


def static_rows(image, handlers):
    starts = sorted(set(handlers.values()))
    extents = base.fde_rows(image, starts)
    decoded = {h: base.sweep_padded(image, *extents[h]) for h in starts}
    info = {}
    for h in starts:
        lo, hi = extents[h]
        gate = result_codes = under = None
        codes, calls, cmps = set(), [], []
        for va, f in decoded[h]:
            if f is None:
                continue
            if f["op"] == 0xb0 and f["r"] == 0:
                codes.add(f["imm"])
            elif f["op"] == 0x80 and f["reg"] & 7 == 7 and f["rm"][0] == "m" and f["rm"][4] == I_SPEC:
                gate = f["imm"] & 0xff if gate is None else gate
            elif f["op"] == 0x83 and f["reg"] & 7 == 7 and f["rm"][0] == "r" and len(cmps) < 1:
                cmps.append((va, f["imm"]))
            elif f["op"] == 0xe8:
                calls.append(f["target"])
            elif f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip":
                calls.append(image.word((va + f["len"] + f["rm"][4]) & M64))
        info[h] = {"lo": lo, "hi": hi, "gate": gate, "codes": sorted(codes), "calls": calls,
                   "arity_cmp": cmps[0][1] if cmps else None, "sha": hashlib.sha256(image.code(lo, hi - lo)).hexdigest()}
    return decoded, info


def byte_mutants(image, handlers, decoded):
    """Single-byte code mutants derived from the decoded handlers: result codes, spec gates, arity compares."""
    rows = []
    for (fam, op), h in sorted(handlers.items()):
        done_cmp = False
        for va, f in decoded[h]:
            if f is None:
                continue
            at = va + f["len"] - 1
            if f["op"] == 0xb0 and f["r"] == 0 and f["imm"] in (R_OOG, R_NOT_ACTIVATED, R_UNDERFLOW):
                rows.append((fam, op, at, (f["imm"] + 1) & 0xff, f"result code {f['imm']:#04x} -> {f['imm'] + 1:#04x}"))
            elif f["op"] == 0x80 and f["reg"] & 7 == 7 and f["rm"][0] == "m" and f["rm"][4] == I_SPEC:
                rows.append((fam, op, at, f["imm"] - 1, f"spec gate {f['imm']} -> {f['imm'] - 1}"))
                rows.append((fam, op, at, f["imm"] + 1, f"spec gate {f['imm']} -> {f['imm'] + 1}"))
            elif f["op"] == 0x83 and f["reg"] & 7 == 7 and f["rm"][0] == "r" and not done_cmp and f["imm"] in (1, 2, 3):
                done_cmp = True
                rows.append((fam, op, at, f["imm"] + 1, f"stack depth compare {f['imm']} -> {f['imm'] + 1}"))
                if f["imm"] > 1:
                    rows.append((fam, op, at, f["imm"] - 1, f"stack depth compare {f['imm']} -> {f['imm'] - 1}"))
    return rows


MODEL_MUTANTS = ["add_nowrap", "div_zero_max", "sdiv_overflow_zero", "sdiv_floor_fix", "mod_zero_a", "smod_divisor_sign",
                 "addmod_wrap", "mulmod_wrap", "exp_bits", "exp_plus1", "exp_zero_charges", "exp_oog_ge",
                 "signext_30", "signext_off", "gt_ge", "slt_unsigned", "eq_ne", "byte_mod256", "shl_255", "sar_big_zero",
                 "sar_logical", "clz_257", "gate_shift_4", "gate_clz_12", "underflow_iszero_2", "swap_operands"]


def controls(image, handlers, decoded):
    rows, equiv = [], []
    cache = {}

    def cases(fam, op):
        if (fam, op) not in cache:
            cache[(fam, op)] = cases_for(fam, op)
        return cache[(fam, op)]

    for name in MODEL_MUTANTS:
        mut = frozenset([name])
        hit = False
        for fam, op in groups():
            if detects(image, handlers[(fam, op)], cases(fam, op), mut):
                hit = True
                break
        rows.append(("model", name, int(hit)))
    for fam, op, at, byte, what in byte_mutants(image, handlers, decoded):
        old = image.code(at, 1)[0]
        if old == byte:
            fail(f"byte mutant at {at:#x} does not change the byte")
        hit = detects(image, handlers[(fam, op)], cases(fam, op), override={at: byte})
        rows.append(("code", f"{at:#x}={byte:#04x} {fam}/{NAMES[op]} {what}", int(hit)))
    corrupt = bytearray(image.data)
    corrupt[image.text["offset"] + 7] ^= 1
    try:
        base.Image(bytes(corrupt))
        rows.append(("input", "one flipped .text byte", 0))
    except ToolError:
        rows.append(("input", "one flipped .text byte", 1))
    try:
        image.code(image.text["address"] + image.text["size"] + 0x100, 4)
        rows.append(("input", "address past .text", 0))
    except ToolError:
        rows.append(("input", "address past .text", 1))
    wrong = dict(handlers)
    wrong[("B", 0x03)] = handlers[("B", 0x01)]  # table slot SUB pointed at ADD
    rows.append(("input", "SUB slot pointed at the ADD handler",
                 int(detects(image, wrong[("B", 0x03)], cases("B", 0x03)))))
    return rows, equiv


# ---------------------------------------------------------------- output
def wtag(x):
    if x is None:
        return "-"
    if x < 1 << 64:
        return f"{x:#x}"
    return "w" + hashlib.sha256(x.to_bytes(32, "little")).hexdigest()[:8]


def outcome(c, want):
    code = want[0]
    kind = {R_OK: "ok", R_OOG: "out-of-gas", R_NOT_ACTIVATED: "not-activated", R_UNDERFLOW: "underflow"}[code]
    return f"{NAMES[c['op']].lower()}/{kind}"


def coverage(image, machine, decoded):
    """Per-function executed/total instruction counts for the handlers and every callee the cases reached."""
    _, fdes = base.fde_extents.eh_frame_records(image.data, image.secs)
    spans = sorted((f["start"], f["end"]) for f in fdes)
    funcs, seen = {}, machine.seen
    import bisect
    starts = [s for s, _ in spans]
    for va in seen:
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and spans[i][0] <= va < spans[i][1]:
            funcs[spans[i]] = True
    out, missing = {}, []
    for lo, hi in sorted(funcs):
        rows = decoded.get(lo)
        if rows is None:
            try:
                rows = base.sweep_padded(image, lo, hi)
            except ToolError:
                rows = None
        if rows is None:
            hit = sum(1 for va in seen if lo <= va < hi)
            out[f"{lo:#x}"] = [hit, None]
            continue
        total = [(va, f) for va, f in rows if f is not None]
        hit = [va for va, f in total if va in seen]
        out[f"{lo:#x}"] = [len(hit), len(total)]
        missing += [(lo, va, f) for va, f in total if va not in seen]
    return out, missing


def generate(out):
    image = base.Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    handlers = handler_table(image)
    decoded, info = static_rows(image, handlers)
    lines = ["case\tfamily\topcode\tname\tspec\tn\tgas\tper_byte\ttop_words\toutcome\tresult\tmatch"]
    classes, total, bad = {}, 0, 0
    machine = XMachine(image)
    case_id = 0
    for fam, op in groups():
        rows, nbad = evaluate_group(image, handlers[(fam, op)], cases_for(fam, op), machine)
        bad += nbad
        for c, want, got, ok in rows:
            oc = outcome(c, want) if want else "error"
            if "error" in got:
                res = got["error"]
            elif got["ret"][0] == "panic":
                res = "panic"
            else:
                a = got["after"]
                res = f"ret={got['ret'][1]:#x},n={got['n']},gas={got['gas']},top={wtag(base.u(a['stk'], 32 * (got['n'] - 1), 32)) if 0 < got['n'] <= c['n'] else '-'}"
            top = ",".join(wtag(w) for w in reversed(c["stack"][-3:])) or "-"
            classes[oc] = classes.get(oc, 0) + 1
            lines.append(f"{case_id}\t{fam}\t{op:#x}\t{NAMES[op]}\t{c['spec']}\t{c['n']}\t{c['gas']}\t{c['per_byte']}\t{top}\t{oc}\t{res}\t{'yes' if ok else 'NO'}")
            case_id += 1
    total = case_id
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    hl = ["family\topcode\tname\ttable_slots\thandler\tfde_end\tbytes\tarity\tspec_gate\tresult_codes\tdepth_compare\tcalls\tsha256"]
    for (fam, op), h in sorted(handlers.items()):
        i = info[h]
        slots = "+".join(f"{t + 8 * op:#x}" for t in TABLES[fam])
        hl.append("\t".join([fam, f"{op:#x}", NAMES[op], slots, f"{h:#x}", f"{i['hi']:#x}", str(i["hi"] - i["lo"]),
                             str(ARITY.get(op, 2)), "-" if i["gate"] is None else str(i["gate"]),
                             ",".join(f"{x:#x}" for x in i["codes"]) or "-",
                             "-" if i["arity_cmp"] is None else str(i["arity_cmp"]),
                             ",".join(f"{x:#x}" for x in i["calls"]) or "-", i["sha"]]))
    (out / "handlers.tsv").write_text("\n".join(hl) + "\n")
    cov, missing = coverage(image, machine, decoded)
    runs = []  # merge adjacent unexecuted instructions into [first, end) runs per function
    for lo, va, f in missing:
        if runs and runs[-1][0] == lo and runs[-1][2] == va:
            runs[-1][2], runs[-1][3] = va + f["len"], runs[-1][3] + 1
        else:
            runs.append([lo, va, va + f["len"], 1])
    mt = ["function\tfirst\tend\tinstructions"]
    mt += [f"{lo:#x}\t{first:#x}\t{end:#x}\t{k}" for lo, first, end, k in runs]
    (out / "unexecuted-ranges.tsv").write_text("\n".join(mt) + "\n")
    ctl, equiv = controls(image, handlers, decoded)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    detected = sum(r[2] for r in ctl)
    equiv_n = len(equiv)
    if equiv:
        (out / "equivalent-mutants.tsv").write_text(
            "mutant\taddress\treason\n" + "".join("\t".join(r) + "\n" for r in equiv))
    summary = {"binary_sha256": SHA256, "cases": total, "mismatches": bad,
               "covered_instructions": {k: f"{v[0]}/{v[1]}" for k, v in cov.items()},
               "outcome_classes": len(classes), "handlers": len(set(handlers.values())),
               "negative_controls": {"total": len(ctl), "detected": detected, "equivalent": equiv_n}}
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": total, "negative_controls": len(ctl),
                                                  "negative_detected": detected, "equivalent": equiv_n},
                                                 indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    nc = summary["negative_controls"]
    return 1 if summary["mismatches"] or nc["detected"] + nc["equivalent"] != nc["total"] else 0


if __name__ == "__main__":
    sys.exit(main())
