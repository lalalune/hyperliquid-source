"""Float-to-decimal conversion of node #115, recovered from bytes.

Function 0x5c43c60 turns a 96-bit mantissa and a binary exponent into a
sign/scale/96-bit decimal (a base-2 to base-10 conversion with an overflow
refusal, a 28-digit scale clamp and two optional significant-digit trims).
Function 0x43099f0 is its f64 caller: it reads a value, splits the f64 bits
into mantissa and exponent and calls the converter with both flags set.
The tool runs both bodies from the binary bytes in the shared evaluator and
compares every result with an independent Python specification.
"""
import argparse
import copy
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as cpu  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
KERNEL = 0x5c43c60
OUTER = 0x43099f0
U64 = cpu.U64
IN = cpu.INPUT
OUT = IN + 0x1000
SP = cpu.STACK + 0x10000
MARK = cpu.RETURN_MARK
OK_TAG = 0x1a2
ERR_TAG = 0xb0
PASSTHROUGH = 6
MASK96 = (1 << 96) - 1
SCALE_MAX = 28


class Machine(cpu.Machine):
    """Shared evaluator plus ror by an immediate (used by the divisibility test)."""

    def shift(self, kind, value, count, bits):
        if kind != 1:
            return super().shift(kind, value, count, bits)
        if bits != 64 or value is None or count is None or not 1 <= count <= 63:
            raise cpu.ToolError("ror outside the modelled 64-bit immediate domain")
        result = ((value >> count) | (value << (64 - count))) & U64
        self.flags = [bool(result >> 63), self.flags[1], self.flags[2], None]
        return result


    def two_byte(self, insn, key, bits, rexr, here):
        reg = ((self.image.data[insn.modrm] >> 3) & 7) | rexr if insn.modrm is not None else 0
        if len(key) == 2 and key[1] == 0x7e and insn.rep == 0xf3:  # movq xmm, m64
            self.xmm[reg] = self.read(self.operand(insn), 64).to_bytes(8, "little") + bytes(8)
            return
        if len(key) == 2 and key[1] == 0x7e and insn.wide16 and bits == 64:  # movq r64, xmm
            if self.xmm[reg] is None:
                raise cpu.ToolError("movq from an unset xmm register")
            self.write(self.operand(insn), 64, int.from_bytes(self.xmm[reg][:8], "little"))
            return
        if len(key) == 2 and key[1] in (0x6f, 0x7f) and insn.rep == 0xf3:  # movdqu load / store
            operand = self.operand(insn)
            if operand[0] != "m":
                raise cpu.ToolError("movdqu register form")
            at = self.address(operand)
            if key[1] == 0x6f:
                self.xmm[reg] = self.load(at, 8).to_bytes(8, "little") + self.load(at + 8, 8).to_bytes(8, "little")
            else:
                self.store(at, 8, int.from_bytes(self.xmm[reg][:8], "little"))
                self.store(at + 8, 8, int.from_bytes(self.xmm[reg][8:], "little"))
            return
        super().two_byte(insn, key, bits, rexr, here)


def wr(m, at, data):
    for i, b in enumerate(data):
        m.mem[at + i] = b


def rd(m, at, n):
    return bytes(m.mem[at + i] for i in range(n))


def finish(m, limit=2_000_000):
    """Step until the return mark or a stop; return how it ended."""
    try:
        for _ in range(limit):
            m.step()
    except cpu.Done as done:
        return done
    raise cpu.ToolError("step bound")


def run_kernel(image, lo, mid, hi, e2, positive, is64, rounding):
    """Execute 0x5c43c60 on one input; returns (tag, flags, hi, lo_mid, steps, pcs)."""
    m = Machine(image)
    wr(m, IN, struct.pack("<III", lo, mid, hi))
    wr(m, OUT, bytes(0x20))
    wr(m, SP, struct.pack("<Q", MARK))
    for reg, val in ((cpu.RSP, SP), (cpu.RDI, OUT), (cpu.RSI, IN), (cpu.RDX, e2 & 0xffffffff), (cpu.RCX, positive),
                     (cpu.R8, is64), (cpu.R9, rounding)):
        m.set_reg(reg, val)
    m.pc = KERNEL
    done = finish(m)
    if done.how != "ret":
        raise cpu.ToolError("converter stopped by %s at %#x" % (done.how, m.pc))
    tag = struct.unpack("<I", rd(m, OUT, 4))[0]
    if tag == 0:
        return (0, None, None, None, m.steps, m.seen)
    flags, hi_w, lo_mid = struct.unpack("<IIQ", rd(m, OUT + 4, 16))
    return (tag, flags, hi_w, lo_mid, m.steps, m.seen)


# ---------------------------------------------------------------------------
# Independent specification, written from the listing.
# ---------------------------------------------------------------------------
def div10_round(x, mut=()):
    q, r = divmod(x, 10)
    if "floor_trim" in mut:
        return q
    if "round_gt5" in mut:
        return q + (1 if r > 5 else 0)
    if "round_up_any" in mut:
        return q + (1 if r else 0)
    return q + (1 if r >= 5 else 0)


def spec_kernel(lo, mid, hi, e2, positive, is64, rounding, mut=()):
    """Return None for the refusal, else (flags, hi, lo_mid) of the produced decimal."""
    m = lo | (mid << 32) | (hi << 64)
    e10 = e2
    top = 94 if "top_bit_94" in mut else 95
    smax = 29 if "scale_29" in mut else 27 if "scale_27" in mut else SCALE_MAX
    if e2 > 0:
        for _ in range(e2):
            if (m >> top) & 1 and "no_div5" not in mut:
                m //= 5
            else:
                m = (m << 1) & MASK96
                e10 -= 1
        if e10 > 0:
            for _ in range(e10):
                m *= 10
                if m >> 96:
                    if "no_overflow_refusal" in mut:
                        m &= MASK96
                    else:
                        return None
            e10 = 0
    elif e2 < 0:
        for _ in range(-e2):
            if m & 1 and "odd_always_half" not in mut:
                t = m * 5
                if t >> 96 == 0:
                    m = t
                    continue
            e10 += 1
            m >>= 1
    if e10 < -smax and "no_clamp" not in mut:
        left = -(e10 + smax)
        tiny = 100 if "tiny_100" in mut else 10
        while left > 0:
            if m < tiny and "no_tiny_exit" not in mut:
                m, e10 = 0, 0
                break
            m = div10_round(m, mut)
            left -= 1
        else:
            e10 = -smax
    if rounding and e10 < 0:
        limit = (1 << 52) if is64 or "f32_limit_52" in mut else (1 << 24)
        if "limit_53" in mut:
            limit = 1 << 53
        while e10 < 0:
            if m >= limit:
                m = div10_round(m, mut)
                e10 += 1
                continue
            while e10 < 0 and m % 10 == 0 and "no_strip" not in mut:
                m //= 10
                e10 += 1
            break
    if e10 >= 0:
        e10 = 0
    flags = ((-e10) << (15 if "flags_shift_15" in mut else 16)) & 0xffffffff
    if (not positive) != ("sign_inverted" in mut) and "ignore_sign" not in mut:
        flags |= 0x80000000
    return (flags, m >> 64, m & ((1 << 64) - 1))


def check_kernel_args(lo, mid, hi, e2, positive, is64, rounding):
    for word in (lo, mid, hi):
        if not 0 <= word < 1 << 32:
            raise cpu.ToolError("mantissa word outside u32")
    if not -(1 << 31) <= e2 < (1 << 31):
        raise cpu.ToolError("exponent outside i32")
    for flag in (positive, is64, rounding):
        if flag not in (0, 1):
            raise cpu.ToolError("flag byte is not 0 or 1")


def load_image(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise cpu.ToolError("input binary digest differs from node #115")
    return cpu.Image(data)


# ---------------------------------------------------------------------------
# The f64 caller 0x43099f0
# ---------------------------------------------------------------------------
SITE_READ, SITE_PARSE, SITE_KERNEL, SITE_DROP, SITE_FREE, SITE_FREE_PAD = (
    0x4309a0f, 0x4309a48, 0x4309b04, 0x4309b66, 0x4309ba0, 0x4309bd8)
RSP0 = SP - 0xf8
STR_PTR = 0x7300_0000
ZERO_CONST = (0x4553c4, 0x4553cc)


class Caller(Machine):
    """Runs 0x43099f0 for real; only the two value-reading GOT helpers, the temp drop and the free are stubs."""

    def call(self, target, where):
        if where == SITE_KERNEL:
            self.kernel_args = (self.get(cpu.RSI, 64) - RSP0, self.get(cpu.RDX, 32), self.get(cpu.RCX, 8),
                                self.get(cpu.R8, 8), self.get(cpu.R9, 8))
            return super().call(target, where)
        c = self.case
        g = lambda r: self.get(r, 64)  # noqa: E731
        if where == SITE_READ:
            self.trace.append(("read", g(cpu.RDI) - RSP0, g(cpu.RSI), g(cpu.RDX)))
            wr(self, g(cpu.RDI), struct.pack("<I", c["tag"]) + c["blob"])
        elif where == SITE_PARSE:
            self.trace.append(("parse", g(cpu.RDI) - RSP0, g(cpu.RSI), g(cpu.RDX)))
            wr(self, g(cpu.RDI), bytes([1 if c["parse_err"] else 0]) + bytes(7) + struct.pack("<Q", c["bits"]))
        elif where == SITE_DROP:
            self.trace.append(("drop_tmp", g(cpu.RDI) - RSP0, struct.unpack("<H", rd(self, g(cpu.RDI), 2))[0]))
        elif where in (SITE_FREE, SITE_FREE_PAD):
            self.trace.append(("free", g(cpu.RDI), g(cpu.RSI), g(cpu.RDX)))
        else:
            raise cpu.ToolError("unexpected call at %#x" % where)
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        self.xmm = [None] * 16
        self.flags = [None, None, None, None]


def run_caller(image, case):
    m = Caller(image)
    m.case, m.trace, m.kernel_args = case, [], None
    wr(m, OUT, bytes(0x20))
    wr(m, SP, struct.pack("<Q", MARK))
    for reg, val in ((cpu.RSP, SP), (cpu.RDI, OUT), (cpu.RSI, STR_PTR + case["ptr"]), (cpu.RDX, case["len"])):
        m.set_reg(reg, val)
    m.pc = OUTER
    done = finish(m)
    if done.how != "ret":
        raise cpu.ToolError("caller stopped by %s" % done.how)
    tag = struct.unpack("<H", rd(m, OUT, 2))[0]
    payload = rd(m, OUT + 4, 16) if tag == OK_TAG else None
    return tag, payload, m.trace, m.kernel_args, m.seen


def zero_bytes(image):
    out = b""
    for va, n in zip(ZERO_CONST, (8, 4)):
        off = image.file_offset(va)
        out += image.data[off:off + n]
    return out


def spec_caller(image, case, mut=()):
    """Return (tag, payload, trace, kernel_args) the caller must produce for the stub answers in `case`."""
    t = [("read", 0x30, STR_PTR + case["ptr"], case["len"])]
    tag = case["tag"]
    blob = case["blob"]
    pass_tag = 7 if "passthrough_tag7" in mut else PASSTHROUGH
    if tag == pass_tag:
        return OK_TAG, blob[:16], t, None
    r14 = struct.unpack("<Q", blob[4:12])[0]
    r15 = struct.unpack("<Q", blob[12:20])[0]
    free_hi = 5 if "free_tags_5" in mut else 4
    needs_free = not ((tag - 1) & 0xffffffff < free_hi) and (r14 != 0 or "free_ignore_null" in mut)

    def end(out_tag, payload, kargs):
        if needs_free:
            t.append(("free", r15, r14, 0))
        return out_tag, payload, t, kargs

    t.append(("parse", 0x50, STR_PTR + case["ptr"], case["len"]))
    if case["parse_err"]:
        return end(ERR_TAG, None, None)
    bits = case["bits"]
    if (bits & ((1 << 63) - 1)) >= 0x7ff0000000000000 and "nonfinite_accepted" not in mut:
        return end(ERR_TAG, None, None)
    expo = (bits >> 52) & 0x7ff
    frac = bits & ((1 << 52) - 1)
    positive = 1 if bits >> 63 == 0 else 0
    if "wrong_flag_sign" in mut:
        positive ^= 1
    kargs = None
    if expo != 0:
        lo, mid, e2 = frac & 0xffffffff, (frac >> 32) | (0 if "no_implicit_bit" in mut else 0x100000), expo - 1075
    elif frac != 0:
        lo, mid, e2 = frac & 0xffffffff, frac >> 32, -1075 if "denormal_bias_1075" in mut else -1074
    else:
        flags = 0 if "zero_sign_dropped" in mut else (bits >> 63) << 31
        dec = struct.pack("<I", flags) + zero_bytes(image)
        t.append(("drop_tmp", 0x50, ERR_TAG))
        return end(OK_TAG, dec, None)
    is64 = 0 if "kernel_is64_0" in mut else 1
    rounding = 0 if "kernel_round_0" in mut else 1
    kargs = (0x50, e2 & 0xffffffff, positive, is64, rounding)
    res = spec_kernel(lo, mid, 0, e2, positive, is64, rounding, mut)
    if res is None:
        return end(ERR_TAG, None, kargs)
    t.append(("drop_tmp", 0x50, ERR_TAG))
    return end(OK_TAG, struct.pack("<IIQ", *res), kargs)


# ---------------------------------------------------------------------------
# Case generation (deterministic)
# ---------------------------------------------------------------------------
KERNEL_MUTANTS = ("no_div5", "odd_always_half", "floor_trim", "round_gt5", "round_up_any", "limit_53", "ignore_sign",
                  "no_overflow_refusal", "scale_29", "scale_27", "tiny_100", "no_strip", "no_tiny_exit",
                  "f32_limit_52", "top_bit_94", "flags_shift_15", "no_clamp", "sign_inverted")
CALLER_MUTANTS = ("denormal_bias_1075", "no_implicit_bit", "zero_sign_dropped", "nonfinite_accepted", "free_tags_5",
                  "free_ignore_null", "passthrough_tag7", "kernel_is64_0", "kernel_round_0", "wrong_flag_sign")
# (address, offset inside the instruction, original byte, replacement, meaning)
PATCHES = (
    (0x5c43fa2, 5, 0x10, 0x20, "f64 trim limit 2^52 -> 2^53"),
    (0x5c43e5e, 3, 0x1c, 0x1d, "scale clamp 28 -> 29"),
    (0x5c43dcd, 0, 0x7e, 0x7c, "jle -> jl after the exponent-ten loops"),
    (0x5c43e31, 3, 0xe3, 0xe2, "clamp threshold -29 -> -30"),
    (0x5c44008, 3, 0x04, 0x05, "round-half-up threshold 4 -> 5 in the f64 trim"),
    (0x5c43d58, 0, 0x7e, 0x7f, "halving loop condition jle -> jg"),
    (0x5c4407e, 6, 0x01, 0x02, "f32 trim limit 2^24 -> 2^25"),
    (0x5c44191, 0, 0x77, 0x72, "zero-strip ja -> jb"),
    (0x5c43ee2, 0, 0x72, 0x73, "tiny-value exit jb -> jae"),
    (0x5c43d5a, 2, 0x01, 0x02, "odd test bit 1 -> bit 2"),
    (0x5c43f4b, 1, 0x84, 0x85, "rounding flag test inverted"),
    (0x5c43f54, 1, 0x84, 0x85, "is64 flag test inverted"),
    (0x5c43f5d, 1, 0x89, 0x88, "negative-exponent test inverted"),
    (0x4309a84, 1, 0x8d, 0x8c, "non-finite test inverted"),
    (0x4309ac0, 2, 0xcd, 0xcc, "exponent bias 1075 -> 1076"),
    (0x4309ae1, 1, 0xce, 0xcf, "denormal exponent -1074 -> -1073"),
    (0x4309af8, 2, 0x01, 0x00, "is64 argument 1 -> 0"),
    (0x4309afe, 2, 0x01, 0x00, "rounding argument 1 -> 0"),
    (0x4309a19, 2, 0x06, 0x05, "passthrough tag 6 -> 5"),
    (0x4309b14, 2, 0x01, 0x02, "converter success tag 1 -> 2"),
    (0x4309b8b, 1, 0x92, 0x93, "free condition tag range inverted"),
)


def kernel_case(rng, kind):
    """Pick one converter input of class `kind`."""
    if kind == "f32":
        return (rng.getrandbits(24), 0, 0, rng.randint(-160, 160), rng.getrandbits(1), 0, rng.getrandbits(1))
    if kind == "wide_mantissa":
        return (rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(32), rng.randint(-70, 70), rng.getrandbits(1),
                rng.getrandbits(1), rng.getrandbits(1))
    if kind == "tiny":
        return (rng.randint(0, 40), rng.choice((0, 0, 1)), 0, rng.randint(-100, 40), rng.getrandbits(1), rng.getrandbits(1),
                rng.getrandbits(1))
    if kind == "multiply_overflow":
        return (rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(31), rng.choice((1, 1, 2, 3, rng.randint(1, 60))),
                rng.getrandbits(1), 1, 1)
    if kind == "clamp_edge":
        return (rng.getrandbits(32), rng.getrandbits(21) | (1 << 20), 0, -rng.randint(128, 165), rng.getrandbits(1),
                rng.getrandbits(1), rng.getrandbits(1))
    if kind == "scale_edge":
        return (rng.getrandbits(32), rng.getrandbits(21) | (1 << 20), 0, -rng.randint(48, 60), rng.getrandbits(1),
                rng.getrandbits(1), rng.getrandbits(1))
    if kind == "carry_edge":
        if rng.getrandbits(1):
            q = (rng.getrandbits(rng.choice((20, 40, 58))) << 32) | 0xffffffff
        else:
            q = (rng.getrandbits(rng.choice((6, 18, 26))) << 64) | ((1 << 64) - 1)
        m = 2 * q + 1
        return (m & 0xffffffff, (m >> 32) & 0xffffffff, (m >> 64) & 0xffffffff, -1, rng.getrandbits(1),
                rng.getrandbits(1), 1)
    if kind == "round_edge":
        digits = rng.choice((5, 15, 25, 35, 45, 55, 65, 75, 85, 95, 105, 995, 9995, 99995))
        m = digits * 10 ** rng.randint(0, 20) + rng.choice((0, 0, 1, -1))
        return (m & 0xffffffff, (m >> 32) & 0xffffffff, (m >> 64) & 0xffffffff, rng.randint(-30, -1), rng.getrandbits(1),
                rng.getrandbits(1), 1)
    span = {"f64_small": 40, "f64_mid": 140, "f64_wide": 1100}[kind]
    return (rng.getrandbits(32), rng.getrandbits(21) | (1 << 20), 0, rng.randint(-span, span), rng.getrandbits(1), 1,
            rng.getrandbits(1))


def kernel_plan():
    """Class -> count; the order is the order cases appear in the evidence."""
    return (("tiny", 900), ("f64_small", 3200), ("f64_mid", 3000), ("f64_wide", 260), ("f32", 1300),
            ("wide_mantissa", 700), ("round_edge", 700), ("multiply_overflow", 400), ("clamp_edge", 350),
            ("carry_edge", 300), ("scale_edge", 400))


EDGE_BITS = (0, 1 << 63, 1, (1 << 63) | 1, (1 << 52) - 1, 1 << 52, 0x3ff0000000000000, 0xbff0000000000000,
             0x3fb999999999999a, 0x4024000000000000, 0x7fefffffffffffff, 0xffefffffffffffff, 0x7ff0000000000000,
             0xfff0000000000000, 0x7ff8000000000000, 0x7ff0000000000001, 0x0010000000000000, 0x000fffffffffffff,
             0x3c9fffffffffffff, 0x4340000000000000, 0x43e0000000000000, 0x44b52d02c7e14af6, 0x3e45798ee2308c3a,
             0x5fe0000000000000, 0x2000000000000000)


def caller_case(rng, index):
    tag = rng.choice((6, 6, 6, 0, 1, 2, 3, 4, 5, 7, 8, 9)) if index % 3 else 6
    blob = bytes(rng.getrandbits(8) for _ in range(28))
    if rng.getrandbits(2) == 0:
        blob = blob[:4] + bytes(8) + blob[12:]
    if index < len(EDGE_BITS) * 3:
        bits = EDGE_BITS[index // 3]
    else:
        kind = rng.randrange(6)
        sign = rng.getrandbits(1) << 63
        if kind == 0:
            bits = rng.getrandbits(64)
        elif kind == 1:
            bits = sign | (rng.randint(1000, 1100) << 52) | rng.getrandbits(52)
        elif kind == 2:
            bits = sign | (rng.randint(0x3f0, 0x410) << 52) | rng.getrandbits(52)
        elif kind == 3:
            bits = sign | rng.getrandbits(52)
        elif kind == 4:
            bits = sign | (rng.randint(0, 0x7ff) << 52)
        else:
            bits = struct.unpack("<Q", struct.pack("<d", round(rng.uniform(-1e6, 1e6), rng.randint(0, 9))))[0]
    return dict(tag=tag, blob=blob, ptr=rng.getrandbits(12), len=rng.randint(0, 400), parse_err=rng.random() < 0.06, bits=bits)


def tag_name(t):
    return {OK_TAG: "ok", ERR_TAG: "err"}.get(t, "tag%#x" % t)


def program_extents(image, data):
    """Instruction boundaries of the two bodies, from the FDE extents of the binary."""
    import fde_extents as fe
    ends = {row["start"]: row["end"] for row in fe.fde_extents(data)[1]}
    out = {}
    for start in (OUTER, KERNEL):
        va, rows = start, []
        while va < ends[start]:
            insn = image.fetch(va)
            rows.append(va)
            va += insn.size
        if va != ends[start]:
            raise cpu.ToolError("instruction stream overruns the extent")
        out[start] = (ends[start], rows)
    return out


def call_rows(image, extents):
    rows = []
    for start, (end, vas) in extents.items():
        for va in vas:
            off = image.file_offset(va)
            raw = image.data[off:off + image.fetch(va).size]
            if raw[0] == 0xe8:
                rows.append((start, va, "direct", image.fetch(va).target))
            elif raw[:2] == b"\xff\x15":
                slot = va + len(raw) + struct.unpack("<i", raw[2:6])[0]
                rows.append((start, va, "slot", slot))
            elif raw[0] == 0xff and raw[1] & 0x38 == 0x10:
                rows.append((start, va, "register", 0))
    return rows


def patched(image, va, at, old, new):
    off = image.file_offset(va) + at
    if image.data[off] != old:
        raise cpu.ToolError("unexpected byte at %#x" % (va + at))
    blob = bytearray(image.data)
    blob[off] = new
    clone = copy.copy(image)
    clone.data = bytes(blob)
    clone.cache = {}
    return clone


def battery(image, rng_seed=77):
    """Small fixed mix of converter and caller inputs with their real outputs, used by the controls."""
    rng = random.Random(rng_seed)
    kernel, caller = [], []
    for kind, n in (("tiny", 8), ("f64_small", 14), ("f64_mid", 16), ("f64_wide", 3), ("f32", 14), ("wide_mantissa", 30),
                    ("round_edge", 24), ("multiply_overflow", 16), ("clamp_edge", 24), ("carry_edge", 12),
                    ("scale_edge", 30)):
        for _ in range(n):
            args = kernel_case(rng, kind)
            kernel.append((args, run_kernel(image, *args)[:4]))
    for i in range(70):
        case = caller_case(rng, i)
        caller.append((case, run_caller(image, case)[:4]))
    return kernel, caller


def kernel_view(real):
    return None if real[0] == 0 else (real[1], real[2], real[3])


def caller_matches(image, case, real, mut=()):
    tag, payload, trace, kargs = spec_caller(image, case, mut)
    return (tag, payload, trace, kargs) == (real[0], real[1], real[2], real[3])


def control_results(image, data):
    """Yield (name, kind, detected) for every negative control."""
    kb, cb = battery(image)

    def kernel_catch(mut):
        return any(spec_kernel(*args, mut=(mut,)) != kernel_view(real) for args, real in kb)

    def caller_catch(mut):
        return any(not caller_matches(image, case, real, (mut,)) for case, real in cb)

    for mut in KERNEL_MUTANTS:
        yield "spec_" + mut, "wrong specification", kernel_catch(mut)
    for mut in CALLER_MUTANTS:
        yield "spec_" + mut, "wrong specification", caller_catch(mut)
    for va, at, old, new, what in PATCHES:
        bad = patched(image, va, at, old, new)
        detected = False
        try:
            if va >= 0x5c00000:
                for args, real in kb:
                    got = kernel_view(run_kernel(bad, *args)[:4])
                    if got != kernel_view(real):
                        detected = True
                        break
            else:
                for case, real in cb:
                    got = run_caller(bad, case)[:4]
                    if got != real:
                        detected = True
                        break
        except (cpu.ToolError, cpu.Done, struct.error, KeyError, IndexError, TypeError):
            detected = True
        yield "bytes_%x_%d" % (va, at), "byte corruption: " + what, detected
    bad_args = ((1 << 32, 0, 0, 0, 1, 1, 1), (0, 1 << 32, 0, 0, 1, 1, 1), (0, 0, -1, 0, 1, 1, 1),
                (0, 0, 0, 1 << 31, 1, 1, 1), (0, 0, 0, 0, 2, 1, 1), (0, 0, 0, 0, 1, 3, 1))
    for n, args in enumerate(bad_args):
        try:
            check_kernel_args(*args)
            detected = False
        except cpu.ToolError:
            detected = True
        yield "range_%d" % n, "out-of-range input %r" % (args,), detected
    for name, blob in (("digest_flip", bytes([data[0] ^ 1]) + data[1:4096]), ("digest_short", data[:4096])):
        try:
            load_image(blob)
            detected = False
        except cpu.ToolError:
            detected = True
        yield name, "damaged input binary", detected


def write_evidence(out, image, data):
    out.mkdir(parents=True, exist_ok=True)
    summary = {"kernel_cases": 0, "kernel_mismatch": 0, "kernel_refused": 0, "caller_cases": 0, "caller_mismatch": 0}
    seen = set()
    per_class = {}
    with open(out / "kernel_cases.tsv", "w", newline="\n") as kf:
        kf.write("class\tlo\tmid\thi\te2\tpositive\tis64\tround\tresult\tflags\thi_word\tlo_mid\n")
        rng = random.Random(115)
        for kind, count in kernel_plan():
            for i in range(count):
                args = kernel_case(rng, kind)
                check_kernel_args(*args)
                real = run_kernel(image, *args)
                seen |= real[5]
                want = spec_kernel(*args)
                summary["kernel_cases"] += 1
                got = kernel_view(real[:4])
                if got != want:
                    summary["kernel_mismatch"] += 1
                if got is None:
                    summary["kernel_refused"] += 1
                per_class[kind] = per_class.get(kind, 0) + 1
                if i % 11 == 0:
                    row = ("refused", "", "", "") if got is None else ("ok", "%#010x" % got[0], got[1], got[2])
                    kf.write("\t".join(map(str, (kind,) + args + row)) + "\n")
    with open(out / "caller_cases.tsv", "w", newline="\n") as cf:
        cf.write("index\tcontent_tag\tparse_error\tbits\tresult\tpayload\tkernel_args\ttrace\n")
        rng = random.Random(116)
        for i in range(1800):
            case = caller_case(rng, i)
            real = run_caller(image, case)
            seen |= real[4]
            summary["caller_cases"] += 1
            if not caller_matches(image, case, real[:4]):
                summary["caller_mismatch"] += 1
            if i % 12 == 0 or i < 30:
                cf.write("\t".join((str(i), str(case["tag"]), str(int(case["parse_err"])), "%#018x" % case["bits"],
                                    tag_name(real[0]), real[1].hex() if real[1] else "-", str(real[3]),
                                    ";".join(x[0] for x in real[2]))) + "\n")
    extents = program_extents(image, data)
    with open(out / "coverage.tsv", "w", newline="\n") as vf:
        vf.write("function\tinstructions\treached\tunreached_addresses\n")
        for start, (end, vas) in extents.items():
            missing = [va for va in vas if va not in seen]
            vf.write("%#x\t%d\t%d\t%s\n" % (start, len(vas), len(vas) - len(missing), ",".join("%#x" % v for v in missing)))
    with open(out / "calls.tsv", "w", newline="\n") as lf:
        lf.write("function\tcall_site\tkind\ttarget_or_slot\n")
        for start, va, kind, target in call_rows(image, extents):
            lf.write("%#x\t%#x\t%s\t%#x\n" % (start, va, kind, target))
    controls = detected = 0
    with open(out / "controls.tsv", "w", newline="\n") as tf:
        tf.write("name\tkind\tdetected\n")
        for name, kind, ok in control_results(image, data):
            controls += 1
            detected += ok
            tf.write("%s\t%s\t%d\n" % (name, kind, ok))
    cases = summary["kernel_cases"] + summary["caller_cases"]
    if summary["kernel_mismatch"] or summary["caller_mismatch"]:
        raise cpu.ToolError("specification differs from the binary: %r" % summary)
    with open(out / "measure.json", "w", newline="\n") as mf:
        json.dump({"cases": cases, "negative_controls": controls, "negative_detected": detected,
                   "kernel_cases": summary["kernel_cases"], "kernel_refusals": summary["kernel_refused"],
                   "caller_cases": summary["caller_cases"], "class_counts": per_class,
                   "binary_sha256": SHA}, mf, indent=1, sort_keys=True)
        mf.write("\n")
    return summary, controls, detected


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    data = TARGET.read_bytes()
    image = load_image(data)
    summary, controls, detected = write_evidence(Path(args.out), image, data)
    print("cases", summary, "controls", detected, "/", controls)


if __name__ == "__main__":
    main()
