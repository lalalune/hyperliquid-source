"""Decimal-to-u64 amount scaler of node #115, recovered from bytes.

Function 0x421e9d0 multiplies a 96-bit decimal by 10^digits, optionally snaps
the product to an integer (two modes) and converts it to a u64 that must stay
below 0x7fffffffffffffff.  It calls five decimal helpers that this tool also
runs from the binary bytes: the checked multiply 0x5c457a0, the round-to-integer
body 0x5c442f0, the fractional-part body 0x5c448a0 (with its subtraction
0x5c46bb0, also called directly) and the comparison 0x5c456c0.  Every case runs
the real bytes of all six bodies in the shared evaluator, compares the result and
the touch of the lazy global with an independent Python specification, and
compares what each helper received and returned with its own Python model.
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
import fde_extents as fe  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SCALER, MUL, ROUND, FRACT, SUB, CMP = 0x421e9d0, 0x5c457a0, 0x5c442f0, 0x5c448a0, 0x5c46bb0, 0x5c456c0
FUNCTIONS = (SCALER, MUL, ROUND, FRACT, SUB, CMP)
TOUCH_SITE = 0x421eb74
OK_TAG, ERR_TAG = 0x1a2, 0xac
LIMIT = 0x7ffffffffffffffe
M96 = 1 << 96
IN = cpu.INPUT
OUT = IN + 0x1000
SP = cpu.STACK + 0x10000
MARK = cpu.RETURN_MARK
U64 = cpu.U64
# call site -> helper kind; sites inside the fractional-part body use the subtraction
SITES = {0x421ea8d: "mul", 0x421eae7: "round", 0x421eafd: "sub", 0x421eb47: "cmp", 0x421eb88: "round",
         0x421eba4: "fract", 0x5c4497b: "sub"}
KINDS = ("mul", "round", "sub", "cmp", "fract")


class Machine(cpu.Machine):
    """Shared evaluator plus pand, pshufd, movd and the helper taps."""

    def two_byte(self, insn, key, bits, rexr, here):
        if len(key) == 2 and key[1] in (0xdb, 0x70, 0x7e) and insn.wide16 and not (key[1] == 0x7e and bits == 64):
            reg = ((self.image.data[insn.modrm] >> 3) & 7) | rexr
            operand = self.operand(insn)
            if key[1] == 0x7e:
                self.write(operand, 32, struct.unpack("<I", self.xmm[reg][:4])[0])
                return
            if operand[0] == "r":
                src = self.xmm[operand[1]]
            else:
                at = self.address(operand)
                src = struct.pack("<QQ", self.load(at, 8), self.load(at + 8, 8))
            if key[1] == 0xdb:
                self.xmm[reg] = bytes(a & b for a, b in zip(self.xmm[reg], src))
            else:
                imm = self.image.data[insn.off + insn.size - 1]
                words = struct.unpack("<4I", src)
                self.xmm[reg] = struct.pack("<4I", *[words[(imm >> (2 * i)) & 3] for i in range(4)])
            return
        super().two_byte(insn, key, bits, rexr, here)

    def call(self, target, where):
        kind = SITES.get(where)
        if kind is not None:
            g = lambda r: self.get(r, 64)  # noqa: E731
            at = {"mul": (g(cpu.RSI), g(cpu.RDX)), "sub": (g(cpu.RSI), g(cpu.RDX)), "round": (g(cpu.RSI),),
                  "cmp": (g(cpu.RDI), g(cpu.RSI)), "fract": (g(cpu.RSI),)}[kind]
            self.pending[where + self.image.fetch(where).size] = (kind, g(cpu.RDI), [rd(self, a, 16) for a in at])
        if where == TOUCH_SITE:  # the lazy-global getter: only its occurrence matters
            self.touches += 1
            for reg in cpu.CALLER_SAVED:
                self.put(reg, 64, None)
            self.xmm = [None] * 16
            self.flags = [None, None, None, None]
            return
        return super().call(target, where)

    def step(self):
        due = self.pending.pop(self.pc, None)
        if due is not None:
            self.tap(due)
        return super().step()

    def tap(self, due):
        kind, out, ins = due
        stat = self.stats[kind]
        stat[0] += 1
        if kind == "cmp":
            got = self.get(cpu.RAX, 8)
            want = model_cmp(*ins) & 0xff
        elif kind in ("round", "fract"):
            got = canon(rd(self, out, 16))
            want = canon(model_round(ins[0]) if kind == "round" else model_fract(ins[0]))
        else:
            tag = struct.unpack("<I", rd(self, out, 4))[0]
            res = model_mul(*ins) if kind == "mul" else model_sub(*ins)
            got = (tag, canon(rd(self, out + 4, 16)) if tag == 0 else None)
            want = (0, canon(res)) if res is not None else (tag, None)
            if res is None and tag == 0:
                want = (-1, None)
        if got != want:
            stat[1] += 1
            if self.first_bad.get(kind) is None:
                self.first_bad[kind] = (ins, got, want)


def wr(m, at, data):
    for i, b in enumerate(data):
        m.mem[at + i] = b


def rd(m, at, n):
    return bytes(m.mem[at + i] for i in range(n))


def finish(m, limit=400_000):
    try:
        for _ in range(limit):
            m.step()
    except cpu.Done as done:
        return done
    raise cpu.ToolError("step bound")


def load_image(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise cpu.ToolError("input binary digest differs from node #115")
    return cpu.Image(data)


def run_scaler(image, flags, hi, lo, mid, mode, digits, stats=None, first_bad=None):
    """Execute 0x421e9d0 once: returns (outcome, touches, steps, reached addresses)."""
    m = Machine(image)
    m.pending, m.touches, m.first_bad = {}, 0, first_bad if first_bad is not None else {}
    m.stats = stats if stats is not None else {k: [0, 0] for k in KINDS}
    wr(m, IN, struct.pack("<IIII", flags, hi, lo, mid))
    wr(m, OUT, bytes(0x20))
    wr(m, SP, struct.pack("<Q", MARK))
    for reg, val in ((cpu.RSP, SP), (cpu.RDI, OUT), (cpu.RSI, IN), (cpu.RDX, mode), (cpu.RCX, digits)):
        m.set_reg(reg, val)
    m.pc = SCALER
    done = finish(m)
    if done.how != "ret":
        raise cpu.ToolError("scaler stopped by %s" % done.how)
    tag = struct.unpack("<H", rd(m, OUT, 2))[0]
    if tag == OK_TAG:
        outcome = ("ok", struct.unpack("<Q", rd(m, OUT + 8, 8))[0])
    elif tag == ERR_TAG:
        outcome = ("err",)
    else:
        raise cpu.ToolError("unknown result tag %#x" % tag)
    return outcome, m.touches, m.steps, m.seen


# ---------------------------------------------------------------------------
# Decimal helpers and the models of the five helper bodies.
# ---------------------------------------------------------------------------
def parts(raw):
    flags, hi, lo, mid = struct.unpack("<IIII", raw)
    return flags >> 31, flags >> 16 & 0xff, hi << 64 | mid << 32 | lo


def canon(raw):
    neg, scale, mag = parts(raw)
    return (neg if mag else 0, scale, mag)


def pack(neg, scale, mag):
    return struct.pack("<IIII", neg << 31 | scale << 16, mag >> 64, mag & 0xffffffff, mag >> 32 & 0xffffffff)


def half_even(q, r, t):
    return q + (1 if 2 * r > t or (2 * r == t and q & 1) else 0)


def model_mul(a, b):
    """Checked multiply of a by an integer-scale operand; None when the product cannot be represented."""
    na, sa, ma = parts(a)
    nb, sb, mb = parts(b)
    if sb:
        raise cpu.ToolError("multiply model covers integer multipliers only")
    p, s = ma * mb, sa
    if p == 0:
        return pack(0, 0, 0)
    if p >= M96:
        k, q = 0, p
        while q >= M96 and k < s:
            q //= 10
            k += 1
        if q >= M96:
            return None
        q, r = divmod(p, 10 ** k)
        if r:
            raise cpu.ToolError("multiply model covers exact scale reductions only")
        p, s = q, s - k
    return pack(na ^ nb, s, p)


def model_round(a):
    na, sa, ma = parts(a)
    t = 10 ** sa
    q = half_even(*divmod(ma, t), t)
    return pack(na if q else 0, 0, q)


def model_fract(a):
    na, sa, ma = parts(a)
    return pack(na, sa, ma % 10 ** sa)


def model_sub(a, b):
    na, sa, ma = parts(a)
    nb, sb, mb = parts(b)
    s = max(sa, sb)
    x = (-ma if na else ma) * 10 ** (s - sa) - (-mb if nb else mb) * 10 ** (s - sb)
    if abs(x) >= M96:
        return None
    return pack(1 if x < 0 else 0, s, abs(x))


def model_cmp(a, b):
    na, sa, ma = parts(a)
    nb, sb, mb = parts(b)
    x = (-ma if na else ma) * 10 ** sb
    y = (-mb if nb else mb) * 10 ** sa
    return (x > y) - (x < y)


# ---------------------------------------------------------------------------
# Independent specification of the scaler itself.
# ---------------------------------------------------------------------------
def spec_scaler(flags, hi, lo, mid, mode, digits, mut=()):
    """Return (outcome, touches)."""
    max_digits = 20 if "digits_20" in mut else 18 if "digits_18" in mut else 19
    if digits > max_digits:
        return ("err",), 0
    mag = hi << 64 | mid << 32 | lo
    s, neg = flags >> 16 & 0xff, flags >> 31
    p = mag * 10 ** digits
    if p == 0 and "mul_zero_keeps_sign" not in mut:
        neg, s = 0, 0
    if p >= M96:
        if "no_mul_reduce" in mut:
            return ("err",), 0
        k, q = 0, p
        while q >= M96 and k < s:
            q //= 10
            k += 1
        if q >= M96:
            return ("err",), 0
        p, s = p // 10 ** k, s - k
    touches = 0
    eff = 2 if "mode1_as_2" in mut and mode == 1 else 0 if "mode_ge2_none" in mut and mode >= 2 else mode
    if "mode0_rounds" in mut and mode == 0:
        eff = 2
    if eff >= 1:
        t = 10 ** s
        q, r = divmod(p, t)
        if "round_half_up" in mut:
            rr = q + (1 if 2 * r >= t else 0)
        elif "round_floor" in mut:
            rr = q
        elif "round_ceil" in mut:
            rr = q + (1 if r else 0)
        else:
            rr = half_even(q, r, t)
        tol = {"tol_1e2": 100, "tol_1e4": 10000}.get(next((x for x in mut if x.startswith("tol_")), ""), 1000)
        if eff == 1:
            diff = abs(p - rr * t)
            lim = diff * tol <= t if "tol_inclusive" in mut else diff * tol < t
            if lim:
                if diff and "never_touch" not in mut or "always_touch" in mut:
                    touches = 1
                p, s = rr, 0
        else:
            p, s = rr, 0
        if p == 0 and "zero_keeps_sign" not in mut:
            neg = 0
    t = 10 ** s
    if p % t and "truncate_fraction" not in mut:
        return ("err",), touches
    if neg and "negative_ok" not in mut:
        return ("err",), touches
    v = p // t
    top = LIMIT + 1 if "limit_plus1" in mut else LIMIT - 1 if "limit_minus1" in mut else (1 << 64) - 1 if "limit_u64" in mut else LIMIT
    if v > top:
        return ("err",), touches
    return ("ok", v), touches


# ---------------------------------------------------------------------------
# Deterministic case generation
# ---------------------------------------------------------------------------
def scaled(rng, value, scale):
    return (value * 10 ** scale) % M96


def make_case(rng, kind):
    scale = rng.choice((0, 0, 1, 2, 3, 4, 6, 8, 10, 18, 20, 24))
    mode = rng.choice((0, 1, 2, 2, 255))
    digits = rng.choice((0, 1, 2, 3, 6, 8, 9, 10, 18, 19))
    neg = 1 if rng.random() < 0.2 else 0
    half = 5 * 10 ** max(scale - 1, 0)
    if kind == "small":
        mag = rng.getrandbits(rng.choice((8, 20, 40, 64)))
    elif kind == "wide":
        mag = rng.getrandbits(96)
    elif kind == "decimal_places":
        mag = rng.getrandbits(rng.choice((8, 20, 40, 64))) * 10 ** rng.randint(0, 6)
    elif kind == "near_integer":
        digits = rng.choice((0, 0, 0, 0, 1, 2))
        scale = max(scale, 4 + digits)
        mag = rng.randint(0, 3000) * 10 ** (scale - digits) + rng.choice((0, 1, -1, 2, -2, 3, -3)) * 10 ** (scale - 4 - digits) + rng.choice((0, 1, -1)) * (digits == 0)
        mode = rng.choice((1, 1, 1, 2, 0))
    elif kind == "tie":
        digits = rng.choice((0, 0, 0, 1, 2))
        scale = max(scale, digits + 1)
        mag = (rng.randint(0, 3000) * 10 + 5) * 10 ** (scale - 1 - digits) + (rng.choice((0, 0, 0, 1, -1)) if digits == 0 else 0)
        mode = rng.choice((1, 2, 2, 0, 255))
    elif kind == "tolerance_edge":
        digits = rng.choice((0, 0, 1, 2))
        scale = rng.choice((3, 4, 5, 6, 8, 12)) + digits
        delta = rng.choice((-1, 0, 0, 1)) if digits == 0 else 0
        mag = (rng.randint(0, 500) * 10 ** scale + rng.choice((-1, 1)) * (10 ** (scale - 3) + delta)) // 10 ** digits
        mode = rng.choice((1, 1, 2))
    elif kind == "limit_edge":
        digits = rng.choice((0, 0, 0, 1, 2))
        scale += digits
        mag = ((LIMIT + rng.randint(-3, 3)) * 10 ** scale) // 10 ** digits
        mode = rng.choice((0, 2, 1))
        neg = 0
    elif kind == "overflow_reduce":
        digits = rng.choice((9, 10, 18, 19, 19, 12))
        scale = rng.choice((1, 2, 5, 10, 18, 20, 28))
        mag = rng.getrandbits(rng.randint(70, 96))
    elif kind == "digits_edge":
        digits = rng.choice((0, 1, 15, 16, 17, 18, 19, 19, 20, 20, 21, 31, 32, 33, 64, 127, 255))
        mag = rng.getrandbits(rng.choice((4, 16, 30)))
        scale = rng.choice((0, 0, 2, 5))
    elif kind == "negative":
        neg = 1
        mag = rng.randint(0, 5) * 10 ** scale + rng.choice((0, 0, 1, half, half - 1, half + 1, rng.getrandbits(20)))
    else:  # zero
        mag = 0
        neg = rng.getrandbits(1)
    mag %= M96
    return (neg << 31 | scale << 16, mag >> 64, mag & 0xffffffff, mag >> 32 & 0xffffffff, mode, digits)


PLAN = (("small", 1100), ("wide", 1100), ("decimal_places", 1000), ("near_integer", 1400), ("tie", 1200),
        ("tolerance_edge", 1200), ("limit_edge", 900), ("overflow_reduce", 1000), ("digits_edge", 700),
        ("negative", 500), ("zero", 200))
MUTANTS = ("digits_20", "digits_18", "no_mul_reduce", "mode1_as_2", "mode_ge2_none",
           "mode0_rounds", "round_half_up", "round_floor", "round_ceil", "tol_1e2", "tol_1e4", "tol_inclusive",
           "never_touch", "always_touch", "zero_keeps_sign", "mul_zero_keeps_sign", "truncate_fraction", "negative_ok", "limit_plus1",
           "limit_minus1", "limit_u64")


def program_extents(image, data):
    ends = {row["start"]: row["end"] for row in fe.fde_extents(data)[1]}
    out = {}
    for start in FUNCTIONS:
        va, rows = start, []
        while va < ends[start]:
            rows.append(va)
            va += image.fetch(va).size
        if va != ends[start]:
            raise cpu.ToolError("instruction stream overruns the extent")
        out[start] = (ends[start], rows)
    return out


def branch_rows(image, extents):
    """(va, conditional-branch opcode offset) for every conditional jump of the six bodies."""
    rows = []
    for start, (end, vas) in extents.items():
        for va in vas:
            raw = image.data[image.file_offset(va):image.file_offset(va) + image.fetch(va).size]
            if 0x70 <= raw[0] <= 0x7f:
                rows.append((start, va, 0))
            elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
                rows.append((start, va, 1))
    return rows


def call_rows(image, extents):
    rows = []
    for start, (end, vas) in extents.items():
        for va in vas:
            raw = image.data[image.file_offset(va):image.file_offset(va) + image.fetch(va).size]
            if raw[0] == 0xe8:
                rows.append((start, va, "direct", image.fetch(va).target))
            elif raw[:2] == b"\xff\x15":
                rows.append((start, va, "slot", image.slots[va + len(raw) + struct.unpack("<i", raw[2:6])[0]]))
            elif raw[0] == 0xff and raw[1] & 0x38 == 0x10:
                rows.append((start, va, "register", 0))
            elif raw[0] == 0xe9:
                rows.append((start, va, "tail", image.fetch(va).target))
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


# (address, offset in instruction, old, new, meaning)
PATCHES = (
    (0x421ebd7, 1, 0x88, 0x89, "negative-value refusal js -> jns"),
    (0x421e9e8, 0, 0x74, 0x75, "zero-digits shortcut je -> jne"),
    (0x421eca1, 1, 0x87, 0x83, "u64 bound ja -> jae"),
    (0x421ec94, 2, 0xfe, 0xfd, "u64 bound immediate 0x7ffffffffffffffe -> ...fd"),
    (0x421eaca, 2, 0x01, 0x02, "mode test 1 -> 2"),
    (0x421eb4e, 0, 0x79, 0x78, "tolerance test jns -> js"),
    (0x421eb2b, 7, 0x03, 0x02, "tolerance 0.001 -> 0.01"),
    (0x421eb34, 5, 0x01, 0x02, "tolerance digit 1 -> 2"),
    (0x421eb72, 0, 0x74, 0x75, "touch only when deviation is non-zero: je -> jne"),
    (0x421ea5c, 3, 0x10, 0x20, "digit group test 16 -> 32"),
    (0x421ea55, 1, 0x90, 0x91, "multiply overflow flag seto -> setno"),
    (0x421ebb3, 1, 0x85, 0x84, "non-integer refusal jne -> je"),
)


DIRECTED = (  # negative zero before and after the multiply, the exact bound, snapping to zero
    (1 << 31 | 3 << 16, 0, 0, 0, 0, 2), (1 << 31, 0, 0, 0, 1, 0), (1 << 31 | 5 << 16, 0, 0, 0, 2, 3),
    (1 << 31 | 1 << 16, 0, 3, 0, 2, 0), (1 << 31 | 4 << 16, 0, 3, 0, 1, 0), (1 << 31 | 1 << 16, 0, 5, 0, 2, 0),
    (0, 0, 0xffffffff, 0x7fffffff, 0, 0), (0, 0, 0xfffffffe, 0x7fffffff, 0, 0), (0, 0, 0xfffffffd, 0x7fffffff, 0, 0),
    (0, 0, 0xffffffff, 0xffffffff, 0, 0), (2 << 16, 0, 5, 0, 2, 0), (2 << 16, 0, 15, 0, 2, 0), (3 << 16, 0, 999, 0, 1, 0),
    (3 << 16, 0, 1001, 0, 1, 0), (4 << 16, 0, 10005, 0, 1, 0), (4 << 16, 0, 10010, 0, 1, 0),
)


def battery(image, seed=77):
    """Fixed mix of inputs with their real outcomes, used by every negative control."""
    rng = random.Random(seed)
    cases = [(args, run_scaler(image, *args)[:2]) for args in DIRECTED]
    for kind, n in (("small", 14), ("wide", 10), ("decimal_places", 10), ("near_integer", 24), ("tie", 36),
                    ("tolerance_edge", 24), ("limit_edge", 24), ("overflow_reduce", 40), ("digits_edge", 30),
                    ("negative", 40), ("zero", 16)):
        for _ in range(n):
            args = make_case(rng, kind)
            real = run_scaler(image, *args)
            cases.append((args, (real[0], real[1])))
    return cases


def control_results(image, data):
    """Yield (name, kind, detected) for every negative control."""
    bat = battery(image)
    for mut in MUTANTS:
        yield "spec_" + mut, "wrong specification", any(spec_scaler(*args, mut=(mut,)) != real for args, real in bat)
    for va, at, old, new, what in PATCHES:
        bad = patched(image, va, at, old, new)
        yield "bytes_%x_%d" % (va, at), "byte corruption: " + what, byte_detected(bad, bat)
    extents = program_extents(image, data)
    flips = [row for row in branch_rows(image, extents) if row[0] != SCALER][::5]
    for start, va, at in flips:
        old = image.data[image.file_offset(va) + at]
        bad = patched(image, va, at, old, old ^ 1)
        survived = not byte_detected(bad, bat)
        if survived:  # reported as a survivor in flip_survivors.tsv, not counted as a control
            SURVIVORS.append((va, start))
        else:
            yield "flip_%x" % va, "condition flip in %#x" % start, True
    bad_args = ((1 << 32, 0, 0, 0, 0, 0), (0, 1 << 32, 0, 0, 0, 0), (0, 0, -1, 0, 0, 0), (0, 0, 0, 1 << 32, 0, 0),
                (0, 0, 0, 0, 256, 0), (0, 0, 0, 0, 0, 256))
    for n, args in enumerate(bad_args):
        try:
            check_args(*args)
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


SURVIVORS = []


def byte_detected(bad, bat):
    try:
        for args, real in bat:
            got = run_scaler(bad, *args)
            if (got[0], got[1]) != real:
                return True
    except (cpu.ToolError, cpu.Done, struct.error, KeyError, IndexError, TypeError):
        return True
    return False


def check_args(flags, hi, lo, mid, mode, digits):
    for word in (flags, hi, lo, mid):
        if not 0 <= word < 1 << 32:
            raise cpu.ToolError("decimal word outside u32")
    for byte in (mode, digits):
        if not 0 <= byte < 256:
            raise cpu.ToolError("byte argument outside u8")
    if flags & 0x7f00ffff or flags >> 16 & 0xff > 28:
        raise cpu.ToolError("decimal flags outside the valid layout")


def write_evidence(out, image, data):
    out.mkdir(parents=True, exist_ok=True)
    summary = {"cases": 0, "mismatch": 0, "ok": 0, "err": 0, "touched": 0}
    seen = set()
    per_class = {}
    stats = {k: [0, 0] for k in KINDS}
    first_bad = {}
    with open(out / "scaler_cases.tsv", "w", newline="\n") as cf:
        cf.write("class\tflags\thi\tlo\tmid\tmode\tdigits\tresult\tvalue\ttouched\n")
        rng = random.Random(115)
        for kind, count in PLAN:
            for i in range(count):
                args = make_case(rng, kind)
                check_args(*args)
                outcome, touches, steps, reached = run_scaler(image, *args, stats=stats, first_bad=first_bad)
                seen |= reached
                want = spec_scaler(*args)
                summary["cases"] += 1
                if (outcome, touches) != want:
                    summary["mismatch"] += 1
                    first_bad.setdefault("scaler", (args, outcome, touches, want))
                summary[outcome[0]] += 1
                summary["touched"] += touches
                per_class[kind] = per_class.get(kind, 0) + 1
                if i % 9 == 0:
                    cf.write("\t".join(map(str, (kind, "%#010x" % args[0]) + args[1:] + (outcome[0], outcome[1] if len(outcome) > 1 else "", touches))) + "\n")
    extents = program_extents(image, data)
    with open(out / "coverage.tsv", "w", newline="\n") as vf:
        vf.write("function\tinstructions\treached\tunreached_addresses\n")
        for start, (end, vas) in extents.items():
            missing = [va for va in vas if va not in seen]
            vf.write("%#x\t%d\t%d\t%s\n" % (start, len(vas), len(vas) - len(missing), ",".join("%#x" % v for v in missing)))
    with open(out / "helper_taps.tsv", "w", newline="\n") as hf:
        hf.write("helper\tcall_sites\tcalls_compared\tmodel_mismatches\n")
        for kind in KINDS:
            sites = ",".join("%#x" % s for s, k in sorted(SITES.items()) if k == kind)
            hf.write("%s\t%s\t%d\t%d\n" % (kind, sites, stats[kind][0], stats[kind][1]))
    with open(out / "calls.tsv", "w", newline="\n") as lf:
        lf.write("function\tcall_site\tkind\ttarget\n")
        for start, va, kind, target in call_rows(image, extents):
            lf.write("%#x\t%#x\t%s\t%#x\n" % (start, va, kind, target))
    controls = detected = 0
    with open(out / "controls.tsv", "w", newline="\n") as tf:
        tf.write("name\tkind\tdetected\n")
        for name, kind, ok in control_results(image, data):
            controls += 1
            detected += ok
            tf.write("%s\t%s\t%d\n" % (name, kind, ok))
    with open(out / "flip_survivors.tsv", "w", newline="\n") as sf:
        sf.write("branch\tfunction\n")
        for va, start in SURVIVORS:
            sf.write("%#x\t%#x\n" % (va, start))
    if summary["mismatch"] or any(stats[k][1] for k in KINDS):
        raise cpu.ToolError("model differs from the binary: %r %r %r" % (summary, stats, first_bad))
    with open(out / "measure.json", "w", newline="\n") as mf:
        json.dump({"cases": summary["cases"], "negative_controls": controls, "negative_detected": detected,
                   "accepted": summary["ok"], "refused": summary["err"], "touched": summary["touched"], "flip_survivors": len(SURVIVORS),
                   "helper_calls": sum(stats[k][0] for k in KINDS), "class_counts": per_class,
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
