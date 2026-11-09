"""Token-decimals scaling helpers of node #115 (l1/src/spot_meta.rs), recovered from bytes.

Three sibling bodies share one decimals rule: the scale is 10 ** (wei_decimals - sz_decimals) of
a token row (stride 0x158, bytes +0x48 and +0x49), built bit by bit (1, 2, 4, 8 and a 10 ** 16
step), a negative difference or a scale above u64 refuses through the spot_meta.rs:1206 panic
and a token index past the row count refuses through spot_meta.rs:119.
  0x434f660  scaled multiply: a * b / scale in u64 (token 0 is unscaled), with the divide-first
             fallback when the product overflows
  0x434f790  percent divide: a * b / (scale * 100) in u128 with an optional round-up and a
             bound of 2 ** 64 / 100
  0x434f910  signed-exponent scaler of a 256-bit value: multiply (negative exponent) or divide
             (zero or positive exponent) by 10 ** |e| and accept results below 2 ** 63 / 10
The tool executes the real bytes in the shared evaluator, including the statically linked
128-bit divide 0x63efec0, the 256-bit multiply 0x43be790 and the 256-bit divide 0x144dde0 (with the
imported memcpy and memset modelled as plain byte moves and the reciprocal-table slot seeded). Every run is compared with an independent specification.
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
MULDIV, PERCENT, SCALER = 0x434f660, 0x434f790, 0x434f910
UDIV128, MUL256, DIV256, PANIC = 0x63efec0, 0x43be790, 0x144dde0, 0x1680c10
SIZES = {MULDIV: 297, PERCENT: 369, SCALER: 453, UDIV128: 190, MUL256: 1127, DIV256: 5874}
U64 = cpu.U64
U128 = (1 << 128) - 1
U256 = (1 << 256) - 1
PCT_BOUND = 0x28f5c28f5c28f5c
SIGNED_BOUND = 0x0ccccccccccccccc
LOCATIONS = {0x6476a48: "scale_range", 0x64768d8: "tokens_oob"}
FAULTS = (cpu.ToolError, cpu.Done, KeyError, ValueError, TypeError, OverflowError, struct.error, IndexError,
          ZeroDivisionError, AssertionError, MemoryError)

STACK_TOP = cpu.STACK + 0x10000
CTX, TOKS = cpu.INPUT + 0x200, 0x7211_0000
VAL = cpu.INPUT + 0x3000
TOKEN_STRIDE = 0x158
RECIP_SLOT, MEMCPY_SLOT, MEMSET_SLOT = 0x64dfa58, 0x64df508, 0x64df750
MEMSET_MARK = 0x6000_0100


class Panic(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


class Machine(cpu.Machine):
    """Shared evaluator plus the packed forms and wide moves these bodies use."""

    def x128(self, operand):
        if operand[0] == "r":
            return self.xmm[operand[1]]
        at = self.address(operand)
        return struct.pack("<QQ", self.load(at, 8), self.load(at + 8, 8))

    def two_byte(self, insn, key, bits, rexr, here):
        two = key[1] if len(key) == 2 else None
        reg = ((self.image.data[insn.modrm] >> 3) & 7) | rexr if insn.modrm is not None else 0
        dest = self.xmm[reg] if insn.modrm is not None else None
        if two in (0x57, 0xef) and insn.wide16:
            if self.operand(insn) != ("r", reg):
                raise cpu.ToolError("xor of two different registers")
            self.xmm[reg] = bytes(16)
            return
        if two == 0xeb and insn.wide16:
            a, b = struct.unpack("<QQ", dest), struct.unpack("<QQ", self.x128(self.operand(insn)))
            self.xmm[reg] = struct.pack("<QQ", a[0] | b[0], a[1] | b[1])
            return
        if two == 0x76 and insn.wide16:
            a, b = struct.unpack("<4I", dest), struct.unpack("<4I", self.x128(self.operand(insn)))
            self.xmm[reg] = struct.pack("<4I", *[0xffffffff if x == y else 0 for x, y in zip(a, b)])
            return
        if two == 0x50:
            operand = self.operand(insn)
            lanes = struct.unpack("<4I", self.xmm[operand[1]])
            self.put(reg, 32, sum((lane >> 31) << i for i, lane in enumerate(lanes)))
            return
        if two == 0x6f and insn.wide16:
            operand = self.operand(insn)
            self.xmm[reg] = self.x128(operand)
            return
        if two == 0x7f and insn.rep == 0xf3:
            operand = self.operand(insn)
            if operand[0] != "m":
                raise cpu.ToolError("movdqu register store")
            at = self.address(operand)
            lo, hi = struct.unpack("<QQ", dest)
            self.store(at, 8, lo)
            self.store(at + 8, 8, hi)
            return
        super().two_byte(insn, key, bits, rexr, here)


def words(value):
    return tuple((value >> (64 * i)) & U64 for i in range(4))


def unwords(w):
    return sum(x << (64 * i) for i, x in enumerate(w))


class Recorder(Machine):
    def setup(self, case):
        self.case = case
        self.trace = []
        self.targets = {}

    def put_mem(self, at, value, n=8):
        for i, b in enumerate(value.to_bytes(n, "little")):
            self.mem[at + i] = b

    def step(self):
        """Imported memcpy (GOT slot 0x64df508) is modelled as a byte copy; every other step is the shared evaluator."""
        pc, img = self.pc, self.image
        if pc == MEMSET_MARK:  # the imported memset, entered by call or by tail jump: fill, then return
            dst, byte, n = self.get(cpu.RDI, 64), self.get(cpu.RSI, 64) & 0xff, self.get(cpu.RDX, 64)
            if n > 4096:
                raise cpu.ToolError("memset length out of range")
            for i in range(n):
                self.mem[dst + i] = byte
            sp = self.get(cpu.RSP, 64)
            self.clobber()
            self.set_reg(cpu.RAX, dst)
            self.pc = self.load(sp, 8)
            self.set_reg(cpu.RSP, sp + 8)
            self.targets[MEMSET_SLOT] = self.targets.get(MEMSET_SLOT, 0) + 1
            return
        if img.text_va <= pc < img.text_va + img.text_size:
            off = img.file_offset(pc)
            i = off + (1 if 0x40 <= img.data[off] <= 0x4f else 0)
            if img.data[i] == 0xff and img.data[i + 1] >> 6 == 3 and (img.data[i + 1] >> 3) & 7 in (2, 4):
                reg = (img.data[i + 1] & 7) | ((img.data[off] & 1) << 3 if i != off else 0)
                if self.get(reg, 64) == MEMSET_MARK:  # call or jmp through a register that holds the imported memset
                    if (img.data[i + 1] >> 3) & 7 == 2:
                        sp = self.get(cpu.RSP, 64) - 8
                        self.set_reg(cpu.RSP, sp)
                        self.store(sp, 8, pc + i + 2 - off)
                    self.pc = MEMSET_MARK
                    return
            if img.data[off:off + 2] == b"\xff\x25" and pc + 6 + struct.unpack_from("<i", img.data, off + 2)[0] == MEMSET_SLOT:
                self.pc = MEMSET_MARK  # tail jump to the imported memset
                return
            if img.data[off:off + 2] == b"\xff\x15" and pc + 6 + struct.unpack_from("<i", img.data, off + 2)[0] == MEMCPY_SLOT:
                dst, src, n = self.get(cpu.RDI, 64), self.get(cpu.RSI, 64), self.get(cpu.RDX, 64)
                if n > 4096:
                    raise cpu.ToolError("memcpy length out of range")
                if any(src + i not in self.mem for i in range(n)):
                    raise cpu.ToolError("memcpy reads bytes the model never wrote")
                chunk = [self.mem[src + i] for i in range(n)]
                for i, b in enumerate(chunk):
                    self.mem[dst + i] = b
                self.clobber()
                self.set_reg(cpu.RAX, dst)
                self.pc = pc + 6
                self.targets[MEMCPY_SLOT] = self.targets.get(MEMCPY_SLOT, 0) + 1
                return
        super().step()

    def read_mem(self, at, n):
        return int.from_bytes(bytes(self.mem[at + i] for i in range(n)), "little")

    def clobber(self):
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        self.flags = [None, None, None, None]

    def call(self, target, where):
        g = lambda r: self.get(r, 64)  # noqa: E731
        if target == MEMSET_MARK:
            super().call(target, where)
            return
        self.targets[target] = self.targets.get(target, 0) + 1
        if target == PANIC:
            raise cpu.Done("panic", g(cpu.RDI))
        if target == UDIV128:
            self.trace.append(("udiv128", (g(cpu.RSI) << 64) | g(cpu.RDI), (g(cpu.RCX) << 64) | g(cpu.RDX)))
            super().call(target, where)
        elif target == MUL256:
            self.trace.append(("mul256", self.read_mem(g(cpu.RSI), 32), self.read_mem(g(cpu.RDX), 32)))
            super().call(target, where)
        elif target == DIV256:
            v, s_ = self.read_mem(g(cpu.RDI), 32), self.read_mem(g(cpu.RSI), 32)
            self.trace.append(("div256", v, s_))
            super().call(target, where)
        else:
            raise cpu.ToolError("unexpected call target %#x" % target)


def build_tokens(m, case):
    m.mem.update({a: 0xa5 for a in range(STACK_TOP - 0x200, STACK_TOP - 8)})
    toks = case["toks"]
    m.put_mem(CTX + 0x20, TOKS)
    m.put_mem(CTX + 0x28, len(toks))
    for i, (d48, d49) in enumerate(toks):
        m.mem[TOKS + TOKEN_STRIDE * i + 0x48] = d48
        m.mem[TOKS + TOKEN_STRIDE * i + 0x49] = d49
    m.put_mem(STACK_TOP, cpu.RETURN_MARK)
    m.set_reg(cpu.RSP, STACK_TOP)


def run(m, entry, steps=400000):
    m.pc = entry
    try:
        for _ in range(steps):
            m.step()
        raise cpu.ToolError("step bound")
    except cpu.Done as done:
        return done


def decode_location(image, va):
    file_ptr = image.slots.get(va)
    if file_ptr is None:
        raise cpu.ToolError("%#x is not a relocated Location" % va)
    length = struct.unpack_from("<Q", image.data, image.file_offset(va + 8))[0]
    line, col = struct.unpack_from("<II", image.data, image.file_offset(va + 16))
    if not 0 < length < 200:
        raise cpu.ToolError("Location file length out of range")
    off = image.file_offset(file_ptr)
    name = image.data[off:off + length].decode()
    return name[name.find("l1/"):] if "l1/" in name else name, line, col


def panic_name(image, va):
    if va not in LOCATIONS:
        raise cpu.ToolError("panic location %#x is not in the table" % va)
    decode_location(image, va)
    return LOCATIONS[va]


def execute(image, case):
    case = copy.deepcopy(case)
    m = Recorder(image)
    m.setup(case)
    kind = case["kind"]
    if kind == "scaler":
        m.put_mem(STACK_TOP, cpu.RETURN_MARK)
        m.set_reg(cpu.RSP, STACK_TOP)
        m.put_mem(VAL, case["value"], 32)
        m.put_mem(RECIP_SLOT, image.slots[RECIP_SLOT])
        m.put_mem(MEMSET_SLOT, MEMSET_MARK)
        m.set_reg(cpu.RSI, case["exp"] & 0xff)
        m.set_reg(cpu.RDX, VAL)
        m.set_reg(cpu.RDI, 0)
        done = run(m, SCALER)
        if done.how == "panic":
            raise cpu.ToolError("scaler panicked")
        flag = m.get(cpu.RAX, 64) & 0xff
        value = m.read_mem(VAL, 32)
        if flag:
            return ("ok", 1, m.get(cpu.RDX, 64), value), m.trace, m.targets
        return ("ok", 0, None, value), m.trace, m.targets
    build_tokens(m, case)
    if kind == "muldiv":
        m.set_reg(cpu.RDI, case["a"])
        m.set_reg(cpu.RSI, case["tok"])
        m.set_reg(cpu.RDX, case["b"])
        m.set_reg(cpu.RCX, CTX)
        done = run(m, MULDIV)
    else:
        m.set_reg(cpu.RDI, case["a"])
        m.set_reg(cpu.RSI, case["tok"])
        m.set_reg(cpu.RDX, case["b"])
        m.set_reg(cpu.RCX, case["up"])
        m.set_reg(cpu.R8, CTX)
        done = run(m, PERCENT)
    if done.how == "panic":
        return ("panic", panic_name(image, done.where)), m.trace, m.targets
    return ("ok", m.get(cpu.RAX, 64) & 0xff if kind == "percent" else m.get(cpu.RAX, 64), m.get(cpu.RDX, 64)), m.trace, m.targets


# ---------------------------------------------------------------------------
# Independent specification, written from the listing
# ---------------------------------------------------------------------------
def scale_of(d48, d49, mut=()):
    """10 ** (d49 - d48) as the bytes build it; None when the body refuses (underflow, > u64)."""
    m = lambda name: name in mut  # noqa: E731
    if d49 < d48 and not m("no_underflow"):
        return None
    diff = (d49 - d48) & 0xff
    if diff == 0:
        return 1
    if diff > 19 and not (m("allow_big") and diff < 32):
        return None
    return 10 ** diff


def spec_muldiv(case, mut=()):
    m = lambda name: name in mut  # noqa: E731
    a, b, tok, toks = case["a"], case["b"], case["tok"], case["toks"]
    scale = 1
    if tok != 0 or m("tok0_checked"):
        if (tok > len(toks)) if m("bounds_gt") else (tok >= len(toks)):
            return ("panic", "tokens_oob"), []
        d48, d49 = toks[tok]
        if m("swap_dec"):
            d48, d49 = d49, d48
        scale = scale_of(d48, d49, mut)
        if scale is None:
            return ("panic", "scale_range"), []
    prod = a * b
    if prod <= U64 and not m("always_divide_first"):
        return ("ok", 1, (prod // scale) if not m("ceil") else -(-prod // scale)), []
    t = (a // scale) * b
    if m("ovf_flag_one"):
        return ("ok", 1, t & U64), []
    return ("ok", 1 if t <= U64 else 0, t & U64), []


def spec_percent(case, mut=()):
    m = lambda name: name in mut  # noqa: E731
    a, b, tok, toks, up = case["a"], case["b"], case["tok"], case["toks"], case["up"]
    if tok >= len(toks):
        return ("panic", "tokens_oob"), []
    d48, d49 = toks[tok]
    scale = scale_of(d48, d49, mut)
    if scale is None:
        return ("panic", "scale_range"), []
    p = a * b
    d = scale * (10 if m("pct10") else 100)
    q = p // d
    t = [("udiv128", p, d)]
    if (up & 0xff) and not m("no_round"):
        if p - q * d != 0 or m("round_always"):
            q += 1
    q &= U128
    bound = PCT_BOUND + (1 if m("bound_plus") else 0)
    ok = (q >> 64) == 0 and (q & U64) < bound
    if m("no_hi_check"):
        ok = (q & U64) < bound
    return ("ok", 1 if ok else 0, q & U64), t


def spec_scaler(case, mut=()):
    m = lambda name: name in mut  # noqa: E731
    e, v = case["exp"], case["value"]
    if e < -128 or e > 127:
        raise ValueError("exponent is an i8")
    t = []
    if e == 0:
        s = 1
        neg = False
    else:
        neg = e < 0
        mag = abs(e)
        if mag >= 32 or (mag > 19 and not m("allow_big")):
            return ("ok", 0, None, v), t
        s = 10 ** mag
    if neg != (m("flip_sign") and e != 0):
        t.append(("mul256", v, s))
        r = v * s
        if r > U256 and not m("mul_wrap"):
            return ("ok", 0, None, v), t
        r &= U256
        v_after = v
    else:
        t.append(("div256", v, s))
        r = v // s
        v_after = r
    bound = SIGNED_BOUND + (1 if m("bound_plus") else 0)
    if r < bound or (m("lo_only") and (r & U64) < bound):
        return ("ok", 1, r & U64, v_after), t
    return ("ok", 0, None, v_after), t


def spec(case, mut=()):
    kind = case["kind"]
    if kind == "muldiv":
        return spec_muldiv(case, mut)
    if kind == "percent":
        return spec_percent(case, mut)
    return spec_scaler(case, mut)


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------
EDGE_DIFF = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 18, 19, 20, 21, 24, 31, 32, 33, 48, 255)
EDGE_U64 = (0, 1, 2, 9, 10, 99, 100, 101, 10 ** 9, 10 ** 10, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1, 10 ** 18, 10 ** 19, U64 - 1, U64,
            PCT_BOUND - 1, PCT_BOUND, PCT_BOUND + 1, SIGNED_BOUND, 1 << 63)


def rand_u64(rng):
    r = rng.random()
    if r < 0.3:
        return rng.choice(EDGE_U64)
    if r < 0.4:
        k = rng.randint(0, 19)
        return min(10 ** k + rng.choice((-1, 0, 1)), U64)
    return rng.getrandbits(rng.randint(1, 64))


def make_tokens(rng, force=None):
    n = rng.randint(1, 5)
    toks = []
    for _ in range(n):
        d48 = rng.choice(EDGE_DIFF) if rng.random() < 0.15 else rng.randint(0, 8)
        diff = rng.choice(EDGE_DIFF) if rng.random() < 0.55 else rng.randint(0, 19)
        if rng.random() < 0.08:
            toks.append((rng.getrandbits(8), rng.getrandbits(8)))
        else:
            toks.append((d48, (d48 + diff) & 0xff))
    if force is not None:
        toks[rng.randrange(n)] = force
    return toks


def make_value(rng):
    r = rng.random()
    if r < 0.2:
        return rng.choice((0, 1, 9, 10, SIGNED_BOUND - 1, SIGNED_BOUND, SIGNED_BOUND + 1, 10 * SIGNED_BOUND, U64, U64 + 1, 1 << 127, U256, U256 // 10,
                           (U256 // 10 ** 19) + 1, 1 << 192))
    if r < 0.4:
        k = rng.randint(0, 77)
        return min(10 ** k + rng.choice((-1, 0, 1)), U256)
    return rng.getrandbits(rng.randint(1, 256))


def directed(n):
    """Cases that sit exactly on the percent bound, the signed bound and the 256-bit overflow edge."""
    rng = random.Random("directed-%d" % n)
    pick = n % 4
    if pick == 0:  # quotient on the percent bound: a * b = q * (scale * 100) (+ remainder)
        diff = rng.choice((0, 1, 2, 5, 8, 12, 17))
        toks = [(rng.randint(0, 6), 0), (4, 4 + diff)]
        q = PCT_BOUND + (n // 4) % 5 - 2
        d = 10 ** diff * 100
        extra = rng.choice((0, 0, 1))
        return dict(kind="percent", toks=toks, tok=1, a=q, b=d + extra, up=rng.choice((0, 1)))
    if pick == 1:  # value on the signed bound, exponent zero or positive
        k = rng.choice((0, 0, 1, 2, 5, 19))
        v = (SIGNED_BOUND + rng.choice((-1, 0, 1))) * 10 ** k + rng.choice((0, 0, 3, 10 ** k - 1))
        return dict(kind="scaler", exp=k, value=v)
    if pick == 2:  # multiply edge: negative exponent, value at or beyond U256 / 10 ** k
        k = rng.randint(1, 19)
        v = U256 // 10 ** k + rng.choice((-1, 0, 1))
        return dict(kind="scaler", exp=-k, value=max(v, 0))
    k = rng.randint(1, 19)  # multiply result on the signed bound
    v = SIGNED_BOUND // 10 ** k + rng.choice((-1, 0, 1, 2))
    return dict(kind="scaler", exp=-k, value=max(v, 0))


def make_case(i):
    if i % 50 == 7:
        return directed(i // 50)
    rng = random.Random("scaling-%d" % i)
    slot = i % 10
    if slot < 4:
        toks = make_tokens(rng)
        tok = rng.randrange(len(toks)) if rng.random() < 0.93 else len(toks) + rng.choice((0, 1, 1000))
        if rng.random() < 0.2:
            tok = 0
        a = rand_u64(rng)
        b = rand_u64(rng)
        if rng.random() < 0.25:  # keep the product close to 2 ** 64 so both branches meet
            b = max(1, (1 << 64) // max(a, 1) + rng.choice((-2, -1, 0, 1, 2)))
            b = min(b, U64)
        return dict(kind="muldiv", toks=toks, tok=tok, a=a, b=b)
    if slot < 7:
        toks = make_tokens(rng)
        tok = rng.randrange(len(toks)) if rng.random() < 0.95 else len(toks) + rng.choice((0, 1, 1000))
        scale_hint = rng.choice((1, 10, 10 ** 6, 10 ** 8))
        a = rand_u64(rng)
        b = rand_u64(rng)
        if rng.random() < 0.35:
            b = (PCT_BOUND * 100 * scale_hint) // max(a, 1) + rng.choice((-100, -1, 0, 1, 100))
            b = min(max(b, 0), U64)
        return dict(kind="percent", toks=toks, tok=tok, a=a, b=b, up=rng.choice((0, 1, 1, 2, 0x100, 0xff)))
    exp = rng.choice((0, 1, -1, 2, -2, 3, -3, 16, -16, 17, -17, 18, -18, 19, -19, 20, -20, 31, -31, 32, -32, 127, -128, 64, -64, 15, -15, 8, -8))
    if rng.random() < 0.45:
        exp = rng.randint(-128, 127)
    return dict(kind="scaler", exp=exp, value=make_value(rng))


# ---------------------------------------------------------------------------
# Verification driver
# ---------------------------------------------------------------------------
def compare(image, case, mut=()):
    got, trace, targets = execute(image, case)
    want, want_trace = spec(case, mut)
    return got == want and trace == want_trace, got, targets


def run_cases(image, count, mut=(), start=0, only=None):
    n, i = 0, start
    while n < count:
        case = make_case(i)
        i += 1
        if only and case["kind"] != only:
            continue
        n += 1
        try:
            ok, _, _ = compare(image, case, mut)
        except FAULTS:
            return i - 1
        if not ok:
            return i - 1
    return None


BYTE_PATCHES = (
    # name, function, pattern, index, replacement, meaning, kind
    ("m_x100", MULDIV, b"\x4d\x6b\xc9\x64", 3, 0x65, "scale step 100 -> 101", "muldiv"),
    ("m_x1e4", MULDIV, b"\x4d\x69\xc9\x10\x27", 3, 0x11, "scale step 10000 -> 10001", "muldiv"),
    ("m_x1e8", MULDIV, b"\x4d\x69\xc9\x00\xe1\xf5\x05", 5, 0x06, "scale step 1e8 -> 1e8+..", "muldiv"),
    ("m_x1e16", MULDIV, b"\x48\xba\x00\x00\xc1\x6f", 4, 0xc2, "scale step 1e16 changed", "muldiv"),
    ("m_stride", MULDIV, b"\x48\x69\xd6\x58\x01", 3, 0x59, "token stride 0x158 -> 0x159", "muldiv"),
    ("m_dec_off", MULDIV, b"\x0f\xb6\x44\x11\x49", 4, 0x48, "wei decimals offset 0x49 -> 0x48", "muldiv"),
    ("m_borrow", MULDIV, b"\x0f\x82\xaf\x00\x00\x00", 1, 0x83, "decimals underflow test inverted", "muldiv"),
    ("m_bounds", MULDIV, b"\x48\x3b\x71\x28\x0f\x83", 5, 0x82, "token bound test inverted", "muldiv"),
    ("m_mul_jo", MULDIV, b"\x49\xf7\xe0\x0f\x80", 4, 0x81, "product overflow test inverted", "muldiv"),
    ("m_tok0", MULDIV, b"\x48\x85\xf6\x74", 3, 0x75, "token 0 shortcut inverted", "muldiv"),
    ("m_ret_flag", MULDIV, b"\xb8\x01\x00\x00\x00\x59\xc3", 1, 0x00, "success flag 1 -> 0", "muldiv"),
    ("m_setno", MULDIV, b"\x0f\x91\xc0", 1, 0x90, "fallback flag setno -> seto", "muldiv"),
    ("p_x100", PERCENT, b"\xba\x64\x00\x00\x00\x48\x89\xc8", 1, 0x65, "percent divisor 100 -> 101", "percent"),
    ("p_round", PERCENT, b"\x84\xdb\x74\x29", 3, 0x75, "round-up flag test inverted", "percent"),
    ("p_bound", PERCENT, b"\x48\xba\x5c\x8f\xc2\xf5\x28", 2, 0x5d, "percent bound constant changed", "percent"),
    ("p_hi", PERCENT, b"\x48\x85\xf6\x0f\x94\xc0", 4, 0x95, "high word zero test sete -> setne", "percent"),
    ("p_carry", PERCENT, b"\x48\x83\xd6\x00", 3, 0x01, "round-up carry adc 0 -> 1", "percent"),
    ("p_ne", PERCENT, b"\x0f\x95\xc0\x48\x01\xc1", 1, 0x94, "remainder non-zero setne -> sete", "percent"),
    ("p_and", PERCENT, b"\x20\xc2\x0f\xb6\xc2", 0, 0x08, "bound and high test and -> or", "percent"),
    ("p_stride", PERCENT, b"\x48\x69\xf6\x58\x01", 3, 0x59, "token stride 0x158 -> 0x159", "percent"),
    ("s_xor", SCALER, b"\x40\x30\xc7", 1, 0x08, "sign fold xor -> or", "scaler"),
    ("s_x100", SCALER, b"\x48\x6b\xc0\x64", 3, 0x65, "scale step 100 -> 101", "scaler"),
    ("s_x1e16", SCALER, b"\x48\xba\x00\x00\xc1\x6f", 4, 0xc2, "scale step 1e16 changed", "scaler"),
    ("s_bound", SCALER, b"\x48\xbf\xcc\xcc\xcc\xcc", 2, 0xcd, "acceptance bound changed", "scaler"),
    ("s_jns", SCALER, b"\x40\x84\xf6\x79\x4f", 3, 0x78, "sign branch inverted", "scaler"),
    ("s_ovf", SCALER, b"\x80\x7c\x24\x40\x00\x0f\x85", 6, 0x84, "multiply overflow test inverted", "scaler"),
    ("s_zero", SCALER, b"\x40\x84\xf6\x0f\x84", 4, 0x85, "zero exponent test inverted", "scaler"),
    ("d_shr24", DIV256, b"\x48\xc1\xea\x18", 3, 0x19, "reciprocal shift 24 -> 25", "scaler"),
    ("d_shr55", DIV256, b"\x48\xc1\xe8\x37", 3, 0x36, "reciprocal table index shift 55 -> 54", "scaler"),
    ("d_shl", DIV256, b"\x49\xd3\xe6", 1, 0xd1, "normalising shift changed", "scaler"),
    ("s_one", SCALER, b"\x48\xc7\x04\x24\x01\x00\x00\x00", 4, 0x02, "zero exponent scale 1 -> 2", "scaler"),
)


def patched_image(image, patch):
    name, fn, pattern, index, value = patch[:5]
    data = bytearray(image.data)
    off = image.file_offset(fn)
    window = bytes(data[off:off + SIZES[fn]])
    at = window.find(pattern)
    if at < 0:
        raise cpu.ToolError("pattern %s not in the body" % name)
    data[off + at + index] = value
    clone = copy.copy(image)
    clone.data = data
    clone.cache = {}
    return clone


def check_digest(data):
    return hashlib.sha256(data).hexdigest() == SHA


def body_extent(image, start):
    lo, hi = image.fde_of(start)
    if lo != start:
        raise cpu.ToolError("%#x is not an FDE start" % start)
    return hi - lo


SPEC_MUTANTS = (
    ("tok0_checked", "token 0 also bounds-checked and scaled", "muldiv"),
    ("bounds_gt", "token index equal to the row count accepted", "muldiv"),
    ("swap_dec", "decimals bytes swapped", "muldiv"),
    ("no_underflow", "negative decimals difference accepted", "muldiv"),
    ("allow_big", "scale above u64 accepted", "muldiv"),
    ("always_divide_first", "divide-first used even when the product fits", "muldiv"),
    ("ceil", "quotient rounded up", "muldiv"),
    ("ovf_flag_one", "overflow fallback always reports success", "muldiv"),
    ("pct10", "percent divisor 10", "percent"),
    ("no_round", "round-up flag ignored", "percent"),
    ("round_always", "round up even when exact", "percent"),
    ("bound_plus", "bound one higher", "percent"),
    ("no_hi_check", "high word ignored", "percent"),
    ("flip_sign", "multiply and divide exchanged", "scaler"),
    ("mul_wrap", "multiply overflow wraps", "scaler"),
    ("lo_only", "only the low word is bounded", "scaler"),
)


def raises(fn, kinds):
    try:
        fn()
    except kinds:
        return True
    return False


def misc_controls(image):
    out = []
    damaged = bytearray(image.data)
    damaged[100] ^= 1
    out.append(("digest_flip", "one flipped byte fails the digest check", not check_digest(bytes(damaged))))
    out.append(("fde_start", "an address inside the body is refused as a start", raises(lambda: body_extent(image, MULDIV + 4), cpu.ToolError)))
    for fn, size in SIZES.items():
        out.append(("extent_%x" % fn, "the body keeps its recorded extent", body_extent(image, fn) == size))
    m = Recorder(image)
    m.setup({})
    out.append(("unknown_target", "a call to an unlisted target is refused", raises(lambda: m.call(0x1234, 0), cpu.ToolError)))
    out.append(("bad_location", "a non-Location address is refused", raises(lambda: decode_location(image, 0x400100), cpu.ToolError)))
    out.append(("unlisted_panic", "a panic location outside the table is refused", raises(lambda: panic_name(image, 0x400100), cpu.ToolError)))
    out.append(("wide_value", "a 65-bit value cannot enter a 64-bit slot", raises(lambda: m.put_mem(0x10, 1 << 64), OverflowError)))
    out.append(("exp_range", "an exponent outside i8 is refused by the specification",
                raises(lambda: spec_scaler(dict(kind="scaler", exp=200, value=1)), ValueError)))
    return out


def write_lines(path, lines):
    with open(path, "w", newline="\n") as f:
        for line in lines:
            f.write(line + "\n")


CASES = 12000
CONTROL_CASES = 500
SAMPLE_EVERY = 16


def scale_table(image):
    """Real scale and result for a fixed multiply across every decimals difference."""
    lines = ["diff\tscale_outcome\tmuldiv_result"]
    for diff in range(0, 40):
        case = dict(kind="muldiv", toks=[(0, 0), (3, (3 + diff) & 0xff)], tok=1, a=7, b=10 ** 12)
        got, _, _ = execute(image, case)
        lines.append("%d\t%s\t%s" % (diff, got[1] if got[0] == "panic" else "ok", got[2] if got[0] == "ok" else "-"))
    return lines


def exponent_table(image):
    lines = ["exp\tflag\tlow_word\tvalue_changed"]
    base = 123456789012345678
    for e in range(-128, 128):
        got, _, _ = execute(image, dict(kind="scaler", exp=e, value=base))
        lines.append("%d\t%d\t%s\t%d" % (e, got[1], got[2] if got[2] is not None else "-", int(got[3] != base)))
    return lines


def call_sites(image):
    """Direct `call rel32` byte patterns in .text that land on a target body, with the FDE that holds them."""
    base, off, size = image.text_va, image.text_off, image.text_size
    text = image.data[off:off + size]
    wanted = {MULDIV, PERCENT, SCALER}
    rows, at = [], text.find(b"\xe8")
    while at >= 0:
        if at + 5 <= size:
            tgt = (base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]) & U64
            if tgt in wanted:
                va = base + at
                try:
                    lo, hi = image.fde_of(va)
                except FAULTS:
                    lo, hi = 0, 0
                rows.append((tgt, va, lo, hi - lo))
        at = text.find(b"\xe8", at + 1)
    return sorted(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if not check_digest(data):
        raise SystemExit("node #115 digest mismatch")
    image = cpu.Image(data)
    for fn, size in SIZES.items():
        if body_extent(image, fn) != size:
            raise SystemExit("body extent changed")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    counts, targets, mismatches, sample = {}, {}, 0, []
    for i in range(CASES):
        case = make_case(i)
        ok, got, tg = compare(image, case)
        mismatches += not ok
        key = case["kind"] + ":" + (got[1] if got[0] == "panic" else "ok%d" % got[1])
        counts[key] = counts.get(key, 0) + 1
        for t, c in tg.items():
            targets[(case["kind"], t)] = targets.get((case["kind"], t), 0) + c
        if i % SAMPLE_EVERY == 0:
            if case["kind"] == "scaler":
                params = "exp=%d,value=%d" % (case["exp"], case["value"])
                result = "%d/%s" % (got[1], got[2])
            else:
                params = "tok=%d,a=%d,b=%d" % (case["tok"], case["a"], case["b"])
                result = "panic" if got[0] == "panic" else "%d/%d" % (got[1], got[2])
            sample.append("%d\t%s\t%s\t%s\t%s" % (i, case["kind"], key.split(":")[1], params, result))
    if mismatches:
        raise SystemExit("%d mismatches" % mismatches)
    controls = []
    for name, meaning, kind in SPEC_MUTANTS:
        controls.append(("spec:" + name, meaning, run_cases(image, CONTROL_CASES, (name,), only=kind)))
    for patch in BYTE_PATCHES:
        clone = patched_image(image, patch)
        first = None
        n, i = 0, 0
        while n < CONTROL_CASES:
            case = make_case(i)
            i += 1
            if case["kind"] != patch[6]:
                continue
            n += 1
            try:
                ok, _, _ = compare(clone, case)
            except FAULTS:
                ok = False
            if not ok:
                first = i - 1
                break
        controls.append(("byte:" + patch[0], patch[5], first))
    for name, meaning, detected in misc_controls(image):
        controls.append(("misc:" + name, meaning, 0 if detected else None))
    detected = sum(1 for c in controls if c[2] is not None)
    write_lines(out / "callees.tsv", ["harness\ttarget\tcalls_in_run"] + [
        "%s\t%#x\t%d" % (k, t, targets[(k, t)]) for k, t in sorted(targets)])
    write_lines(out / "locations.tsv", ["site\tva\tfile\tline\tcolumn"] + [
        "%s\t%#x\t%s\t%d\t%d" % ((LOCATIONS[va], va) + decode_location(image, va)) for va in sorted(LOCATIONS)])
    write_lines(out / "call_sites.tsv", ["target\tcall_va\towner_fde\towner_size"] + [
        "%#x\t%#x\t%#x\t%d" % r for r in call_sites(image)])
    write_lines(out / "scale_by_difference.tsv", scale_table(image))
    write_lines(out / "scaler_by_exponent.tsv", exponent_table(image))
    write_lines(out / "cases.tsv", ["case\tkind\toutcome\tparams\tresult"] + sample)
    write_lines(out / "outcomes.tsv", ["outcome\tcases"] + ["%s\t%d" % kv for kv in sorted(counts.items())])
    write_lines(out / "controls.tsv", ["control\tmeaning\tfirst_mismatch_case"] + [
        "%s\t%s\t%s" % (n, m_, "undetected" if h is None else h) for n, m_, h in controls])
    write_lines(out / "measure.json", [json.dumps({"cases": CASES, "negative_controls": len(controls),
                                                    "negative_detected": detected, "mismatches": mismatches},
                                                   indent=1, sort_keys=True)])
    if detected != len(controls):
        raise SystemExit("undetected controls: " + ", ".join(c[0] for c in controls if c[2] is None))


if __name__ == "__main__":
    main()
