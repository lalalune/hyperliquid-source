"""Hyperliquidity ladder generation of node #115, recovered from bytes.

Three functions of l1/src/hyperliquidity.rs are rebuilt as one path: the price
tick-size rule 0x3be2a50 (five significant digits, the decimals clamp and the
special-tick token set), the level generator 0x38bddf0 (rounds the start price to
the tick, then repeatedly multiplies by 1.003, rounds half away from zero via the
statically linked libm routine 0x63efe40, saturates to u64 and re-rounds to the
tick) and the cost helper 0x38bcb80 (checked sum of price * size over the first
`seeded` levels). The tool executes the real bytes in the shared evaluator; only
the hashing and probing of the special-tick set and the vector growth are replaced
by recorded stubs. Each run is compared with an independent specification.
"""
import argparse
import copy
import hashlib
import json
import math
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as cpu  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TICK, LADDER, COST, ROUND = 0x3be2a50, 0x38bddf0, 0x38bcb80, 0x63efe40
SIZES = {TICK: 807, LADDER: 569, COST: 110}
ROUND_WINDOW = 0x71
U64 = cpu.U64
SPECIAL_TICK = 1000
GROWTH = 1.003
HASH, PROBE, GROW = 0x47172c0, 0x3ed2180, 0x43bbf00
PANIC_TARGETS = {0x1680cbf: cpu.RDX, 0x1680c10: cpu.RDI, 0x1681e40: cpu.RDI}
LOCATIONS = {0x6476678: "rows_oob", 0x6493b30: "map_oob", 0x64768d8: "tokens_oob", 0x6476a30: "decimals_underflow"}
COST_LIMIT = 0x7ffffffffffffffe
FAULTS = (cpu.ToolError, cpu.Done, KeyError, ValueError, TypeError, OverflowError, struct.error, IndexError,
          ZeroDivisionError, AssertionError, MemoryError)

STACK_TOP = cpu.STACK + 0x10000
CTX, ROWS, TOKS, ENTS = cpu.INPUT + 0x200, 0x7210_0000, 0x7211_0000, 0x7212_0000
OUT, VEC, CS, CELLS = cpu.INPUT + 0x1000, 0x7260_0000, cpu.INPUT + 0x2000, cpu.INPUT + 0x2100
HEAP = 0x7300_0000
TOKEN_STRIDE, ROW_STRIDE, ENTRY_STRIDE = 0x158, 32, 16


class Panic(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


class Machine(cpu.Machine):
    """Shared evaluator plus the scalar and packed double forms these bodies use."""

    def x128(self, operand):
        if operand[0] == "r":
            return self.xmm[operand[1]]
        at = self.address(operand)
        return struct.pack("<QQ", self.load(at, 8), self.load(at + 8, 8))

    def xd(self, operand):
        if operand[0] == "r":
            return struct.unpack("<d", self.xmm[operand[1]][:8])[0]
        return struct.unpack("<d", struct.pack("<Q", self.load(self.address(operand), 8)))[0]

    def two_byte(self, insn, key, bits, rexr, here):
        data = self.image.data
        two = key[1] if len(key) == 2 else None
        reg = ((data[insn.modrm] >> 3) & 7) | rexr if insn.modrm is not None else 0
        dest = self.xmm[reg] if insn.modrm is not None else None
        if two in (0x58, 0x59, 0x5c, 0x5d, 0x5f) and insn.rep == 0xf2:
            left, right = struct.unpack("<d", dest[:8])[0], self.xd(self.operand(insn))
            res = {0x58: lambda: left + right, 0x59: lambda: left * right, 0x5c: lambda: left - right,
                   0x5d: lambda: left if left < right else right,
                   0x5f: lambda: left if left > right else right}[two]()
            self.xmm[reg] = struct.pack("<d", res) + dest[8:]
            return
        if two == 0x10 and insn.rep == 0xf2:
            operand = self.operand(insn)
            if operand[0] != "m":
                raise cpu.ToolError("movsd register form")
            self.xmm[reg] = struct.pack("<Q", self.load(self.address(operand), 8)) + bytes(8)
            return
        if two == 0x5c and insn.wide16:
            a, b = struct.unpack("<dd", dest), struct.unpack("<dd", self.x128(self.operand(insn)))
            self.xmm[reg] = struct.pack("<dd", a[0] - b[0], a[1] - b[1])
            return
        if two == 0x62 and insn.wide16:
            a, b = struct.unpack("<4I", dest), struct.unpack("<4I", self.x128(self.operand(insn)))
            self.xmm[reg] = struct.pack("<4I", a[0], b[0], a[1], b[1])
            return
        if two == 0x15 and insn.wide16:
            a, b = struct.unpack("<QQ", dest), struct.unpack("<QQ", self.x128(self.operand(insn)))
            self.xmm[reg] = struct.pack("<QQ", a[1], b[1])
            return
        if two in (0x54, 0x56) and insn.wide16:
            a, b = struct.unpack("<QQ", dest), struct.unpack("<QQ", self.x128(self.operand(insn)))
            op = (lambda x, y: x & y) if two == 0x54 else (lambda x, y: x | y)
            self.xmm[reg] = struct.pack("<QQ", op(a[0], b[0]), op(a[1], b[1]))
            return
        if two == 0x6e and insn.wide16 and insn.rex & 8:
            operand = self.operand(insn)
            if operand[0] != "r":
                raise cpu.ToolError("movq from memory")
            self.xmm[reg] = struct.pack("<Q", self.get(operand[1], 64)) + bytes(8)
            return
        if two == 0x7e and insn.wide16 and insn.rex & 8:
            operand = self.operand(insn)
            if operand[0] != "r":
                raise cpu.ToolError("movq to memory")
            self.put(operand[1], 64, struct.unpack("<Q", dest[:8])[0])
            return
        if two == 0x2e and insn.wide16:
            left, right = struct.unpack("<d", dest[:8])[0], self.xd(self.operand(insn))
            unordered = left != left or right != right
            self.flags = [unordered or left < right, unordered or left == right, False, False]
            return
        if two == 0x2c and insn.rep == 0xf2 and insn.rex & 8:
            value = self.xd(self.operand(insn))
            if value != value or not -(2.0 ** 63) <= value < 2.0 ** 63:
                self.put(reg, 64, 1 << 63)
            else:
                self.put(reg, 64, int(value) & U64)
            return
        if two == 0x57 and insn.wide16:
            if self.operand(insn) != ("r", reg):
                raise cpu.ToolError("xorpd of two different registers")
            self.xmm[reg] = bytes(16)
            return
        if two == 0x28 and insn.wide16:
            operand = self.operand(insn)
            if operand[0] == "r":
                self.xmm[reg] = self.xmm[operand[1]]
                return
        super().two_byte(insn, key, bits, rexr, here)


class Recorder(Machine):
    def setup(self, case):
        self.case = case
        self.trace = []
        self.targets = {}
        self.calls = list(case.get("calls", ()))
        self.heap = HEAP

    def put_mem(self, at, value, n=8):
        for i, b in enumerate(value.to_bytes(n, "little")):
            self.mem[at + i] = b

    def clobber(self, rax=None, rdx=None):
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        self.flags = [None, None, None, None]
        if rax is not None:
            self.set_reg(cpu.RAX, rax)
        if rdx is not None:
            self.set_reg(cpu.RDX, rdx)

    def call(self, target, where):
        g = lambda r: self.get(r, 64)  # noqa: E731
        t = self.trace
        self.targets.setdefault(target, 0)
        self.targets[target] += 1
        if target in PANIC_TARGETS:
            raise cpu.Done("panic", g(PANIC_TARGETS[target]))
        if target == HASH:
            t.append(("hash", g(cpu.RDI), g(cpu.RSI), g(cpu.RDX)))
            h = self.calls[0][0] if self.calls else 0
            self.clobber(h)
        elif target == PROBE:
            key = self.load(g(cpu.RDX), 8)
            t.append(("probe", g(cpu.RSI), key, g(cpu.RDI) - CTX))
            _, rax, rdx = self.calls.pop(0) if self.calls else (0, 0, 0)
            self.clobber(rax, rdx)
        elif target == GROW:
            vec = g(cpu.RDI)
            cap, ptr, length = (self.load(vec + 8 * i, 8) for i in range(3))
            t.append(("grow", length))
            if cap > 4096:
                raise cpu.ToolError("vector capacity out of range")
            new = max(cap * 2, 4)
            fresh = self.heap
            self.heap += 0x10000
            for i in range(cap * 24):
                if ptr + i in self.mem:
                    self.mem[fresh + i] = self.mem[ptr + i]
            self.put_mem(vec, new)
            self.put_mem(vec + 8, fresh)
            self.clobber()
        elif target == ROUND:
            t.append(("round", struct.unpack("<Q", self.xmm[0][:8])[0]))
            super().call(target, where)
        elif target == TICK:
            super().call(target, where)
        else:
            raise cpu.ToolError("unexpected call target %#x" % target)


def build_context(m, case):
    m.mem.update({a: 0xa5 for a in range(STACK_TOP - 0x200, STACK_TOP - 8)})
    rows, toks, ents = case["rows"], case["toks"], case["entries"]
    m.put_mem(CTX + 0x08, ROWS)
    m.put_mem(CTX + 0x10, len(rows))
    m.put_mem(CTX + 0x20, TOKS)
    m.put_mem(CTX + 0x28, len(toks))
    m.put_mem(CTX + 0x50, ENTS)
    m.put_mem(CTX + 0x58, len(ents))
    m.put_mem(CTX + 0x80, case["k0"])
    m.put_mem(CTX + 0x88, case["k1"])
    for i, (a, b) in enumerate(rows):
        m.put_mem(ROWS + ROW_STRIDE * i, a)
        m.put_mem(ROWS + ROW_STRIDE * i + 8, b)
    for i, (d48, d49) in enumerate(toks):
        m.mem[TOKS + TOKEN_STRIDE * i + 0x48] = d48
        m.mem[TOKS + TOKEN_STRIDE * i + 0x49] = d49
    for i, key in enumerate(ents):
        m.put_mem(ENTS + ENTRY_STRIDE * i + 8, key)
    m.put_mem(STACK_TOP, cpu.RETURN_MARK)
    m.set_reg(cpu.RSP, STACK_TOP)


def run(m, entry, steps=60000):
    m.pc = entry
    try:
        for _ in range(steps):
            m.step()
        raise cpu.ToolError("step bound")
    except cpu.Done as done:
        return done


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
    if kind == "cost":
        vec_cap, levels, take, size = case["cap"], case["levels"], case["take"], case["size"]
        m.put_mem(STACK_TOP, cpu.RETURN_MARK)
        m.set_reg(cpu.RSP, STACK_TOP)
        m.put_mem(VEC, vec_cap)
        m.put_mem(VEC + 8, VEC + 0x100)
        m.put_mem(VEC + 0x10, len(levels))
        for i, (a, b, price) in enumerate(levels):
            m.put_mem(VEC + 0x100 + 24 * i, a)
            m.put_mem(VEC + 0x108 + 24 * i, b)
            m.put_mem(VEC + 0x110 + 24 * i, price)
        m.put_mem(CS, VEC)
        m.put_mem(CS + 8, CELLS)
        m.put_mem(CS + 0x10, CELLS + 8)
        m.put_mem(CELLS, take)
        m.put_mem(CELLS + 8, size)
        m.set_reg(cpu.RDI, CS)
        done = run(m, COST)
        return ("ok", m.get(cpu.RAX, 64), m.get(cpu.RDX, 64)), m.trace, m.targets
    build_context(m, case)
    if kind == "tick":
        m.set_reg(cpu.RDI, CTX)
        m.set_reg(cpu.RSI, case["tok"])
        m.set_reg(cpu.RDX, case["price"])
        done = run(m, TICK)
        if done.how == "panic":
            return ("panic", panic_name(image, done.where)), m.trace, m.targets
        return ("ok", m.get(cpu.RAX, 64)), m.trace, m.targets
    m.set_reg(cpu.RDI, OUT)
    m.set_reg(cpu.RSI, case["tok"])
    m.set_reg(cpu.RDX, case["price"])
    m.set_reg(cpu.RCX, case["size"])
    m.set_reg(cpu.R8, case["n"])
    m.set_reg(cpu.R9, CTX)
    done = run(m, LADDER)
    if done.how == "panic":
        return ("panic", panic_name(image, done.where)), m.trace, m.targets
    cap, ptr, length, size = (m.load(OUT + 8 * i, 8) for i in range(4))
    if length > 4096:
        raise cpu.ToolError("level count out of range")
    prices = tuple(m.load(ptr + 24 * i + 16, 8) for i in range(length))
    zero = all(m.load(ptr + 24 * i, 8) == 0 for i in range(length))
    gap = all(ptr + 24 * i + 8 + j not in m.mem for i in range(length) for j in range(8))
    return ("ok", prices, size, cap, zero, gap), m.trace, m.targets


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
    return name[name.find("z_vendor/"):] if "z_vendor/" in name else name, line, col


# ---------------------------------------------------------------------------
# Independent specification, written from the listing
# ---------------------------------------------------------------------------
def trunc_signed(v):
    if v != v or not -(2.0 ** 63) <= v < 2.0 ** 63:
        return 1 << 63
    return int(v) & U64


def saturate(x, consts, mut=()):
    """max(x, 0) with NaN -> 0, +inf -> 0, clamp to 2^64, then the double-to-u64 sequence."""
    cinf, cmax, c63, csat = consts
    v = x if x > 0.0 else 0.0
    if v == cinf:
        v = 0.0
    elif v > cmax:
        v = cmax
    a = trunc_signed(v)
    b = trunc_signed(v - c63)
    r = (b & (U64 if a >> 63 else 0)) | a
    if v > csat:
        return 0 if "sat_zero" in mut else U64
    return r


def libm_round(x, mut=()):
    """Round half away from zero; values at or above 2^52 and non-finite values pass through."""
    if x != x or x in (math.inf, -math.inf) or abs(x) >= 2.0 ** 52:
        return x
    if "round_trunc" in mut:
        return float(math.trunc(x))
    fl = math.floor(abs(x))
    r = fl + (1 if abs(x) - fl >= 0.5 else 0)
    return math.copysign(float(r), x)


def digits_tick(price, mut=()):
    """Five significant digits: 10 ** (digits - 5), at least 1 and at most 10 ** 15."""
    drop = 6 if "dig6" in mut else 5
    return 10 ** min(max(len(str(price)) - drop, 0), 15)


def spec_tick(case, price, tok, calls, t, mut=()):
    m = lambda name: name in mut  # noqa: E731
    rows, toks, ents = case["rows"], case["toks"], case["entries"]
    if tok > len(rows) if m("rows_gt") else tok >= len(rows):
        raise Panic("rows_oob")
    first, second = rows[tok]
    n = len(ents)
    special = False
    if n == 1 and not m("one_skip"):
        special = ents[0] == first
    elif n >= 1 if m("one_skip") else n >= 2:
        t.append(("hash", case["k0"], case["k1"], first))
        h = calls[0][0] if calls else 0
        t.append(("probe", h, first, 0x48))
        _, rax, idx = calls.pop(0) if calls else (0, 0, 0)
        if (rax != 0) if m("found_any") else (rax & 1):
            if idx > n if m("idx_gt") else idx >= n:
                raise Panic("map_oob")
            special = True
    if special:
        return SPECIAL_TICK + (1 if m("special_1001") else 0)
    tick = digits_tick(price, mut)
    if second >= len(toks) or first >= len(toks):
        raise Panic("tokens_oob")
    d48, d49 = toks[first][0], toks[second][1]
    if m("dl_swap"):
        d48, d49 = toks[second][0], toks[first][1]
    if d49 < d48:
        raise Panic("decimals_underflow")
    dl = d49 - d48
    limit = 10 ** dl
    if limit <= U64 and not m("no_min"):
        tick = min(tick, limit)
    if m("dl0_keep") and dl == 0:
        tick = digits_tick(price, mut)
    return tick


def floor_to(price, tick, mut=()):
    out = (price // tick) * tick
    return max(out, 1) if "min1_off" not in mut else out


def spec_ladder(case, consts, mut=()):
    t, calls = [], list(case["calls"])
    tok, price, n = case["tok"], case["price"], case["n"]
    prices, cap = [], 0
    try:
        p = price if "first_no_round" in mut else floor_to(price, spec_tick(case, price, tok, calls, t, mut), mut)
        if "first_no_round" in mut:
            p = max(p, 1)
        for _ in range(n - 1 if "n_minus" in mut else n):
            if len(prices) == cap:
                t.append(("grow", len(prices)))
                cap = max(cap * 2, 4)
            prices.append(p)
            x = float(p) * (1.004 if "mul_1004" in mut else GROWTH)
            t.append(("round", struct.unpack("<Q", struct.pack("<d", x))[0]))
            q = max(saturate(libm_round(x, mut), consts, mut), 1)
            p = q if "no_tick_after" in mut else floor_to(q, spec_tick(case, q, tok, calls, t, mut), mut)
    except Panic as p_:
        return ("panic", p_.name), t
    return ("ok", tuple(prices), case["size"], cap, True, True), t


def spec_cost(case, mut=()):
    acc = 0
    take = case["take"] + (1 if "take_plus1" in mut else 0)
    for a, b, price in case["levels"][:take]:
        prod = price * case["size"]
        bad = prod > U64 or (prod >= COST_LIMIT if "cost_ge" in mut else prod > COST_LIMIT)
        if not bad and "no_add_check" not in mut:
            bad = acc + prod > U64
        if bad:
            return ("ok", 0, acc), []
        acc = (acc + prod) & U64
    return ("ok", 1, acc), []


def spec(case, consts, mut=()):
    if case["kind"] == "cost":
        return spec_cost(case, mut)
    if case["kind"] == "tick":
        t = []
        try:
            return ("ok", spec_tick(case, case["price"], case["tok"], list(case["calls"]), t, mut)), t
        except Panic as p:
            return ("panic", p.name), t
    return spec_ladder(case, consts, mut)


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------
EDGE_BYTES = (0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 19, 20, 21, 31, 32, 33, 47, 48, 49, 63, 64, 255)


SWEEP = sorted({min(max(10 ** k + d, 0), U64) for k in range(21) for d in (-1, 0, 1)} | {U64})


def boundary_price(rng):
    k = rng.randint(0, 20)
    return min(max(10 ** k + rng.choice((-1, 0, 0, 1)), 0), U64)


def log_price(rng):
    r = rng.random()
    if r < 0.45:
        return boundary_price(rng)
    if r < 0.55:
        return rng.choice((0, 1, U64, U64 - 1, 1 << 63, 5 ** 10 << 10, (5 ** 10 << 10) - 1, 5 ** 13 << 13, (5 ** 13 << 13) - 1))
    return rng.getrandbits(rng.randint(1, 64))


def make_context(rng, tok_count_hint=None, valid=True):
    ntoks = rng.randint(1, 6)
    nrows = rng.randint(1, 6)
    toks = []
    for _ in range(ntoks):
        d48 = rng.choice(EDGE_BYTES) if rng.random() < 0.4 else rng.randint(0, 8)
        toks.append((d48, rng.choice(EDGE_BYTES) if rng.random() < 0.5 else rng.randint(0, 12)))
    if valid:
        toks = [(min(a, b), max(a, b)) if rng.random() < 0.7 else (a, b) for a, b in toks]
    rows = []
    for _ in range(nrows):
        if rng.random() < 0.97:
            rows.append((rng.randrange(ntoks), rng.randrange(ntoks)))
        else:
            rows.append((rng.getrandbits(rng.choice((8, 40, 64))), rng.randrange(ntoks)))
    nents = rng.choice((0, 0, 1, 1, 2, 3, 5))
    ents = [rng.getrandbits(rng.choice((8, 40, 64))) for _ in range(nents)]
    return dict(rows=rows, toks=toks, entries=ents, k0=rng.getrandbits(64), k1=rng.getrandbits(64))


def make_calls(rng, count, nents):
    out = []
    for _ in range(count):
        found = rng.random() < 0.3
        high = rng.getrandbits(8) << 1
        rax = (high | int(found)) if rng.random() < 0.85 else rng.choice((0, 2, 0x100, 1 << 40, 3))
        idx = rng.randrange(nents + 2) if rng.random() < 0.95 else rng.getrandbits(64)
        out.append((rng.getrandbits(64), rax, idx))
    return out


def make_case(i):
    rng = random.Random("ladder-%d" % i)
    slot = i % 10
    if slot >= 8:
        n = rng.randint(0, 9)
        size = rng.choice((1, 2, 1000, rng.getrandbits(32), rng.getrandbits(62), 1 << 62, (1 << 63) // 3))
        levels = [(rng.getrandbits(64), rng.getrandbits(64), rng.choice((rng.getrandbits(rng.randint(1, 40)), 0, 1, COST_LIMIT // max(size, 1),
                                                                         COST_LIMIT // max(size, 1) + 1, U64 // max(size, 1), rng.getrandbits(64))))
                  for _ in range(n)]
        take = rng.choice((0, 1, n, n + 1, rng.randint(0, n + 2), U64))
        if rng.random() < 0.25 and levels:
            size = max(1, COST_LIMIT // levels[0][2]) if levels[0][2] else 1
        return dict(kind="cost", levels=levels, take=take, size=size, cap=rng.randint(n, n + 5), calls=[])
    ctx = make_context(rng, valid=rng.random() < 0.9)
    tok = rng.randrange(len(ctx["rows"])) if rng.random() < 0.97 else len(ctx["rows"]) + rng.choice((0, 1, 1000))
    first = ctx["rows"][tok][0] if tok < len(ctx["rows"]) else 0
    if len(ctx["entries"]) == 1 and rng.random() < 0.4:
        ctx["entries"][0] = first
    if slot < 5:
        case = dict(ctx, kind="tick", tok=tok, price=log_price(rng))
        if (i // 10) % 2 == 0:  # wide decimals and no special set: the digit rule alone decides, swept over every boundary
            case.update(entries=[], toks=[(0, rng.choice((30, 40)))] * len(ctx["toks"]), tok=rng.randrange(len(ctx["rows"])),
                        price=SWEEP[(i // 20 * 5 + slot) % len(SWEEP)])
            case["rows"] = [(a % len(case["toks"]), b % len(case["toks"])) for a, b in ctx["rows"]]
        case["calls"] = make_calls(rng, 1, len(ctx["entries"]))
        return case
    n = rng.randint(1, 24) if rng.random() > 0.04 else rng.randint(25, 70)
    price = rng.choice((rng.getrandbits(rng.randint(1, 50)), log_price(rng), rng.randint(1, 10 ** 6), U64 - rng.randint(0, 5 * 10 ** 17),
                        (U64 // 1003) * 1000 + rng.randint(0, 10 ** 15)))
    case = dict(ctx, kind="ladder", tok=tok, price=price, n=n, size=rng.getrandbits(rng.choice((16, 40, 64))))
    case["calls"] = make_calls(rng, n + 2, len(ctx["entries"]))
    return case


# ---------------------------------------------------------------------------
# Verification driver
# ---------------------------------------------------------------------------
def compare(image, case, consts, mut=()):
    got, trace, targets = execute(image, case)
    want, want_trace = spec(case, consts, mut)
    return got == want and trace == want_trace, got, targets


def run_cases(image, consts, count, mut=(), start=0):
    for i in range(start, start + count):
        try:
            ok, _, _ = compare(image, make_case(i), consts, mut)
        except FAULTS:
            return i
        if not ok:
            return i
    return None


def cases_by_kind(image, consts, count, want):
    """First `count` case indices whose kind is `want` (used by byte controls so every body is exercised)."""
    out, i = [], 0
    while len(out) < count:
        if make_case(i)["kind"] == want:
            out.append(i)
        i += 1
    return out


BYTE_PATCHES = (
    # name, function, pattern, index, replacement, meaning
    ("t_100k", TICK, b"\x48\x81\xfa\xa0\x86\x01\x00", 3, 0xa1, "first tick step 100000 -> 100001"),
    ("t_1m", TICK, b"\x48\x81\xfa\x40\x42\x0f\x00", 3, 0x41, "second tick step 1000000 -> 1000001"),
    ("t_10m", TICK, b"\x48\x81\xfa\x80\x96\x98\x00", 3, 0x81, "third tick step 1e7 -> 1e7+1"),
    ("t_shift10", TICK, b"\x48\xc1\xe9\x0a", 3, 0x0b, "1e10 step shift 10 -> 11"),
    ("t_shift13", TICK, b"\x48\xc1\xe9\x0d", 3, 0x0c, "1e13 step shift 13 -> 12"),
    ("t_1e14", TICK, b"\x48\xb9\xff\x3f\x7a\x10\xf3\x5a\x00\x00", 2, 0xfe, "1e14 step bound lowered"),
    ("t_1e15", TICK, b"\x48\xb8\xff\x7f\xc6\xa4\x7e\x8d\x03\x00", 2, 0xfe, "1e15 step bound lowered"),
    ("t_ten_pow", TICK, b"\xb8\xff\xe3\x0b\x54\x02\x00\x00", 1, 0xfe, "tick 1e10 constant lowered"),
    ("t_special", TICK, b"\xb8\xe8\x03\x00\x00\xe9", 1, 0xe9, "special tick 1000 -> 1001"),
    ("t_one_ent", TICK, b"\x48\x83\xfb\x01\x75", 4, 0x74, "single-entry special test inverted"),
    ("t_row_shift", TICK, b"\x48\xc1\xe6\x05", 3, 0x04, "row stride 32 -> 16"),
    ("t_tok_stride", TICK, b"\x48\x69\xc9\x58\x01\x00\x00", 3, 0x59, "token stride 0x158 -> 0x159"),
    ("t_dec_first", TICK, b"\x0f\xb6\x54\x0f\x49", 4, 0x48, "second decimals byte offset 0x49 -> 0x48"),
    ("t_dec_borrow", TICK, b"\x0f\x82\xd0\x00\x00\x00", 1, 0x83, "decimals underflow test inverted"),
    ("t_pow100", TICK, b"\x48\x6b\xc9\x64", 3, 0x65, "decimals step factor 100 -> 101"),
    ("t_bounds", TICK, b"\x48\x39\xc6\x0f\x83", 4, 0x82, "row bounds test inverted"),
    ("l_adc", LADDER, b"\x48\x83\xfb\x01\x48\x83\xd3\x00", 6, 0xdb, "first tick floor-to-one adc -> sbb"),
    ("l_dec", LADDER, b"\x49\xff\xcc", 2, 0xc4, "loop counter dec -> inc"),
    ("l_cap", LADDER, b"\x48\x89\x5c\xc8\x10", 4, 0x08, "price store offset 0x10 -> 0x8"),
    ("l_stride", LADDER, b"\x48\x8d\x0c\x6d\x00\x00\x00\x00", 3, 0x2d, "level stride scale 2 -> 1"),
    ("l_cmova", LADDER, b"\x49\x0f\x47\xde", 2, 0x42, "saturation cmova -> cmovb"),
    ("l_max", LADDER, b"\xf2\x0f\x5f\xc1", 2, 0x5d, "max with zero -> min"),
    ("l_size_out", LADDER, b"\x48\x89\x41\x18", 3, 0x10, "size output offset 0x18 -> 0x10"),
    ("c_limit", COST, b"\x49\xba\xfe\xff\xff\xff\xff\xff\xff\x7f", 2, 0xff, "product limit 2^63-2 -> 2^63-1"),
    ("c_seta", COST, b"\x41\x0f\x97\xc3", 2, 0x93, "product limit test seta -> setae"),
    ("c_borrow", COST, b"\x49\x83\xe8\x01", 3, 0x02, "take counter step 1 -> 2"),
    ("c_add", COST, b"\x48\x01\xc8", 1, 0x29, "accumulator add -> sub"),
    ("c_or", COST, b"\x08\xd3", 0, 0x20, "overflow flag or -> and"),
)


def patched_image(image, patch):
    name, fn, pattern, index, value, _ = patch
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


def constants(image):
    vals = tuple(struct.unpack_from("<d", image.data, image.file_offset(v))[0] for v in (0x459010, 0x459090, 0x459360, 0x458d58))
    mul = struct.unpack_from("<d", image.data, image.file_offset(0x459390))[0]
    if mul != GROWTH:
        raise cpu.ToolError("growth factor constant changed")
    return vals


SPEC_MUTANTS = (
    ("rows_gt", "row bound accepts tok == len"), ("one_skip", "single-entry shortcut removed"),
    ("found_any", "any non-zero probe result counts as found"), ("idx_gt", "index bound test uses > len"),
    ("special_1001", "special tick 1001"), ("dig6", "six significant digits"), ("dl_swap", "decimals bytes taken from the wrong rows"),
    ("no_min", "decimals clamp dropped"), ("dl0_keep", "equal decimals keep the digit tick"),
    ("first_no_round", "start price not rounded to the tick"), ("min1_off", "floor to one dropped"),
    ("mul_1004", "growth factor 1.004"), ("no_tick_after", "later prices not rounded to the tick"),
    ("n_minus", "one level fewer"), ("round_trunc", "truncation instead of round half away"),
    ("sat_zero", "products above the saturation bound become zero"), ("cost_ge", "cost refuses the limit itself"),
    ("take_plus1", "one level too many costed"), ("no_add_check", "cost accumulator overflow unchecked"),
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
    out.append(("fde_start", "an address inside the body is refused as a start",
                raises(lambda: body_extent(image, TICK + 4), cpu.ToolError)))
    for fn, size in SIZES.items():
        out.append(("extent_%x" % fn, "the body keeps its recorded extent", body_extent(image, fn) == size))
    out.append(("round_bytes", "the libm round routine keeps its byte digest",
                hashlib.sha256(image.data[image.file_offset(ROUND):image.file_offset(ROUND) + ROUND_WINDOW]).hexdigest() == ROUND_SHA))
    m = Recorder(image)
    m.setup({})
    out.append(("unknown_target", "a call to an unlisted target is refused", raises(lambda: m.call(0x1234, 0), cpu.ToolError)))
    out.append(("bad_location", "a non-Location address is refused", raises(lambda: decode_location(image, 0x400100), cpu.ToolError)))
    out.append(("unlisted_panic", "a panic location outside the table is refused", raises(lambda: panic_name(image, 0x400100), cpu.ToolError)))
    out.append(("wide_value", "a 65-bit value cannot enter a 64-bit slot", raises(lambda: m.put_mem(0x10, 1 << 64), OverflowError)))
    return out


ROUND_SHA = "dd46dae4d1f2461cfc75bdecf58b1d395710f64ea9c824a6b8e77f98b72d565f"


def write_lines(path, lines):
    with open(path, "w", newline="\n") as f:
        for line in lines:
            f.write(line + "\n")


CASES = 12000
CONTROL_CASES = 600
SAMPLE_EVERY = 10


def tick_table(image):
    """Real tick for prices around every power of ten, one fixed context (decimals 0/0 clamp -> raised to 8/8)."""
    base = dict(kind="tick", rows=[(0, 1)], toks=[(0, 20), (0, 20)], entries=[], k0=0, k1=0, tok=0, calls=[])
    lines = ["price\ttick"]
    prices = []
    for k in range(0, 21):
        for d in (-1, 0, 1):
            v = 10 ** k + d
            if 0 <= v <= U64:
                prices.append(v)
    prices.append(U64)
    for price in sorted(set(prices)):
        got, _, _ = execute(image, dict(base, price=price))
        lines.append("%d\t%d" % (price, got[1]))
    return lines


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if not check_digest(data):
        raise SystemExit("node #115 digest mismatch")
    image = cpu.Image(data)
    consts = constants(image)
    for fn, size in SIZES.items():
        if body_extent(image, fn) != size:
            raise SystemExit("body extent changed")
    if hashlib.sha256(data[image.file_offset(ROUND):image.file_offset(ROUND) + ROUND_WINDOW]).hexdigest() != ROUND_SHA:
        raise SystemExit("round routine changed")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    counts, targets, mismatches, sample, examples = {}, {}, 0, [], []
    for i in range(CASES):
        case = make_case(i)
        ok, got, tg = compare(image, case, consts)
        mismatches += not ok
        key = case["kind"] + ":" + (got[1] if got[0] == "panic" else "ok")
        counts[key] = counts.get(key, 0) + 1
        for t, c in tg.items():
            targets[(case["kind"], t)] = targets.get((case["kind"], t), 0) + c
        if i % SAMPLE_EVERY == 0:
            if case["kind"] == "cost":
                params = "take=%d,size=%d,levels=%d" % (min(case["take"], 999), case["size"], len(case["levels"]))
                result = "%d/%d" % (got[1], got[2])
            elif case["kind"] == "tick":
                params = "tok=%d,price=%d,entries=%d" % (case["tok"], case["price"], len(case["entries"]))
                result = str(got[1])
            else:
                params = "tok=%d,price=%d,n=%d" % (case["tok"], case["price"], case["n"])
                result = "panic" if got[0] == "panic" else "%d..%d" % (got[1][0], got[1][-1])
            sample.append("%d\t%s\t%s\t%s\t%s" % (i, case["kind"], key.split(":")[1], params, result))
    if mismatches:
        raise SystemExit("%d mismatches" % mismatches)
    controls = []
    for name, meaning in SPEC_MUTANTS:
        controls.append(("spec:" + name, meaning, run_cases(image, consts, CONTROL_CASES, (name,))))
    for patch in BYTE_PATCHES:
        clone = patched_image(image, patch)
        first = None
        for i in cases_by_kind(image, consts, 300, {TICK: "tick", LADDER: "ladder", COST: "cost"}[patch[1]]):
            try:
                ok, _, _ = compare(clone, make_case(i), consts)
            except FAULTS:
                ok = False
            if not ok:
                first = i
                break
        controls.append(("byte:" + patch[0], patch[5], first))
    for name, meaning, detected in misc_controls(image):
        controls.append(("misc:" + name, meaning, 0 if detected else None))
    detected = sum(1 for c in controls if c[2] is not None)
    write_lines(out / "callees.tsv", ["harness\ttarget\tcalls_in_run"] + [
        "%s\t%#x\t%d" % (k, t, targets[(k, t)]) for k, t in sorted(targets)])
    write_lines(out / "locations.tsv", ["site\tva\tfile\tline\tcolumn"] + [
        "%s\t%#x\t%s\t%d\t%d" % ((LOCATIONS[va], va) + decode_location(image, va)) for va in sorted(LOCATIONS)])
    write_lines(out / "tick_by_price.tsv", tick_table(image))
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
