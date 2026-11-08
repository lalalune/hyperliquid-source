"""Hyperliquidity seeding check of node #115, recovered from bytes.

Function 0x38bc000 (l1/src/hyperliquidity.rs) validates and registers the
automated market-making ladder of a spot token: it refuses a duplicate ladder,
an unsupported quote token, too few or too many levels, an invalid ladder
configuration, an out-of-range market cap and an unfunded seed, and on success
stores the ladder and returns the quote amount. The tool runs the real bytes in
the shared evaluator with every callee replaced by a recorded stub, then compares
the call trace, the result and the context write with an independent
specification written from the listing.
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
ENTRY, SIZE = 0x38bc000, 2705
CAP_CHECK, CAP_SIZE, WINDOW = 0x38bcaa0, 212, 0xb80
U64 = cpu.U64
MIN = 1 << 63
OK_TAG, ERR_TAG = 0x1a2, 0xee
LIM = 0x1999999999999999
MAX_LEVELS, MIN_LEVELS = 4000, 10
PRICE_MAX = 0x38d7ea4c68000
Y_MAX = 1_000_000
START_MIN = 1_000_000
BANDS = ((1_000_000_000, 100_000_000_000), (0, 10_000_000))

STACK_TOP = cpu.STACK + 0x10000
BODY_RSP = STACK_TOP - 0x138
MAP, P, CTX, ST = cpu.INPUT, cpu.INPUT + 0x100, cpu.INPUT + 0x200, cpu.INPUT + 0x1000
ROWS, TOKS, NAMES, SUP = 0x7210_0000, 0x7211_0000, 0x7212_0000, 0x7213_0000
MNODES, RNODES, RRING, ROBJ = 0x7220_0000, 0x7230_0000, 0x7240_0000, 0x7250_0000
LEVELS, OUT = 0x7260_0000, 0x7270_0000
DEFAULT_R, ONCE_CTX, ONCE_DFLT = 0x64fd958, 0x64f01d8, 0x64fd9a8
CTX_INIT = 0x1234_5678_9abc
TOKEN_STRIDE, ROW_STRIDE = 0x158, 32

# call-site offsets from the body start -> stub name
SITES = {0x118: "find_a", 0x186: "entry_lookup", 0x2b8: "once_exists", 0x2cb: "ring", 0x373: "drop_quote",
         0x3d6: "supply", 0x3f5: "drop_supply", 0x476: "libm", 0x5a4: "balance1", 0x5d5: "levels", 0x690: "insert",
         0x6b7: "free_old", 0x6e1: "drop_balance", 0x6f4: "balance2", 0x741: "once_dflt", 0x82d: "tick",
         0x873: "price_ok", 0x886: "cap_ok", 0x8fc: "free_vec", 0x930: "cost", 0x9be: "once_ctx", 0xb36: "once_cap",
         0x9dd: "drop_cost", 0x9fc: "free_cost", 0xa1e: "panic_rows", 0xa2b: "panic_tokens", 0xa46: "panic_none"}
PANICS = {"panic_rows": cpu.RDX, "panic_tokens": cpu.RDI, "panic_none": cpu.RDI}

MSG = {  # name -> (text start in rodata, length)
    "too_many": 0x7a0899, "cannot_seed": 0x7a0877, "exists": 0x7a085a, "quote": 0x7a080a, "hold": 0x7a0835,
    "too_few": 0x7a07cc, "no_supply": 0x7a07e9, "config": 0x7a07a8, "start_price": 0x7a075d,
    "balance": 0x7a0784, "zero_size": 0x7a0642, "start_value": 0x7a0660, "price": 0x7a06c7, "mcap": 0x7a06e6,
    "funds": 0x7a069b}
MSG_LEN = {"too_many": 30, "cannot_seed": 34, "exists": 29, "quote": 43, "hold": 37, "too_few": 29, "no_supply": 33,
           "config": 36, "start_price": 39, "balance": 36, "zero_size": 30, "start_value": 59, "price": 31,
           "mcap": 119, "funds": 44}


class Machine(cpu.Machine):
    """Shared evaluator plus ror-free scalar double forms and the vector moves of this body."""

    pf = False

    def xd(self, operand):
        if operand[0] == "r":
            return struct.unpack("<d", self.xmm[operand[1]][:8])[0]
        return struct.unpack("<d", struct.pack("<Q", self.load(self.address(operand), 8)))[0]

    def two_byte(self, insn, key, bits, rexr, here):
        data = self.image.data
        two = key[1] if len(key) == 2 else None
        reg = ((data[insn.modrm] >> 3) & 7) | rexr if insn.modrm is not None else 0
        if two in (0x59, 0x5c, 0x5d, 0x5f) and insn.rep == 0xf2:
            left, right = struct.unpack("<d", self.xmm[reg][:8])[0], self.xd(self.operand(insn))
            if two == 0x59:
                res = left * right
            elif two == 0x5c:
                res = left - right
            elif two == 0x5f:
                res = left if left > right else right
            else:
                res = left if left < right else right
            self.xmm[reg] = struct.pack("<d", res) + self.xmm[reg][8:]
            return
        if two == 0x10 and insn.rep == 0xf2:
            operand = self.operand(insn)
            if operand[0] != "m":
                raise cpu.ToolError("movsd register form")
            self.xmm[reg] = struct.pack("<Q", self.load(self.address(operand), 8)) + bytes(8)
            return
        if two == 0x7e and insn.wide16 and insn.rex & 8:
            operand = self.operand(insn)
            if operand[0] != "r":
                raise cpu.ToolError("movq to memory")
            self.put(operand[1], 64, struct.unpack("<Q", self.xmm[reg][:8])[0])
            return
        if two == 0x2e and insn.wide16:
            left, right = struct.unpack("<d", self.xmm[reg][:8])[0], self.xd(self.operand(insn))
            unordered = left != left or right != right
            self.flags = [unordered or left < right, unordered or left == right, False, False]
            self.pf = unordered
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
        if two == 0x76 and insn.wide16:
            if self.operand(insn) != ("r", reg):
                raise cpu.ToolError("pcmpeqd of two different registers")
            self.xmm[reg] = b"\xff" * 16
            return
        super().two_byte(insn, key, bits, rexr, here)


class Recorder(Machine):
    def setup(self, case):
        self.case = case
        self.trace = []
        self.targets = {}
        self.start = ENTRY

    def rd(self, at, n):
        out = bytearray()
        for i in range(n):
            b = self.mem.get(at + i)
            if b is None:
                b = self.image.read_only(at + i)
            if b is None:
                raise cpu.ToolError("stub read of unwritten byte at %#x" % (at + i))
            out.append(b)
        return bytes(out)

    def wr(self, at, data):
        for i, b in enumerate(data):
            self.mem[at + i] = b

    def clobber(self, rax=None, rdx=None):
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        self.xmm = [None] * 16
        self.flags = [None, None, None, None]
        if rax is not None:
            self.set_reg(cpu.RAX, rax)
        if rdx is not None:
            self.set_reg(cpu.RDX, rdx)

    def call(self, target, where):
        site = SITES.get(where - self.start)
        if site is None:
            raise cpu.ToolError("unknown call site %#x" % where)
        self.targets[site] = target
        g = lambda r: self.get(r, 64)  # noqa: E731
        c, t = self.case, self.trace
        rel = lambda r: g(r) - BODY_RSP  # noqa: E731
        if site in PANICS:
            raise cpu.Done(site, (site, g(PANICS[site])))
        if site == "find_a":
            t.append((site, self.load(g(cpu.RSI), 8)))
            self.clobber(c["find_a"])
        elif site == "entry_lookup":
            t.append((site, g(cpu.RDI) - ST))
            self.clobber(c["entry_ptr"])
        elif site.startswith("once"):
            t.append(("once", site))
            self.clobber()
        elif site == "ring":
            which = "default" if g(cpu.RDI) == DEFAULT_R else "object"
            t.append((site, which, self.load(g(cpu.RSI), 8)))
            self.clobber(c["ring_flag"], c["ring_idx"])
        elif site.startswith("drop"):
            t.append(("drop", site))
            self.clobber()
        elif site == "supply":
            t.append((site, g(cpu.RDI) - ST, self.load(g(cpu.RSI), 8)))
            self.clobber(SUP if c["supply"] else 0)
        elif site == "libm":
            t.append((site, struct.unpack("<Q", self.xmm[0][:8])[0]))
            self.xmm = [None] * 16
            self.xmm[0] = struct.pack("<d", c["libm"]) + bytes(8)
            for reg in cpu.CALLER_SAVED:
                self.put(reg, 64, None)
            self.flags = [None, None, None, None]
        elif site in ("balance1", "balance2"):
            t.append((site, g(cpu.RDI) - ST, g(cpu.RSI), g(cpu.RDX)))
            self.clobber(c["bal_rax"], c["bal_rdx"])
        elif site == "levels":
            t.append((site, g(cpu.RSI), g(cpu.RDX), g(cpu.RCX), g(cpu.R8), g(cpu.R9) - ST))
            out = g(cpu.RDI)
            self.wr(out, struct.pack("<QQQ", c["lv_cap"], LEVELS, len(c["levels"])))
            self.clobber()
        elif site == "insert":
            t.append((site, g(cpu.RSI) - MAP, g(cpu.RDX), self.load(g(cpu.RCX), 8), self.load(g(cpu.RCX) + 8, 8)))
            self.wr(g(cpu.RDI), struct.pack("<QQ", c["old_cap"], 0x7280_0000))
            self.clobber()
        elif site in ("free_old", "free_vec", "free_cost"):
            t.append(("free", g(cpu.RDI), g(cpu.RSI), g(cpu.RDX)))
            self.clobber()
        elif site == "tick":
            t.append((site, g(cpu.RDI) - ST, g(cpu.RSI), g(cpu.RDX)))
            self.clobber(c["ticks"].pop(0) if c["ticks"] else 1)
        elif site == "price_ok":
            t.append((site, g(cpu.RDI), g(cpu.RSI), g(cpu.RDX), g(cpu.RCX) - ST))
            self.clobber(c["price_ok"].pop(0) if c["price_ok"] else 0, c["mcaps"].pop(0) if c["mcaps"] else 0)
        elif site == "cap_ok":
            t.append((site, g(cpu.RDI), g(cpu.RSI), g(cpu.RDX)))
            super().call(target, where)
        elif site == "cost":
            vec = self.load(g(cpu.RDI), 8)
            t.append((site, self.load(vec, 8), self.load(vec + 8, 8), self.load(self.load(g(cpu.RDI) + 8, 8), 8),
                      self.load(self.load(g(cpu.RDI) + 16, 8), 8)))
            self.clobber(c["cost_rax"], c["cost_rdx"])
        else:
            raise cpu.ToolError("unhandled site " + site)


def put(m, at, value, n=8):
    m.wr(at, value.to_bytes(n, "little"))


def write_tree(m, base, height, keys, children, node_size, key_off, len_off, child_off, val_off=None, vals=None):
    """Write a one- or two-level tree; returns the root address."""
    cursor = [base]

    def node(ks, vs):
        at = cursor[0]
        cursor[0] += node_size
        for j, k in enumerate(ks):
            put(m, at + key_off + 8 * j, k)
            if val_off is not None:
                m.wr(at + val_off + 24 * j, struct.pack("<QQQ", *vs[j]))
        put(m, at + len_off, len(ks), 2)
        return at

    if height == 0:
        return node(keys, vals)
    root = node(keys, vals)
    for j, (ks, vs) in enumerate(children):
        put(m, root + child_off + 8 * j, node(ks, vs))
    return root


def write_R(m, at, R):
    if R[0] == "tree":
        _, height, keys, vals, children = R
        root = write_tree(m, RNODES + (0x4000 if at == DEFAULT_R else 0), height, keys, children, 0x230, 8, 0x16a,
                          0x170, 0x60, vals) if keys is not None else 0
        put(m, at, MIN)
        put(m, at + 8, root)
        put(m, at + 0x10, height)
    else:
        _, cap, head, entries = R
        ring = RRING + (0x1000 if at == DEFAULT_R else 0)
        put(m, at, cap)
        put(m, at + 8, ring)
        put(m, at + 0x10, head)
        put(m, at + 0x18, len(entries))
        for pos, (a, b) in entries:
            put(m, ring + 32 * pos + 8, a)
            put(m, ring + 32 * pos + 16, b)


def build(m, case):
    m.mem.update({a: 0xa5 for a in range(STACK_TOP - 0x200, STACK_TOP - 8)})
    A, tok, size, n, seeded, cap = case["P"]
    for i, v in enumerate((A, tok, size, n, seeded, cap)):
        put(m, P + 8 * i, v)
    kind = case["map"]
    if kind[0] == "tree":
        _, height, keys, children = kind
        root = write_tree(m, MNODES, height, keys, children, 0x230, 0x168, 0x1c2, 0x1c8) if keys is not None else 0
        put(m, MAP, MIN)
        put(m, MAP + 8, root)
        put(m, MAP + 0x10, height)
    else:
        put(m, MAP, 1)
    put(m, ST + 0x18, ROWS)
    put(m, ST + 0x20, len(case["rows"]))
    put(m, ST + 0x30, TOKS)
    put(m, ST + 0x38, len(case["toks"]))
    for i, (r0, r8) in enumerate(case["rows"]):
        put(m, ROWS + ROW_STRIDE * i, r0)
        put(m, ROWS + ROW_STRIDE * i + 8, r8)
    for i, (name) in enumerate(case["toks"]):
        put(m, TOKS + TOKEN_STRIDE * i + 0x38, NAMES + 16 * i)
        put(m, TOKS + TOKEN_STRIDE * i + 0x40, len(name))
        m.wr(NAMES + 16 * i, name + b"\0" * 4)
    put(m, SUP, case["supply_value"])
    put(m, CTX + 0x108, CTX_INIT)
    put(m, ONCE_CTX, case["once_ctx"], 4)
    put(m, ONCE_DFLT, case["once_dflt"], 4)
    write_R(m, DEFAULT_R, case["R_default"])
    if case["R_object"] is not None:
        write_R(m, ROBJ, case["R_object"])
    for i, (p, q, f) in enumerate(case["levels"]):
        m.wr(LEVELS + 24 * i, struct.pack("<QQQ", p, q, f))
    put(m, STACK_TOP, cpu.RETURN_MARK)
    m.set_reg(cpu.RSP, STACK_TOP)
    m.set_reg(cpu.RDI, OUT)
    m.set_reg(cpu.RSI, MAP)
    m.set_reg(cpu.RDX, P)
    m.set_reg(cpu.RCX, ST)
    m.set_reg(cpu.R8, CTX)
    m.set_reg(cpu.R9, 0)


def execute(image, case, steps=40000):
    case = copy.deepcopy(case)
    m = Recorder(image)
    m.setup(case)
    build(m, case)
    m.pc = ENTRY
    try:
        for _ in range(steps):
            m.step()
        raise cpu.ToolError("step bound")
    except cpu.Done as done:
        end = done
    ctx = m.load(CTX + 0x108, 8)
    if end.how == "ret":
        tag = m.load(OUT, 2)
        if tag == OK_TAG:
            outcome = ("ok", m.load(OUT + 8, 8))
        elif tag == ERR_TAG:
            ptr, ln = m.load(OUT + 8, 8), m.load(OUT + 0x10, 8)
            a, off, size = image.rodata
            if not a <= ptr < a + size:
                raise cpu.ToolError("refusal text outside rodata")
            outcome = ("err", image.data[ptr - a + off:ptr - a + off + ln])
        else:
            raise cpu.ToolError("unknown result tag %#x" % tag)
    else:
        name, loc = end.where
        outcome = ("panic", name, decode_location(image, loc))
    return outcome, m.trace, ctx, m.targets


def decode_location(image, va):
    file_ptr = image.slots.get(va)
    if file_ptr is None:
        raise cpu.ToolError("%#x is not a relocated Location" % va)
    length = struct.unpack_from("<Q", image.data, image.file_offset(va + 8))[0]
    line, col = struct.unpack_from("<II", image.data, image.file_offset(va + 16))
    if not 0 < length < 200:
        raise cpu.ToolError("Location file length out of range")
    off = image.file_offset(file_ptr)
    return image.data[off:off + length].decode(), line, col


# ---------------------------------------------------------------------------
# Independent specification, written from the listing
# ---------------------------------------------------------------------------
def message(image, name):
    a, off, _ = image.rodata
    return image.data[MSG[name] - a + off:MSG[name] - a + off + MSG_LEN[name]]


def tree_search(height, keys, children, key):
    """Return (node_keys, index) of the match or None; keys sorted inside each node."""
    nk, ch = keys, children
    h = height
    while True:
        i = 0
        while i < len(nk) and key > nk[i]:
            i += 1
        if i < len(nk) and key == nk[i]:
            return nk, i
        if h == 0:
            return None
        nk = ch[i][0]
        h -= 1


def trunc_signed(v):
    if v != v or not -(2.0 ** 63) <= v < 2.0 ** 63:
        return 1 << 63
    return int(v) & U64


def saturate(x, consts):
    """The double-to-u64 conversion at the end of the level-count formula."""
    cmax, c63, csat = consts
    bits = struct.unpack("<Q", struct.pack("<d", x))[0]
    if bits & 0x7fff_ffff_ffff_ffff > 0x7fef_ffff_ffff_ffff:
        v = 0.0
    elif 0.0 > x:
        v = min(cmax, max(0.0, x))
    elif x <= cmax:
        v = x
    else:
        v = min(cmax, max(0.0, x))
    a = trunc_signed(v)
    b = trunc_signed(v - c63)
    mask = U64 if a >> 63 else 0
    r = (b & mask) | a
    r = r if v >= 0.0 else 0
    return U64 if v > csat else r


def spec(image, case, consts, mut=()):
    m = lambda name: name in mut  # noqa: E731
    t = []
    A, tok, size, n, seeded, cap = case["P"]
    ctx = CTX_INIT

    def err(name, free=None):
        if free is not None and free[0]:
            t.append(("free", LEVELS, free[0] * 24, 0))
        return ("err", message(image, name)), t, ctx

    if n > (MAX_LEVELS + 1 if m("many_gt") else MAX_LEVELS):
        return err("too_many")
    if (n <= seeded) if m("seed_le") else (n < seeded):
        return err("cannot_seed")
    delta = n - seeded
    kind = case["map"]
    if kind[0] == "tree":
        exists = kind[2] is not None and tree_search(kind[1], kind[2], kind[3], tok) is not None
        exists = exists != m("exists_inv")
    else:
        t.append(("find_a", tok))
        exists = case["find_a"] == 0
    if exists:
        if case["once_ctx"] != 0:
            t.append(("once", "once_exists"))
        return err("exists")
    if tok >= len(case["rows"]):
        return ("panic", "panic_rows"), t, ctx
    row0, row8 = case["rows"][tok]
    t.append(("entry_lookup", 0x370))
    if case["once_dflt"] != 0:
        t.append(("once", "once_dflt"))
    R = case["R_object"] if case["entry_ptr"] else case["R_default"]
    if R[0] == "tree":
        _, height, keys, vals, children = R
        hit = tree_search(height, keys, children, row0) if keys is not None else None
        if hit is None:
            a, bz = 0, True
        else:
            node, i = hit
            entry = vals[i] if height == 0 else None
            if height != 0:
                entry = find_value(height, keys, vals, children, row0)
            a, bz = entry[0], entry[1] == 0
    else:
        _, rcap, head, entries = R
        t.append(("ring", "object" if case["entry_ptr"] else "default", row0))
        if case["ring_flag"] & 1:
            a, bz = 0, True
        elif case["ring_idx"] < len(entries):
            pos = case["ring_idx"] + head
            if pos >= rcap:
                pos -= rcap
            ent = dict(entries)[pos]
            a, bz = ent[0], ent[1] == 0
        else:
            a, bz = 0, True
    if (a | n) == 0 and not m("no_empty_path"):
        return finish(image, case, t, ctx, 0, MIN, 0, mut)
    if bz if m("hold_inv") else not bz:
        return err("hold")
    if row8 != 0:
        t.append(("drop", "drop_quote"))
        return err("quote")
    t.append(("supply", 0x510, row0))
    if not case["supply"] and not m("supply_skip"):
        t.append(("drop", "drop_supply"))
        return err("no_supply")
    if n < (MIN_LEVELS + 1 if m("few_off") else MIN_LEVELS):
        return err("too_few")
    c0, c1 = consts_pow(image)
    x = c0
    for _ in range(n):
        x *= c1
    t.append(("libm", struct.unpack("<Q", struct.pack("<d", x))[0]))
    y = saturate(case["libm"], consts)
    if size * n > U64 or size * n > LIM or (y >= Y_MAX if m("y_ge") else y > Y_MAX):
        return err("config")
    ay = A * y
    if ay > U64 or ay > LIM:
        return err("config")
    say = size * ay
    if say > U64 or say > (U64 if m("lim_off") else LIM):
        return err("config")
    if size == 0:
        return err("zero_size")
    need = delta * size
    if need > U64:
        need = U64
    t.append(("balance1", 0x10, row0, need))
    if case["bal_rax"] != 1 or (case["bal_rdx"] != a and not m("bal_loose")):
        t.append(("drop", "drop_balance"))
        t.append(("balance2", 0x10, row0, need))
        return err("balance")
    t.append(("levels", tok, A, size, n, 0x10))
    levels = case["levels"]
    lcap = case["lv_cap"]
    if not levels:
        return ("panic", "panic_none"), t, ctx
    first, last = levels[0][2], levels[-1][2]
    prod = first * size
    if prod <= START_MIN if m("prod_le") else (prod < START_MIN and prod <= U64):
        return err("start_value", (lcap,))
    if first == last and not m("same_ok"):
        return err("start_price", (lcap,))
    ticks = list(case["ticks"])
    pok = list(case["price_ok"])
    mcaps = list(case["mcaps"])
    for idx, price in enumerate((first, last) if m("order_swap") else (last, first)):
        lo, hi = BANDS[idx]
        if price == 0:
            break
        if price >= PRICE_MAX if m("price_ge") else price > PRICE_MAX:
            return err("price", (lcap,))
        t.append(("tick", 0x10, tok, price))
        tick = ticks.pop(0) if ticks else 1
        if price % tick != 0:
            return err("price", (lcap,))
        t.append(("price_ok", case["supply_value"], row0, price, 0x10))
        ok = pok.pop(0) if pok else 0
        mcap = mcaps.pop(0) if mcaps else 0
        passed = False
        if ok == 1:
            t.append(("cap_ok", lo, hi, mcap))
            passed = band_ok(lo, hi, mcap, mut)
            if case["once_ctx"] != 0:
                t.append(("once", "once_cap"))
        if not passed:
            if row0 >= len(case["toks"]):
                return ("panic", "panic_tokens"), t, ctx
            if m("hype_any") or case["toks"][row0] != b"HYPE":
                return err("mcap", (lcap,))
    t.append(("cost", lcap, LEVELS, seeded, size))
    if case["cost_rax"] != 1 or (case["cost_rdx"] >= cap if m("cost_ge") else case["cost_rdx"] > cap):
        t.append(("drop", "drop_cost"))
        return err("funds", (lcap,))
    return finish(image, case, t, ctx, case["cost_rdx"], lcap, LEVELS, mut)


def band_ok(lo, hi, mcap, mut=()):
    """0x38bcaa0: the market cap must lie within 0.7x of the lower and 1.3x of the upper band, in 1e-2 units."""
    low = lo * (0xaae61 if "low_mul" in mut else 0xaae60) * 100
    high = hi * 0x13d620 * 100
    if lo * 0xaae60 > U64 or low > U64 or hi * 0x13d620 > U64 or high > U64:
        return False
    return mcap >= low and (mcap < high if "high_lt" in mut else mcap <= high)


def find_value(height, keys, vals, children, key):
    nk, nv, ch, h = keys, vals, children, height
    while True:
        i = 0
        while i < len(nk) and key > nk[i]:
            i += 1
        if i < len(nk) and key == nk[i]:
            return nv[i]
        nk, nv = ch[i][0], ch[i][1]
        h -= 1


def finish(image, case, t, ctx, amount, v0, v1, mut):
    if case["once_ctx"] != 0:
        t.append(("once", "once_ctx"))
    A, tok = case["P"][0], case["P"][1]
    ctx = A if "ctx_skip" not in mut else ctx
    t.append(("insert", 0, tok, v0, v1 if v0 != MIN else case["P"][3]))
    old = case["old_cap"]
    signed = old - (1 << 64) if old >> 63 else old
    if signed >= -(1 << 63) + 2 and old != 0:
        t.append(("free", 0x7280_0000, (old * 24) & U64, 0))
    return ("ok", amount), t, ctx


def consts_pow(image):
    return (struct.unpack_from("<d", image.data, image.file_offset(0x4592b0))[0],
            struct.unpack_from("<d", image.data, image.file_offset(0x459390))[0])


def conv_consts(image):
    return tuple(struct.unpack_from("<d", image.data, image.file_offset(v))[0] for v in (0x459090, 0x459360, 0x458d58))


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------
CLASSES = ("ok", "ok", "ok_a", "ok_zero", "ok_zero", "many", "seed", "exists", "rows", "hold", "quote", "nosup", "few",
           "cfg_a", "cfg_b", "cfg_c", "cfg_d", "zero", "bal_rax", "bal_rdx", "lv_empty", "startval", "startprice",
           "pbig", "ptick", "pok0", "cok0", "hype", "toks_oob", "pzero", "cost_rax", "cost_over", "ok_hype_both",
           "exists_tree1", "y_edge", "startval_eq", "pmax")
SPECIAL_Y = (1e6 + 1, 1e300, float("inf"), float("nan"), 2.0 ** 64, 1.8446744073709552e19, 2.0 ** 63, 2.0 ** 63 + 2048,
             1e7, -1.5, -0.0, 0.0, 0.5, 1e6, 999999.5, 1844674407370955.0, 1.8446744073709550e19, 4294967296.0)


def rand_tree(rng, forbid=None, want=None):
    """A one- or two-level sorted tree of distinct u64 keys; `want` is forced in, `forbid` forced out."""
    height = rng.choice((0, 0, 1))
    pool = set()
    while len(pool) < rng.randint(0, 8 if height == 0 else 9):
        k = rng.getrandbits(rng.choice((8, 32, 64)))
        if k != forbid:
            pool.add(k)
    if want is not None:
        pool.add(want)
    keys = sorted(pool)
    if height == 0:
        return height, keys, None
    if len(keys) < 2:
        return 0, keys, None
    cut = sorted(rng.sample(range(len(keys)), min(len(keys), rng.randint(1, 3))))
    return 1, [keys[c] for c in cut], split_children(keys, cut)


def split_children(keys, cut):
    out, lo = [], 0
    for c in cut:
        out.append(keys[lo:c])
        lo = c + 1
    out.append(keys[lo:])
    return out


def rand_R(rng, row0, a, b, present):
    """Entry map keyed by row0 holding (a, b); `present` False leaves the key out."""
    if rng.random() < 0.5:
        height = rng.choice((0, 1))
        pool = set(rng.getrandbits(rng.choice((8, 40, 64))) for _ in range(rng.randint(0, 6)))
        pool.discard(row0)
        if present:
            pool.add(row0)
        keys = sorted(pool)
        if height == 1 and len(keys) >= 2:
            cut = sorted(rng.sample(range(len(keys)), rng.randint(1, min(3, len(keys)))))
            sep = [keys[c] for c in cut]
            kids = split_children(keys, cut)
            val = lambda k: (a, b, rng.getrandbits(64)) if k == row0 else (rng.getrandbits(64), rng.getrandbits(64), 0)  # noqa: E731
            return ("tree", 1, sep, [val(k) for k in sep], [(ks, [val(k) for k in ks]) for ks in kids])
        height = 0
        val = lambda k: (a, b, rng.getrandbits(64)) if k == row0 else (rng.getrandbits(64), rng.getrandbits(64), 0)  # noqa: E731
        return ("tree", 0, keys, [val(k) for k in keys], None) if keys else ("tree", 0, None, None, None)
    cap = rng.randint(2, 8)
    head = rng.randrange(cap)
    n = rng.randint(0, cap)
    entries = [((head + j) % cap, (rng.getrandbits(40) if rng.random() < 0.5 else a, 0 if rng.random() < 0.7 else b))
               for j in range(n)]
    return ("ring", cap, head, entries)


def edge_mcap(rng, lo, hi):
    low, high = lo * 0xaae60 * 100, hi * 0x13d620 * 100
    pick = rng.random()
    if pick < 0.6:
        return rng.randint(low, high)
    return rng.choice((low, low + 1, max(low - 1, 0), high, high + 1, high - 1, 0, U64, rng.getrandbits(64)))


def resolve(case):
    """Entry (a, bz) the specification reads from the entry map, without tracing."""
    R = case["R_object"] if case["entry_ptr"] else case["R_default"]
    row0 = case["rows"][case["P"][1]][0] if case["P"][1] < len(case["rows"]) else 0
    if R[0] == "tree":
        _, height, keys, vals, children = R
        if keys is None:
            return 0, True
        hit = tree_search(height, keys, children, row0)
        if hit is None:
            return 0, True
        entry = find_value(height, keys, vals, children, row0)
        return entry[0], entry[1] == 0
    _, rcap, head, entries = R
    if case["ring_flag"] & 1 or case["ring_idx"] >= len(entries):
        return 0, True
    pos = case["ring_idx"] + head
    if pos >= rcap:
        pos -= rcap
    ent = dict(entries)[pos]
    return ent[0], ent[1] == 0


def make_case(i):
    rng = random.Random("hyperliquidity-%d" % i)
    cls = CLASSES[i % len(CLASSES)]
    n = rng.randint(10, 60) if rng.random() > 0.01 else rng.randint(500, 4000)
    seeded = rng.randint(0, n)
    size = rng.randint(1, 1000)
    A = rng.randint(1, 1000)
    tok = rng.randrange(0, 5)
    nrows = tok + 1 + rng.randint(0, 2)
    rows = [(rng.randrange(0, 6) if rng.random() < 0.85 else rng.getrandbits(rng.choice((8, 40, 64))), 0) for _ in range(nrows)]
    row0 = rows[tok][0]
    ntoks = rng.randint(1, 7)
    toks = [rng.choice((b"HYPE", b"USDC", b"HYPX", b"PURR", b"HYP", b"HYPER", bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 7)))))
            for _ in range(ntoks)]
    if row0 < ntoks and rng.random() < 0.6 and cls not in ("hype", "ok_hype_both"):
        toks[row0] = b"PURR"
    kind = rng.choice(("ring", "tree"))
    if kind == "tree":
        height, keys, kids = rand_tree(rng, forbid=tok)
        mp = ("tree", height, keys, [(k, None) for k in kids] if kids else None)
        if keys == []:
            mp = ("tree", 0, None, None) if rng.random() < 0.5 else mp
    else:
        mp = ("ring",)
    entry_present = rng.random() < 0.5
    a_val = 0 if rng.random() < 0.5 else rng.getrandbits(rng.choice((8, 40, 64)))
    levels_n = rng.randint(1, 4)
    tick = rng.choice((1, 2, 3, 5, 10))
    first = 30 * rng.randint(40000, 10 ** 7)
    last = first + 30 * rng.randint(1, 10 ** 7)
    case = dict(
        P=(A, tok, size, n, seeded, rng.randint(1, 10 ** 12)), map=mp,
        find_a=rng.randint(1, 5) if kind == "ring" else 0,
        rows=rows, toks=toks, supply_value=rng.getrandbits(64), supply=rng.getrandbits(48) | 1,
        once_ctx=rng.choice((0, 0, 3, 1)), once_dflt=rng.choice((0, 0, 3, 2)),
        entry_ptr=ROBJ if rng.random() < 0.6 else 0,
        R_default=rand_R(rng, row0, a_val, 0, entry_present), R_object=rand_R(rng, row0, a_val, 0, True),
        ring_flag=rng.choice((0, 0, 0, 1)), ring_idx=rng.randint(0, 6),
        libm=float(rng.randint(1, 900000)) if rng.random() < 0.9 else rng.choice(SPECIAL_Y),
        bal_rax=1, bal_rdx=0, lv_cap=rng.choice((0, 1, 3, levels_n, 100)),
        levels=[(rng.getrandbits(64), rng.getrandbits(64), first)] + [(rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64))
                                                                     for _ in range(levels_n - 2)] + [(rng.getrandbits(64), rng.getrandbits(64), last)]
        if levels_n >= 2 else [(rng.getrandbits(64), rng.getrandbits(64), first)],
        ticks=[tick, tick], price_ok=[1, 1], mcaps=[0, 0], cost_rax=1, cost_rdx=0,
        old_cap=rng.choice((MIN, MIN + 1, MIN + 2, 0, 5, 7, U64, 1 << 62)),
    )
    mc0 = edge_mcap(rng, *BANDS[0])
    mc1 = edge_mcap(rng, *BANDS[1])
    case["mcaps"] = [mc0, mc1]
    if cls == "ok_zero":
        P = list(case["P"])
        P[3], P[4] = 0, 0
        case["P"] = tuple(P)
        rows[tok] = (rows[tok][0], rows[tok][1])
        case["R_default"] = rand_R(rng, row0, 0, 0, False)
        case["R_object"] = rand_R(rng, row0, 0, 0, False)
        case["entry_ptr"] = 0 if rng.random() < 0.5 else ROBJ
        case["ring_flag"] = 1
        if rng.random() < 0.5:
            case["ring_flag"] = rng.choice((0, 1))
            case["ring_idx"] = 99
    a, bz = resolve(case)
    case["bal_rdx"] = a
    a_now = a
    P = list(case["P"])
    cap = P[5]
    y = saturate(case["libm"], CONV)
    case["cost_rdx"] = rng.randint(0, cap)
    if cls == "ok_a":
        case["R_object"] = rand_R(rng, row0, rng.getrandbits(32) | 1, 0, True)
        case["entry_ptr"] = ROBJ
        a_now = resolve(case)[0]
        case["bal_rdx"] = a_now
    if cls == "many":
        P[3] = rng.choice((MAX_LEVELS + 1, MAX_LEVELS + 2, 5000, 1 << 40, U64))
        P[4] = rng.randint(0, 9)
    if cls == "seed":
        P[4] = P[3] + rng.choice((1, 2, 100, 1 << 40))
    if cls == "exists":
        if kind == "tree":
            height, keys, kids = rand_tree(rng, want=tok)
            case["map"] = ("tree", height, keys, [(k, None) for k in kids] if kids else None)
        else:
            case["find_a"] = 0
    if cls == "exists_tree1":
        case["map"] = ("tree", 1, [tok + 50], [([tok], None), ([tok + 99], None)])
    if cls == "rows":
        case["rows"] = rows[:tok]
    if cls == "hold":
        case["R_object"] = rand_R(rng, row0, rng.getrandbits(8), 5 + rng.getrandbits(8), True)
        case["entry_ptr"] = ROBJ
        case["ring_flag"] = 0
        case["ring_idx"] = 0
        if case["R_object"][0] == "ring" and case["R_object"][3]:
            lst = case["R_object"][3]
            case["R_object"] = ("ring", case["R_object"][1], case["R_object"][2], [(lst[0][0], (lst[0][1][0], 9))] + lst[1:])
            case["ring_idx"] = 0
    if cls == "quote":
        rows[tok] = (row0, rng.choice((1, 2, 1 << 40, U64)))
    if cls == "nosup":
        case["supply"] = 0
    if cls == "few":
        P[3] = rng.randint(0, 9)
        P[4] = rng.randint(0, P[3])
        case["R_object"] = rand_R(rng, row0, 0, 0, False)
        case["R_default"] = rand_R(rng, row0, 0, 0, False)
        case["ring_flag"] = 1
        case["bal_rdx"] = 0
        if P[3] == 0:
            P[3] = rng.randint(1, 9)
    if cls == "cfg_a":
        P[2] = rng.choice((LIM // P[3] + 1, U64 // max(P[3], 1) + 1, 1 << 63))
        if rng.random() < 0.5:
            case["libm"] = rng.choice((0.5, 0.0, float("nan"), -1.0))
            P[2] = LIM // P[3] + rng.randint(1, 3)
    if cls == "cfg_b":
        case["libm"] = rng.choice(SPECIAL_Y[:9])
    if cls == "cfg_c":
        y = saturate(case["libm"], CONV) or 1
        P[0] = rng.choice((LIM // y + 1, 1 << 50, U64, LIM // y + rng.randint(2, 9)))
    if cls == "cfg_d":
        y = saturate(case["libm"], CONV) or 1
        P[0] = max(1, LIM // y // 2)
        P[2] = rng.randint(3, 50)
    if cls == "zero":
        P[2] = 0
    if cls == "bal_rax":
        case["bal_rax"] = rng.choice((0, 2, U64, 1 << 33))
    if cls == "bal_rdx":
        case["bal_rdx"] = (a_now + rng.choice((1, 2, U64))) & U64
    if cls == "lv_empty":
        case["levels"] = []
    if cls == "startval":
        case["levels"][0] = (0, 0, rng.choice((1, 2, START_MIN // P[2], max(1, START_MIN // P[2] - 1))))
        if len(case["levels"]) == 1:
            case["levels"].append((0, 0, rng.getrandbits(40) + 5))
    if cls == "startprice":
        case["levels"][-1] = case["levels"][0] if len(case["levels"]) > 1 else case["levels"][-1]
        if len(case["levels"]) == 1:
            case["levels"].append(case["levels"][0])
    if cls == "pbig":
        case["levels"][-1] = (0, 0, rng.choice((PRICE_MAX + 1, U64, PRICE_MAX + 30)))
        if rng.random() < 0.5:
            case["levels"][0] = (0, 0, PRICE_MAX + 1 + 30 * rng.randint(0, 5))
            case["levels"][-1] = (0, 0, 30 * rng.randint(1, 100))
        if len(case["levels"]) == 1:
            case["levels"].append((0, 0, 30))
    if cls == "ptick":
        case["ticks"] = [rng.choice((7, 11, 4000000007)), 7] if rng.random() < 0.5 else [tick, 7]
        case["ticks"][0] = case["ticks"][0] if rng.random() < 0.5 else 7
    if cls == "pok0":
        case["price_ok"] = [rng.choice((0, 2, U64)), 1] if rng.random() < 0.5 else [1, rng.choice((0, 2))]
    if cls == "cok0":
        mc0, mc1 = BANDS[0][0] * 0xaae60 * 100 - 1, BANDS[1][1] * 0x13d620 * 100 + 1
        case["mcaps"] = [rng.choice((0, U64, 10 ** 30 % U64)), 5] if rng.random() < 0.5 else [mc0, 10 ** 16]
    if cls == "hype":
        toks[:] = [b"HYPE"] * ntoks
        case["price_ok"] = [0, 0]
        case["mcaps"] = [0, 0]
    if cls == "ok_hype_both":
        toks[:] = [b"HYPE"] * ntoks
        case["price_ok"] = [rng.choice((0, 1)), rng.choice((0, 1))]
        case["mcaps"] = [rng.choice((0, mc0, U64)), rng.choice((0, mc1, U64))]
    if cls == "toks_oob":
        case["toks"] = toks[:0] if rng.random() < 0.5 else toks[:max(0, row0 - 1) if row0 < 9 else 0]
        case["price_ok"] = [0, 0]
    if cls == "pzero":
        case["levels"][-1] = (0, 0, 0) if len(case["levels"]) > 1 else case["levels"][-1]
        if len(case["levels"]) == 1:
            case["levels"].append((0, 0, 0))
        if rng.random() < 0.5:
            case["levels"][0] = (0, 0, 30 * rng.randint(40000, 100000))
            case["price_ok"] = [1, 1]
    if cls == "cost_rax":
        case["cost_rax"] = rng.choice((0, 2, U64))
    if cls == "cost_over":
        case["cost_rdx"] = cap + rng.choice((1, 2, U64 - cap))
        case["cost_rdx"] = min(case["cost_rdx"], U64)
        if rng.random() < 0.3:
            case["cost_rdx"] = cap
    if cls == "y_edge":
        case["libm"] = rng.choice((1e6, 999999.5, 1000000.4, 999999.0, 1000000.9999))
    if cls == "startval_eq":
        P[2] = 1000
        case["ticks"] = [10, 10]
        if len(case["levels"]) == 1:
            case["levels"].append((0, 0, 30 * rng.randint(40000, 10 ** 6)))
        case["levels"][0] = (0, 0, 1000)
        case["levels"][-1] = (0, 0, 30 * rng.randint(40000, 10 ** 6))
    if cls == "pmax":
        case["ticks"] = [5, 5]
        if len(case["levels"]) == 1:
            case["levels"].append((0, 0, 30 * rng.randint(40000, 10 ** 6)))
        case["levels"][-1] = (0, 0, PRICE_MAX)
    case["P"] = tuple(P)
    case["rows"] = list(case["rows"])
    return case


# ---------------------------------------------------------------------------
# Verification driver
# ---------------------------------------------------------------------------
def compare(image, case, mut=()):
    got, trace, ctx, targets = execute(image, case)
    want, want_trace, want_ctx = spec(image, case, CONV, mut)
    if want[0] == "panic":
        same = got[0] == "panic" and got[1] == want[1]
    else:
        same = got == want
    return same and trace == want_trace and ctx == want_ctx, got, targets


def classify(got):
    if got[0] == "panic":
        return "panic:" + got[1]
    if got[0] == "err":
        for name in MSG:
            if got[1] == MESSAGES.get(name):
                return "err:" + name
        return "err:?"
    return got[0]


def run_cases(image, count, mut=(), start=0):
    for i in range(start, start + count):
        try:
            ok, _, _ = compare(image, make_case(i), mut)
        except (cpu.ToolError, cpu.Done, KeyError, ValueError, TypeError, OverflowError, struct.error, IndexError,
                ZeroDivisionError, AssertionError):
            return i
        if not ok:
            return i
    return None


BYTE_PATCHES = (
    # name, pattern, index, replacement, meaning
    ("max_levels", b"\x49\x81\xfd\xa0\x0f\x00\x00", 3, 0xa1, "level limit 4000 -> 4001"),
    ("min_levels", b"\x49\x83\xfd\x0a", 3, 0x0b, "level floor 10 -> 11"),
    ("y_limit", b"\x48\x81\xf9\x40\x42\x0f\x00", 3, 0x41, "count limit 1000000 -> 1000001"),
    ("mul_limit", b"\x48\xbe\x99\x99\x99\x99\x99\x99\x99\x19", 9, 0x1a, "product limit top byte raised"),
    ("price_limit", b"\x48\xb9\x00\x80\xc6\xa4\x7e\x8d\x03\x00", 3, 0x81, "price limit 1e15 -> 1e15+256"),
    ("band_end_lo", b"\x48\xc7\x44\x24\x78\x00\xca\x9a\x3b", 6, 0xcb, "end band lower 1e9 raised"),
    ("band_start_hi", b"\x48\xc7\x84\x24\x98\x00\x00\x00\x80\x96\x98\x00", 8, 0x81, "start band upper 1e7 raised"),
    ("hype_text", b"\x81\x38\x48\x59\x50\x45", 2, 0x49, "exempt name HYPE -> IYPE"),
    ("hype_len", b"\x48\x83\x78\x40\x04", 4, 0x05, "exempt name length 4 -> 5"),
    ("tag_err", b"\x66\xc7\x07\xee\x00", 3, 0xef, "refusal tag 0xee -> 0xef"),
    ("tag_ok", b"\x66\xc7\x07\xa2\x01", 3, 0xa3, "success tag 0x1a2 -> 0x1a3"),
    ("token_stride", b"\x48\x69\x4c\x24\x18\x58\x01\x00\x00", 5, 0x59, "token record stride 0x158 -> 0x159"),
    ("row_shift", b"\x48\xc1\xe2\x05", 3, 0x04, "row stride 32 -> 16"),
    ("seed_borrow", b"\x49\x29\xc2\x73", 3, 0x72, "seed count borrow test inverted"),
    ("tok_bound", b"\x48\x39\xf3\x0f\x83", 4, 0x82, "row bounds test inverted"),
    ("bal_one", b"\x48\x83\xf8\x01\x0f\x85", 5, 0x84, "balance flag test inverted"),
    ("bal_cmp", b"\x48\x39\xea\x0f\x85", 4, 0x84, "balance equality test inverted"),
    ("first_last", b"\x48\x39\xc1\x0f\x85", 4, 0x84, "start/end price equality test inverted"),
    ("price_gt", b"\x49\x39\xcc\x0f\x87", 4, 0x83, "price limit test ja -> jae"),
    ("cap_gt", b"\x48\x3b\x94\x24\xc0\x00\x00\x00\x0f\x87", 9, 0x83, "funding cap test ja -> jae"),
    ("ctx_store", b"\x48\x89\x88\x08\x01\x00\x00", 3, 0x90, "context write base register changed"),
    ("pow_blocks", b"\x81\xe1\xf8\x0f\x00\x00", 2, 0xf0, "multiplication block mask 0xff8 -> 0xff0"),
    ("pow_rest", b"\x83\xe0\x07", 2, 0x06, "multiplication remainder mask 7 -> 6"),
    ("band_low_mul", b"\xba\x60\xae\x0a\x00", 1, 0x61, "lower band factor 700000 -> 700001"),
    ("band_high_mul", b"\xba\x20\xd6\x13\x00", 1, 0x21, "upper band factor 1300000 -> 1300001"),
    ("band_low_cmp", b"\x0f\x93\xc2", 1, 0x92, "lower band test setae -> setb"),
    ("band_high_cmp", b"\x0f\x96\xc0", 1, 0x97, "upper band test setbe -> seta"),
    ("band_and", b"\x20\xd0", 0, 0x08, "both band tests and -> or"),
    ("band_scale", b"\xba\x64\x00\x00\x00", 1, 0x65, "first band scale 100 -> 101"),
    ("one_usdc", b"\x48\x3d\x40\x42\x0f\x00", 2, 0x41, "starting value floor 1e6 -> 1e6+1"),
    ("msg_len_seed", b"\x41\xbf\x22\x00\x00\x00", 2, 0x21, "seed refusal length 34 -> 33"),
)


def patched_image(image, patch):
    name, pattern, index, value, _ = patch
    data = bytearray(image.data)
    off = image.file_offset(ENTRY)
    at = bytes(data[off:off + WINDOW]).find(pattern)
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


def init(image):
    global CONV, MESSAGES
    CONV = conv_consts(image)
    MESSAGES = {name: message(image, name) for name in MSG}


SPEC_MUTANTS = (
    ("many_gt", "level limit test uses > 4001"), ("few_off", "level floor one higher"),
    ("lim_off", "final product limit dropped"), ("hype_any", "market cap band applies to HYPE too"),
    ("ctx_skip", "context write dropped"), ("no_empty_path", "empty seed treated as a normal seed"),
    ("seed_le", "seed count refused at equality"), ("exists_inv", "duplicate test inverted"),
    ("hold_inv", "holdings test inverted"), ("y_ge", "count limit refused at equality"),
    ("bal_loose", "balance equality not checked"), ("prod_le", "starting value refused at the floor"),
    ("price_ge", "price limit refused at the limit"), ("order_swap", "bands applied to the wrong price"),
    ("cost_ge", "funding refused at the cap"), ("supply_skip", "missing supply not refused"),
    ("same_ok", "equal start and end price accepted"), ("low_mul", "lower band factor 700001"),
    ("high_lt", "upper band excludes equality"),
)


def misc_controls(image):
    out = []

    def raises(fn, kinds):
        try:
            fn()
        except kinds:
            return True
        return False

    damaged = bytearray(image.data)
    damaged[100] ^= 1
    out.append(("digest_flip", "one flipped byte fails the digest check", not check_digest(bytes(damaged))))
    out.append(("fde_start", "an address inside the body is refused as a start",
                raises(lambda: body_extent(image, ENTRY + 4), cpu.ToolError)))
    out.append(("extent", "the body keeps its recorded extent", body_extent(image, ENTRY) == SIZE))
    out.append(("band_extent", "the band check keeps its recorded extent", body_extent(image, CAP_CHECK) == CAP_SIZE))
    m = Recorder(image)
    m.setup({})
    out.append(("unknown_site", "a call outside the site table is refused",
               raises(lambda: m.call(0, ENTRY + 1), cpu.ToolError)))
    out.append(("unwritten_read", "a stub read of unwritten memory is refused",
                raises(lambda: m.rd(0x1234, 4), cpu.ToolError)))
    out.append(("bad_location", "a non-Location address is refused",
                raises(lambda: decode_location(image, 0x400100), cpu.ToolError)))
    out.append(("wide_value", "a 65-bit value cannot enter a 64-bit slot",
                raises(lambda: put(m, 0x10, 1 << 64), OverflowError)))
    out.append(("msg_text", "a refusal text outside the table does not classify",
                classify(("err", b"nothing")) == "err:?"))
    return out


def write_lines(path, lines):
    with open(path, "w", newline="\n") as f:
        for line in lines:
            f.write(line + "\n")


CASES = 12000
CONTROL_CASES = 700


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if not check_digest(data):
        raise SystemExit("node #115 digest mismatch")
    image = cpu.Image(data)
    init(image)
    if body_extent(image, ENTRY) != SIZE or body_extent(image, CAP_CHECK) != CAP_SIZE:
        raise SystemExit("body extent changed")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    counts, targets, locations, mismatches, sample = {}, {}, {}, 0, []
    for i in range(CASES):
        ok, got, tg = compare(image, make_case(i))
        mismatches += not ok
        key = classify(got)
        counts[key] = counts.get(key, 0) + 1
        targets.update(tg)
        if i % 20 == 0:
            case = make_case(i)
            sample.append("%d\t%s\t%s\t%s\t%s" % (i, CLASSES[i % len(CLASSES)], key, ",".join(str(v) for v in case["P"]),
                                                  ",".join(sorted({e[0] if e[0] != "once" else e[1] for e in execute(image, case)[1]}))))
        if got[0] == "panic":
            prev = locations.setdefault(got[1], got[2])
            if prev != got[2]:
                raise SystemExit("panic site %s moved" % got[1])
    if mismatches:
        raise SystemExit("%d mismatches" % mismatches)
    controls = []
    for name, meaning in SPEC_MUTANTS:
        controls.append(("spec:" + name, meaning, run_cases(image, CONTROL_CASES, (name,))))
    for patch in BYTE_PATCHES:
        controls.append(("byte:" + patch[0], patch[4], run_cases(patched_image(image, patch), CONTROL_CASES)))
    for name, meaning, detected in misc_controls(image):
        controls.append(("misc:" + name, meaning, 0 if detected else None))
    detected = sum(1 for c in controls if c[2] is not None)
    write_lines(out / "callees.tsv", ["offset\tsite\ttarget"] + [
        "%#x\t%s\t%#x" % (off, name, targets[name]) for off, name in sorted(SITES.items()) if name in targets])
    write_lines(out / "locations.tsv", ["site\tfile\tline\tcolumn"] + [
        "%s\t%s\t%d\t%d" % ((s,) + locations[s]) for s in sorted(locations)])
    write_lines(out / "messages.tsv", ["name\tlength\ttext"] + [
        "%s\t%d\t%s" % (n, MSG_LEN[n], MESSAGES[n].decode()) for n in sorted(MSG)])
    write_lines(out / "cases.tsv", ["case\tclass\toutcome\tparams_A_tok_size_n_seeded_cap\tcalls_reached"] + sample)
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
