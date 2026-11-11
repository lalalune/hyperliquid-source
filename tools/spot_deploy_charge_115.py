"""Exchange spot-deploy perp-to-spot charge path of node #115, recovered from bytes.

Three 2.4 KB bodies (0x2c57090, 0x55cbcc0, 0x55cc610) of impl_spot_deploy.rs
share one control flow: look up the user and amount, refuse above a counter
limit, ask the fee helper, round the fee up to whole units, mark the ledger
row and, when the charge is non-zero, debit it through two helpers and emit an
event. The tool runs each body from its own bytes in the shared evaluator with
every callee replaced by a recorded stub, then compares the call trace, the
returned value and the ledger row with an independent specification.
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
OK_TAG = 0x1a2
LIMIT = 0x68db8bac710cb
LIMIT_TEXT = b"could not convert perp usdc to spot"
U64 = cpu.U64

STACK_TOP = cpu.STACK + 0x10000
CTX = cpu.INPUT
KEYS = 0x7200_0000
ROWS = 0x7210_0000
OUT = 0x7230_0000
ALLOC = 0x7250_0000
STR_A = 0x7260_0000
STR_B = 0x7261_0000
ROW = 0x158

# start, ledger-flag offset, counter object offset, ... per body (bytes of the
# three bodies are the same length, so call sites sit at the same offsets)
LAYOUT_A = dict(valid=0x7d0, cobj=0x7c8, len3=0x3ae8, base3=0x3ae0, fee=0x3fc8, vec=0x7c0, r11=0x7d8, r10=0x3f08, b9a=0xb9a, event=0xb9b)
LAYOUT_B = dict(valid=0x1340, cobj=0x1338, len3=0x4658, base3=0x4650, fee=0x4b38, vec=0x1330, r11=0x1348, r10=0x4a78, b9a=0x170a, event=0x7c0)
BODIES = {
    "A": (0x2c57090, 2399, LAYOUT_A),
    "B": (0x55cbcc0, 2383, LAYOUT_B),
    "C": (0x55cc610, 2383, LAYOUT_A),
}
# call-site offsets from the body start, in listing order (the 0x2c57090 body is 16 bytes
# longer after the debit helper because its tail helper is reached by a shorter form)
SITE_ORDER = ("parse_a", "lookup", "parse_b", "scale", "drop_slot", "counter", "fee", "vec_new", "vec_push",
              "debit1", "debit2", "alloc", "context", "drop_err", "drop_addr", "event", "panic_key", "panic_slot",
              "panic_row", "panic_debit1", "panic_debit2", "panic_idx0", "panic_idx1", "panic_none")
OFFSETS_A = (0x51, 0x93, 0xc8, 0x142, 0x181, 0x1a4, 0x240, 0x2df, 0x2f5, 0x350, 0x397, 0x3b6, 0x42e, 0x5fb, 0x6fe,
             0x767, 0x77e, 0x78b, 0x798, 0x81e, 0x8a9, 0x8bb, 0x8cb, 0x8f7)
OFFSETS_BC = (0x51, 0x93, 0xc8, 0x142, 0x181, 0x1a4, 0x240, 0x2df, 0x2f5, 0x350, 0x387, 0x3a6, 0x41e, 0x5eb, 0x6ee,
              0x757, 0x76e, 0x77b, 0x788, 0x80e, 0x899, 0x8ab, 0x8bb, 0x8e7)
SITE_MAP = {"A": dict(zip(OFFSETS_A, SITE_ORDER)), "B": dict(zip(OFFSETS_BC, SITE_ORDER)),
            "C": dict(zip(OFFSETS_BC, SITE_ORDER))}
PANICS = ("panic_idx0", "panic_idx1", "panic_key", "panic_slot", "panic_row", "panic_none", "panic_debit1", "panic_debit2")
LOC_REG = {"panic_idx0": cpu.RDX, "panic_idx1": cpu.RDX, "panic_key": cpu.RDI, "panic_slot": cpu.RDI,
           "panic_row": cpu.RDI, "panic_none": cpu.R8, "panic_debit1": cpu.R8, "panic_debit2": cpu.R8}
DIVISOR = 1e6


class Machine(cpu.Machine):
    """Shared evaluator plus the few forms this path needs: ror, pcmpeqd, cvtsi2sd, divsd, movsd store."""

    def shift(self, kind, value, count, bits):
        if kind != 1:
            return super().shift(kind, value, count, bits)
        if bits != 64 or value is None or count is None or not 1 <= count <= 63:
            raise cpu.ToolError("ror outside the modelled 64-bit immediate domain")
        result = ((value >> count) | (value << (64 - count))) & U64
        self.flags = [bool(result >> 63), self.flags[1], self.flags[2], None]
        return result

    def two_byte(self, insn, key, bits, rexr, here):
        data = self.image.data
        reg = ((data[insn.modrm] >> 3) & 7) | rexr if insn.modrm is not None else 0
        if len(key) == 2 and key[1] == 0x76 and insn.wide16:
            if self.operand(insn) != ("r", reg):
                raise cpu.ToolError("pcmpeqd of two different registers")
            self.xmm[reg] = b"\xff" * 16
            return
        if len(key) == 2 and key[1] == 0x2a and insn.rep == 0xf2:
            value = self.read(self.operand(insn), 64)
            signed = value - (1 << 64) if value >> 63 else value
            self.xmm[reg] = struct.pack("<dQ", float(signed), 0)
            return
        if len(key) == 2 and key[1] == 0x5e and insn.rep == 0xf2:
            operand = self.operand(insn)
            bits64 = self.read(operand, 64)
            left = struct.unpack("<d", self.xmm[reg][:8])[0]
            right = struct.unpack("<d", struct.pack("<Q", bits64))[0]
            self.xmm[reg] = struct.pack("<d", left / right) + self.xmm[reg][8:]
            return
        if len(key) == 2 and key[1] == 0x11 and insn.rep == 0xf2:
            operand = self.operand(insn)
            if operand[0] != "m":
                raise cpu.ToolError("movsd register store")
            self.store(self.address(operand), 8, struct.unpack("<Q", self.xmm[reg][:8])[0])
            return
        super().two_byte(insn, key, bits, rexr, here)

    def call(self, target, where):
        raise cpu.ToolError("call without a stub at %#x" % where)


class Recorder(Machine):
    """Machine whose calls are stubs driven by one case; trace holds what each stub saw."""

    def setup(self, body, case):
        self.body = body
        self.start, _, self.layout = BODIES[body]
        self.case = case
        self.trace = []
        self.targets = {}
        self.entry_rsp = STACK_TOP
        self.body_rsp = STACK_TOP - 0x258

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

    def result(self, spec_result, at):
        self.wr(at, spec_result)

    def clobber(self, rax=None):
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        self.xmm = [None] * 16
        self.flags = [None, None, None, None]
        if rax is not None:
            self.set_reg(cpu.RAX, rax)

    def call(self, target, where):
        site = SITE_MAP[self.body].get(where - self.start)
        if site is None:
            raise cpu.ToolError("unknown call site %#x" % where)
        self.targets[site] = target
        g = lambda r: self.get(r, 64)  # noqa: E731
        c, L = self.case, self.layout
        rel = lambda r: g(r) - self.body_rsp  # noqa: E731
        t = self.trace
        if site in PANICS:
            raise cpu.Done(site, (site, g(LOC_REG[site])))
        if site in ("parse_a", "parse_b"):
            t.append((site, g(cpu.RSI), g(cpu.RDX), rel(cpu.RDI)))
            res = c[site]
            self.result(res, g(cpu.RDI))
            if site == "parse_b" and "mut_len0" in c:
                self.store(CTX + 0xa0, 8, c["mut_len0"])
            self.clobber()
        elif site == "lookup":
            t.append((site, g(cpu.RSI) - CTX, g(cpu.RDX), self.rd(g(cpu.RCX), 16), rel(cpu.RDI)))
            self.result(c["lookup"], g(cpu.RDI))
            self.clobber()
        elif site == "scale":
            t.append((site, self.rd(g(cpu.RSI), 16), g(cpu.RDX), self.get(cpu.RCX, 32), rel(cpu.RDI)))
            self.result(c["scale"], g(cpu.RDI))
            self.clobber()
        elif site == "drop_slot":
            t.append((site, rel(cpu.RDI), self.load(g(cpu.RDI), 2)))
            self.clobber()
        elif site == "counter":
            t.append((site, g(cpu.RDI), self.rd(g(cpu.RSI), 20)))
            self.clobber(c["counter"])
        elif site == "fee":
            t.append((site, rel(cpu.RDI), g(cpu.RSI) - CTX, self.rd(g(cpu.RDX), 48), g(cpu.RCX) - CTX, g(cpu.R8)))
            self.result(c["fee"], g(cpu.RDI))
            if "mut_len2" in c:
                self.store(CTX + 0xb8, 8, c["mut_len2"])
            self.clobber()
        elif site == "vec_new":
            t.append((site, g(cpu.RDI) - CTX, g(cpu.RSI)))
            self.clobber(c["vec_handle"])
        elif site == "vec_push":
            t.append((site, g(cpu.RDI), g(cpu.RSI)))
            self.clobber(c["push_handle"])
        elif site == "debit1":
            sp = g(cpu.RSP)
            t.append((site, rel(cpu.RDI), g(cpu.RSI), self.rd(g(cpu.RDX), 20), self.rd(g(cpu.RCX), 20), g(cpu.R8),
                      g(cpu.R9), self.load(sp, 8) - CTX, self.load(sp + 8, 8) - CTX))
            self.result(c["debit1"], g(cpu.RDI))
            self.clobber()
        elif site == "debit2":
            t.append((site, rel(cpu.RDI), g(cpu.RSI) - CTX, g(cpu.RDX), self.rd(g(cpu.RCX), 20), g(cpu.R8), g(cpu.R9)))
            self.result(c["debit2"], g(cpu.RDI))
            self.clobber()
        elif site == "alloc":
            t.append((site, g(cpu.RDI), g(cpu.RSI)))
            self.clobber(ALLOC)
        elif site == "context":
            t.append((site, rel(cpu.RDI), self.get(cpu.RSI, 32), g(cpu.RDX), g(cpu.RCX), self.get(cpu.R8, 32)))
            self.wr(g(cpu.RDI), c["context"])
            self.clobber()
        elif site == "drop_addr":
            t.append((site, rel(cpu.RDI), self.rd(g(cpu.RDI), 20)))
            self.clobber()
        elif site == "drop_err":
            t.append((site, rel(cpu.RDI), self.rd(g(cpu.RDI), 0x70)))
            self.clobber()
        elif site == "event":
            vec = g(cpu.RSI)
            ptr = self.load(vec + 8, 8)
            r8 = g(cpu.R8)
            t.append((site, g(cpu.RDI) - CTX, self.load(vec, 8), self.load(vec + 16, 8), self.rd(ptr, 20),
                      self.rd(g(cpu.RDX), 8), self.load(g(cpu.RDX) + 8, 4), self.rd(g(cpu.RCX), 32),
                      self.load(r8, 8), self.rd(r8 + 8, 16), self.load(r8 + 0x18, 4), self.rd(r8 + 0x20, 8)))
            self.clobber()
        else:
            raise cpu.ToolError("unhandled site " + site)


def put(m, at, value, n=8):
    m.wr(at, value.to_bytes(n, "little"))


def build(m, body, case):
    """Lay out the context, the rows, the argument registers and the return mark."""
    L = m.layout
    put(m, CTX + 0xa0, case["len0"])
    put(m, CTX + 0x98, KEYS)
    put(m, CTX + 0xb8, case["len2"])
    put(m, CTX + 0xb0, ROWS)
    put(m, CTX + L["valid"], case["valid"])
    put(m, CTX + L["cobj"], case["cobj"])
    put(m, CTX + L["len3"], case["len3"])
    put(m, CTX + L["base3"], case["base3"])
    put(m, CTX, case["mode"], 4)
    put(m, CTX + 8, case["c8"])
    put(m, CTX + 0x28, case["c28"])
    m.mem[CTX + L["b9a"]] = case["b9a"]
    put(m, CTX + 0x60, case["c60"])
    put(m, CTX + 0x68, case["c68"], 4)
    for i, key in enumerate(case["keys"]):
        put(m, KEYS + 32 * i, key)
    for i, row in enumerate(case["rows"]):
        m.wr(ROWS + ROW * i, row)
    m.wr(STR_A, b"\0" * 8)
    put(m, STR_A + 8, case["str_a"][0])
    put(m, STR_A + 0x10, case["str_a"][1])
    put(m, STR_B + 8, case["str_b"][0])
    put(m, STR_B + 0x10, case["str_b"][1])
    addr_at = 0x7270_0000
    m.wr(addr_at, case["addr"])
    sp = STACK_TOP
    put(m, sp, cpu.RETURN_MARK)
    put(m, sp + 8, case["stack1"])
    put(m, sp + 0x10, case["stack2"])
    m.set_reg(cpu.RSP, sp)
    m.set_reg(cpu.RDI, OUT)
    m.set_reg(cpu.RSI, CTX)
    m.set_reg(cpu.RDX, addr_at)
    m.set_reg(cpu.RCX, case["idx"])
    m.set_reg(cpu.R8, STR_A)
    m.set_reg(cpu.R9, STR_B)


def execute(image, body, case):
    m = Recorder(image)
    m.setup(body, case)
    build(m, body, case)
    m.pc = m.start
    try:
        for _ in range(4000):
            m.step()
        raise cpu.ToolError("step bound")
    except cpu.Done as done:
        end = done
    if end.how == "ret":
        tag = m.load(OUT, 2)
        if tag == OK_TAG:
            outcome = ("ok",)
        elif tag == 0xee:
            ptr, ln = m.load(OUT + 8, 8), m.load(OUT + 0x10, 8)
            a, off, _ = image.rodata
            if not a <= ptr < a + image.rodata[2]:
                raise cpu.ToolError("refusal text outside rodata")
            outcome = ("limit", image.data[ptr - a + off:ptr - a + off + ln])
        else:
            outcome = ("err", m.rd(OUT, 0x70))
    else:
        name, loc = end.where
        outcome = ("panic", name, decode_location(image, loc))
    row = tuple(m.load(ROWS + ROW * case["keys"][case["idx"]] + o, 8) if case["idx"] < len(case["keys"]) and case["keys"][case["idx"]] < len(case["rows"]) else None for o in (0, 8))
    return outcome, m.trace, row, m.targets


def decode_location(image, va):
    """Rust panic Location: file pointer (relative reloc), file length, line, column."""
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
# Independent specification of the same path, written from the listing.
# ---------------------------------------------------------------------------
def ceil_div100(fee, mut=()):
    q, r = divmod(fee, 100)
    if "floor" in mut:
        return q
    if "always_up" in mut:
        return q + 1
    return q + (1 if r else 0)


def spec(body, case, mut=()):
    """Return (outcome, trace, row) the body must produce for the stub answers in `case`."""
    L = BODIES[body][2]
    t = []
    m = lambda n: n in mut  # noqa: E731
    idx = case["idx"]
    row_before = None
    if idx > case["len0"] if m("idx_gt") else idx >= case["len0"]:
        return ("panic", "panic_idx0"), t, None
    key = case["keys"][idx]
    pa = case["parse_a"]
    t.append(("parse_a", STR_A_PTR(case), STR_A_LEN(case), 0x30))
    if tag_of(pa) != OK_TAG:
        return ("err", pa), t, None
    t.append(("lookup", 0x90, idx, pa[4:20], 0xe0))
    lk = case["lookup"]
    if tag_of(lk) != OK_TAG:
        return ("err", lk), t, None
    owner = val_of(lk)
    t.append(("parse_b", STR_B_PTR(case), STR_B_LEN(case), 0x30))
    pb = case["parse_b"]
    if tag_of(pb) != OK_TAG:
        return ("err", pb), t, None
    len0 = case.get("mut_len0", case["len0"])
    if idx >= len0:
        return ("panic", "panic_idx1"), t, None
    if key >= case["len2"]:
        return ("panic", "panic_key"), t, None
    dec = struct.unpack_from("<I", case["rows"][key], 0x48)[0]
    t.append(("scale", pb[4:20], 1, dec, 0x170))
    sc = case["scale"]
    if tag_of(sc) != OK_TAG:
        if not m("no_wrap"):
            t.append(("drop_err", 0x30, sc))
        wrapped = struct.pack("<H", 0xae) + sc[2:]
        return ("err", sc if m("no_wrap") else wrapped), t, None
    amount = val_of(sc)
    if case["valid"] == 0 and not m("skip_valid"):
        return ("panic", "panic_none"), t, None
    t.append(("drop_slot", 0x30, 0x156))
    t.append(("counter", case["cobj"], case["addr"]))
    cnt = case["counter"]
    limit = LIMIT - 1 if m("limit_minus") else LIMIT
    if cnt >= limit if m("limit_ge") else cnt > limit:
        return ("limit", LIMIT_TEXT), t, None
    scaled = (cnt * (10 if m("mul10") else 100)) & U64
    ledger = (val_of(lk) if not m("swap_owner") else idx, idx if not m("swap_owner") else val_of(lk), amount,
              case["stack1"], case["stack2"], scaled)
    if m("swap_stack"):
        ledger = ledger[:3] + (case["stack2"], case["stack1"]) + ledger[5:]
    if idx >= case["len3"]:
        return ("panic", "panic_slot"), t, None
    stride = 144 if m("stride") else 288
    t.append(("fee", 0x30, L["fee"], b"".join(struct.pack("<Q", v) for v in ledger), 0x80, case["base3"] + idx * stride))
    fe = case["fee"]
    if tag_of(fe) != OK_TAG:
        return ("err", fe), t, None
    charge = ceil_div100(val_of(fe), mut)
    len2 = case.get("mut_len2", case["len2"])
    if key >= len2:
        return ("panic", "panic_row"), t, None
    row = list(struct.unpack("<QQ", case["rows"][key][:16]))
    flag_clear = (case["rows"][key][0] == 0)
    if m("flag_inverted"):
        flag_clear = not flag_clear
    if flag_clear:
        row[0] = 1
        if not m("keep_old_value"):
            row[1] = charge
    row = tuple(row)
    if charge == 0 and not m("zero_pushes"):
        return ("ok",), t, row
    t.append(("vec_new", L["vec"], 0))
    t.append(("vec_push", case["vec_handle"], charge))
    t.append(("debit1", 0xe0, case["vec_handle"], case["addr"], b"\xff" * 20, case["push_handle"], 0,
              L["r10"], L["r11"]))
    if tag_of(case["debit1"]) != OK_TAG:
        return ("panic", "panic_debit1"), t, row
    t.append(("debit2", 0xe0, 0, 0, b"\xff" * 20, 1, charge if not m("debit_fee") else val_of(fe)))
    if tag_of(case["debit2"]) != OK_TAG:
        return ("panic", "panic_debit2"), t, row
    t.append(("alloc", 1, 0x14))
    if (case["mode"] != 1) if m("mode_inverted") else (case["mode"] == 1):
        t.append(("context", 0xe0, case["b9a"], case["c28"], case["c8"], 0))
        ctxbytes = case["context"]
    else:
        ctxbytes = b"\0" * 32
    t.append(("drop_addr", 0x10, case["addr"]))
    dbl = float(-charge if not m("no_neg") else charge) / (1e5 if m("div_1e5") else DIVISOR)
    t.append(("event", L["event"], 1, 1, case["addr"], struct.pack("<Q", case["c60"]), case["c68"], ctxbytes,
              0x8000000000000010, case["addr"][:16], struct.unpack_from("<I", case["addr"], 16)[0],
              struct.pack("<d", dbl)))
    return ("ok",), t, row


def tag_of(r):
    return struct.unpack_from("<H", r, 0)[0]


def val_of(r):
    return struct.unpack_from("<Q", r, 8)[0]


def STR_A_PTR(c):
    return c["str_a"][0]


def STR_A_LEN(c):
    return c["str_a"][1]


def STR_B_PTR(c):
    return c["str_b"][0]


def STR_B_LEN(c):
    return c["str_b"][1]


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------
EDGE64 = [U64 - 14, U64 - 15, U64 - 16, 0, 1, 2, 99, 100, 101, 199, 200, 201, 9999, 10000, 10001, U64, U64 - 1, U64 - 99, U64 - 100, U64 - 101,
          (1 << 63) - 1, 1 << 63, LIMIT - 1, LIMIT, LIMIT + 1, LIMIT + 2, 0x28f5c28f5c28f5c, 0x28f5c28f5c28f5d,
          0x28f5c28f5c28f5c3, 0x8f5c28f5c28f5c29, 1 << 32, (1 << 32) - 1]
CLASSES = ("ok", "ok_zero", "idx0", "parse_a", "lookup", "parse_b", "idx1", "key", "scale", "none", "limit", "slot",
           "fee", "row", "debit1", "debit2", "mode_other", "flag_set", "fee_edge")


def blob(rng, n, tag=None):
    data = bytearray(rng.getrandbits(8) for _ in range(n))
    if tag is not None:
        data[0:2] = struct.pack("<H", tag)
    return bytes(data)


def ok_result(rng, value=None, n=0x70):
    r = bytearray(blob(rng, n, OK_TAG))
    if value is not None:
        r[8:16] = struct.pack("<Q", value)
    return bytes(r)


def err_result(rng, n=0x70):
    tag = rng.getrandbits(16)
    if tag == OK_TAG:
        tag ^= 1
    return blob(rng, n, tag)


def u64edge(rng):
    return rng.choice(EDGE64) if rng.random() < 0.6 else rng.getrandbits(rng.choice((8, 16, 32, 48, 64)))


def make_case(body, i):
    rng = random.Random("spot-%s-%d" % (body, i))
    cls = CLASSES[i % len(CLASSES)]
    len0 = rng.randint(1, 5)
    len2 = rng.randint(1, 5)
    len3 = rng.randint(1, 5)
    idx = rng.randrange(len0)
    keys = [rng.randrange(len2) if rng.random() < 0.9 else rng.getrandbits(64) for _ in range(len0)]
    keys[idx] = rng.randrange(len2)
    rows = []
    for _ in range(len2):
        row = bytearray(blob(rng, ROW))
        row[0:8] = struct.pack("<Q", rng.choice((0, 0, 1, 2, 0x100, rng.getrandbits(64))))
        if row[0] == 0 and any(row[1:8]):
            row[1:8] = b"\0" * 7
        rows.append(bytes(row))
    key = keys[idx]
    fee = rng.choice(EDGE64) if cls != "fee_edge" else rng.choice((0, 1, 99, 100, 101, U64, U64 - 99, U64 - 100))
    if cls == "ok_zero":
        fee = 0
    len3 = rng.randint(idx + 1, idx + 4)
    case = dict(
        cls=cls, len0=len0, len2=len2, len3=len3, idx=idx, keys=keys, rows=rows,
        valid=rng.randint(1, U64), cobj=rng.getrandbits(48), base3=rng.getrandbits(40) << 4,
        mode=1 if rng.random() < 0.6 else rng.choice((0, 2, 3, 0xffffffff)),
        c8=rng.getrandbits(64), c28=rng.getrandbits(64), b9a=rng.getrandbits(8), c60=rng.getrandbits(64),
        c68=rng.getrandbits(32), str_a=(rng.getrandbits(40), rng.getrandbits(8)), str_b=(rng.getrandbits(40), rng.getrandbits(8)),
        addr=blob(rng, 20), stack1=u64edge(rng), stack2=u64edge(rng), counter=rng.choice((0, 1, 2, 12345, LIMIT, LIMIT - 1, rng.randrange(LIMIT))),
        vec_handle=rng.getrandbits(48), push_handle=rng.getrandbits(48), context=blob(rng, 32),
        parse_a=ok_result(rng), lookup=ok_result(rng, u64edge(rng)), parse_b=ok_result(rng),
        scale=ok_result(rng, u64edge(rng)), fee=ok_result(rng, fee), debit1=ok_result(rng), debit2=ok_result(rng),
    )
    if cls == "ok":
        case["fee"] = ok_result(rng, rng.choice((100, 101, 199, 1, U64, 12345, U64 - 15)))
        case["counter"] = rng.randrange(LIMIT)
    if cls == "flag_set":
        rows[key] = struct.pack("<Q", rng.choice((1, 2, 0xff))) + rows[key][8:]
        case["fee"] = ok_result(rng, rng.choice((1, 100, 5000)))
    if cls == "idx0":
        case["idx"] = rng.choice((len0, len0 + 1, U64, 1 << 63))
        case["keys"] = keys
    if cls == "parse_a":
        case["parse_a"] = err_result(rng)
    if cls == "lookup":
        case["lookup"] = err_result(rng)
    if cls == "parse_b":
        case["parse_b"] = err_result(rng)
    if cls == "idx1":
        case["mut_len0"] = rng.randrange(idx + 1)
    if cls == "key":
        keys[idx] = rng.choice((len2, len2 + 1, U64, 1 << 63))
        key = keys[idx]
    if cls == "scale":
        case["scale"] = err_result(rng)
    if cls == "none":
        case["valid"] = 0
    if cls == "limit":
        case["counter"] = rng.choice((LIMIT + 1, LIMIT + 2, U64, 1 << 63, 1 << 62))
    if cls == "slot":
        case["len3"] = rng.randrange(idx + 1)
    if cls == "fee":
        case["fee"] = err_result(rng)
    if cls == "row":
        case["mut_len2"] = rng.randrange(key + 1) if key < len2 else 0
        case["fee"] = ok_result(rng, rng.choice((0, 1, 100, 250)))
    if cls == "debit1":
        case["debit1"] = err_result(rng)
        case["fee"] = ok_result(rng, rng.choice((1, 100, 250, U64)))
    if cls == "debit2":
        case["debit2"] = err_result(rng)
        case["fee"] = ok_result(rng, rng.choice((1, 100, 250, U64)))
    if cls == "mode_other":
        case["mode"] = rng.choice((0, 2, 3, 0xffffffff))
        case["fee"] = ok_result(rng, rng.choice((1, 100, 250, U64)))
    if cls == "ok":
        case["mode"] = 1
    return case


def compare(image, body, case, mut=()):
    got, trace, row, targets = execute(image, body, case)
    want_out, want_trace, want_row = spec(body, case, mut)
    ok_out = got == want_out if want_out[0] != "panic" else (got[0] == "panic" and got[1] == want_out[1])
    ok = ok_out and trace == want_trace and (want_row is None or row == want_row)
    return ok, got, targets


def classify(got):
    if got[0] == "panic":
        return "panic:" + got[1]
    if got[0] == "err":
        return "err"
    return got[0]


# ---------------------------------------------------------------------------
# Callee 2: the quantity lookup that the charge path calls first (two copies)
# ---------------------------------------------------------------------------
LOOKUPS = {"L1": 0x2891af0, "L2": 0x5a00b00}
LOOKUP_SIZE = 436
LOOKUP_SITES = {0x70: "scale", 0xa1: "drop_ok", 0x10e: "drop_err", 0x18b: "panic_tok", 0x1a1: "panic_idx",
                0x1ae: "panic_sub"}
LOOKUP_LOC = {"panic_tok": cpu.RDI, "panic_idx": cpu.RDX, "panic_sub": cpu.RDI}
LOOKUP_RSP = STACK_TOP - 0xe8
PAYLOAD = 0x7280_0000


class LookupRecorder(Recorder):
    def call(self, target, where):
        site = LOOKUP_SITES.get(where - self.start)
        if site is None:
            raise cpu.ToolError("unknown lookup call site %#x" % where)
        self.targets[site] = target
        g = lambda r: self.get(r, 64)  # noqa: E731
        rel = lambda r: g(r) - LOOKUP_RSP  # noqa: E731
        if site in LOOKUP_LOC:
            raise cpu.Done(site, (site, g(LOOKUP_LOC[site])))
        if site == "scale":
            self.trace.append((site, rel(cpu.RDI), self.rd(g(cpu.RSI), 16), self.get(cpu.RDX, 32), self.get(cpu.RCX, 32)))
            self.result(self.case["scale"], g(cpu.RDI))
        else:
            self.trace.append((site, rel(cpu.RDI), self.rd(g(cpu.RDI), 0x70 if site == "drop_err" else 2)))
        self.clobber()


def make_lookup_case(copy_name, i):
    rng = random.Random("lookup-%s-%d" % (copy_name, i))
    cls = ("ok", "zero", "scale_err", "idx", "tok_a", "tok_b", "sub", "ok_equal")[i % 8]
    n_entries, n_tok = rng.randint(1, 5), rng.randint(1, 5)
    entries = [(rng.randrange(n_tok), rng.randrange(n_tok)) for _ in range(n_entries)]
    toks = []
    for _ in range(n_tok):
        t = bytearray(blob(rng, ROW))
        t[0x48], t[0x49] = rng.randint(0, 20), rng.randint(0, 20)
        toks.append(t)
    idx = rng.randrange(n_entries)
    b, a = entries[idx]
    da, db = toks[a][0x49], toks[b][0x48]
    if cls in ("ok", "zero", "scale_err", "ok_equal"):
        if da < db:
            toks[a][0x49] = db + rng.randint(0, 5)
    if cls == "ok_equal":
        toks[a][0x49] = toks[b][0x48]
    if cls == "sub":
        toks[b][0x48] = rng.randint(1, 255)
        toks[a][0x49] = rng.randrange(toks[b][0x48])
    if cls == "idx":
        idx = rng.choice((n_entries, n_entries + 1, U64, 1 << 59))
    if cls == "tok_a":
        entries[idx] = (b, rng.choice((n_tok, n_tok + 5, U64)))
    if cls == "tok_b":
        entries[idx] = (rng.choice((n_tok, n_tok + 5, U64)), a)
    scale = ok_result(rng, rng.choice((1, 2, 100, U64, rng.getrandbits(64)))) if cls != "zero" else ok_result(rng, 0)
    if cls == "scale_err":
        scale = err_result(rng)
    return dict(cls=cls, idx=idx, entries=entries, toks=[bytes(t) for t in toks], scale=scale, payload=blob(rng, 16))


def run_lookup(image, copy_name, case, patched=False):
    m = LookupRecorder(image)
    m.case = case
    m.start = LOOKUPS[copy_name]
    m.trace, m.targets = [], {}
    put(m, CTX + 0x10, len(case["entries"]))
    put(m, CTX + 8, KEYS)
    put(m, CTX + 0x28, len(case["toks"]))
    put(m, CTX + 0x20, ROWS)
    for i, (b, a) in enumerate(case["entries"]):
        put(m, KEYS + 32 * i, b)
        put(m, KEYS + 32 * i + 8, a)
    for i, t in enumerate(case["toks"]):
        m.wr(ROWS + ROW * i, t)
    m.wr(PAYLOAD, case["payload"])
    put(m, STACK_TOP, cpu.RETURN_MARK)
    m.set_reg(cpu.RSP, STACK_TOP)
    m.set_reg(cpu.RDI, OUT)
    m.set_reg(cpu.RSI, CTX)
    m.set_reg(cpu.RDX, case["idx"])
    m.set_reg(cpu.RCX, PAYLOAD)
    m.pc = m.start
    try:
        for _ in range(1000):
            m.step()
        raise cpu.ToolError("step bound")
    except cpu.Done as done:
        end = done
    if end.how == "ret":
        tag = m.load(OUT, 2)
        if tag == OK_TAG:
            outcome = ("ok", m.load(OUT + 8, 8))
        elif tag == 0xad and m.load(OUT + 8, 8) is None:
            outcome = ("zero",)
        else:
            outcome = ("err", m.rd(OUT, 0x70))
    else:
        outcome = ("panic", end.where[0], decode_location(image, end.where[1]))
    return outcome, m.trace, m.targets


def lookup_spec(case, mut=()):
    t = []
    m = lambda n: n in mut  # noqa: E731
    n, ntok = len(case["entries"]), len(case["toks"])
    idx = case["idx"]
    if idx > n if m("idx_gt") else idx >= n:
        return ("panic", "panic_idx"), t
    b, a = case["entries"][idx]
    if a >= ntok or b >= ntok:
        return ("panic", "panic_tok"), t
    da, db = case["toks"][a][0x49], case["toks"][b][0x48]
    if da < db and not m("no_sub_check"):
        return ("panic", "panic_sub"), t
    diff = (da - db) & 0xff
    if m("swap_roles"):
        diff = (case["toks"][b][0x49] - case["toks"][a][0x48]) & 0xff
    t.append(("scale", 0, case["payload"], 2 if not m("mode1") else 1, diff))
    sc = case["scale"]
    if tag_of(sc) != OK_TAG:
        t.append(("drop_err", 0x70, sc))
        return ("err", struct.pack("<H", 0xad) + sc[2:]), t
    value = val_of(sc)
    if value == 0 and not m("accept_zero"):
        return ("zero",), t
    t.append(("drop_ok", 0x70, struct.pack("<H", 0xad)))
    return ("ok", value), t


def lookup_compare(image, copy_name, case, mut=()):
    got, trace, targets = run_lookup(image, copy_name, case)
    want, want_trace = lookup_spec(case, mut)
    if want[0] == "panic":
        same = got[0] == "panic" and got[1] == want[1]
    else:
        same = got == want
    return same and trace == want_trace, got, targets


LOOKUP_MUTANTS = (
    ("idx_gt", "index check uses > instead of >="), ("no_sub_check", "decimal difference never panics"),
    ("swap_roles", "token decimals read from the wrong side"), ("mode1", "scale mode 1 instead of 2"),
    ("accept_zero", "zero quantity accepted"),
)
LOOKUP_PATCHES = (
    ("lk_stride", b"\x48\x69\xc0\x58\x01\x00\x00", 3, 0x59, "token stride 0x158 -> 0x159"),
    ("lk_mode", b"\xba\x02\x00\x00\x00", 1, 3, "scale mode 2 -> 3"),
    ("lk_tag_ok", b"\x66\x81\x3c\x24\xa2\x01", 4, 0xa3, "Ok tag compare 0x1a2 -> 0x1a3"),
    ("lk_zero", b"\x48\x85\xc0\x0f\x84", 4, 0x85, "zero test inverted"),
    ("lk_entry", b"\x48\xc1\xe2\x05", 3, 4, "entry stride 32 -> 16"),
)


def lookup_run(image, count, mut=()):
    for name in LOOKUPS:
        for i in range(count):
            try:
                ok, _, _ = lookup_compare(image, name, make_lookup_case(name, i), mut)
            except (cpu.ToolError, cpu.Done, KeyError, ValueError, TypeError, OverflowError, struct.error, IndexError):
                return name, i
            if not ok:
                return name, i
    return None


def patched_lookup_image(image, patch):
    name, pattern, index, value, _ = patch
    data = bytearray(image.data)
    for start in LOOKUPS.values():
        off = image.file_offset(start)
        at = bytes(data[off:off + LOOKUP_SIZE]).find(pattern)
        if at < 0:
            raise cpu.ToolError("pattern %s not in lookup %#x" % (name, start))
        data[off + at + index] = value
    clone = copy.copy(image)
    clone.data = data
    clone.cache = {}
    return clone


# ---------------------------------------------------------------------------
# Callee 3: leaf helpers of the charge path (rate scaler, row getter, USDC name)
# ---------------------------------------------------------------------------
RATE_ENTRY = 0x44811d0
ROWGET_ENTRY = 0x446b3f0
USDC_ENTRY = 0x421b150
RATE_LIMIT = 0x147ae147ae147ae
RATE_SPLIT = 0x28f5c28f5c28f5c
RATE_LO, RATE_HI = -(2.0 ** 63), 2.0 ** 63
RATE_SAT = struct.unpack("<d", bytes.fromhex("ffffffffffffdf43"))[0]
ROW_STRIDE = 0x510
LEAF_OBJ = 0x7290_0000
LEAF_SITES = {
    RATE_ENTRY: {0xda: "panic_neg"},
    ROWGET_ENTRY: {0x1f: "drop_tag", 0x50: "panic_row"},
    USDC_ENTRY: {0x9: "alloc", 0x3c: "alloc_error"},
}
LEAF_LOC = {"panic_neg": cpu.RDI, "panic_row": cpu.R8}


def f64(bits):
    return struct.unpack("<d", struct.pack("<Q", bits))[0]


def bits64(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class FloatMachine(Machine):
    """Adds the scalar double forms of the rate scaler on top of the charge-path evaluator."""

    pf = False

    def xd(self, operand):
        if operand[0] == "r":
            return struct.unpack("<d", self.xmm[operand[1]][:8])[0]
        return f64(self.load(self.address(operand), 8))

    def two_byte(self, insn, key, bits, rexr, here):
        data = self.image.data
        two = key[1] if len(key) == 2 else None
        reg = ((data[insn.modrm] >> 3) & 7) | rexr if insn.modrm is not None else 0
        if two in (0x59, 0x5d, 0x5f) and insn.rep == 0xf2:
            left, right = struct.unpack("<d", self.xmm[reg][:8])[0], self.xd(self.operand(insn))
            if two == 0x59:
                res = left * right
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
        if two == 0x4b:
            taken = not self.pf
            src, old = self.read(self.operand(insn), bits), self.get(reg, bits)
            self.put(reg, bits, src if taken else old)
            return
        super().two_byte(insn, key, bits, rexr, here)


class LeafRecorder(FloatMachine, Recorder):
    def call(self, target, where):
        site = LEAF_SITES[self.entry].get(where - self.entry)
        if site is None:
            raise cpu.ToolError("unknown leaf call site %#x" % where)
        if site in LEAF_LOC or site == "alloc_error":
            raise cpu.Done(site, (site, self.get(LEAF_LOC.get(site, cpu.RDI), 64)))
        if site == "alloc":
            self.trace.append((site, self.get(cpu.RDI, 64)))
            self.clobber(self.case["block"])
        else:
            self.trace.append((site, self.get(cpu.RDI, 64) - self.body_rsp, self.load(self.get(cpu.RDI, 64), 2)))
            self.clobber()



def run_leaf(image, entry, case, rsp_depth):
    m = LeafRecorder(image)
    m.entry, m.case, m.trace = entry, case, []
    m.body_rsp = STACK_TOP - rsp_depth
    put(m, STACK_TOP, cpu.RETURN_MARK)
    m.set_reg(cpu.RSP, STACK_TOP)
    return m


def finish(m):
    try:
        for _ in range(500):
            m.step()
        raise cpu.ToolError("step bound")
    except cpu.Done as done:
        if done.how != "ret" and isinstance(done.where, tuple):
            LEAF_LOCS[done.how] = done.where[1]
        return done


LEAF_LOCS = {}


def rate_spec(x, mult, mut=()):
    """Scale a charge by the f64 multiplier with the same saturation steps as the body."""
    if x > (RATE_SPLIT + 1 if "split_off" in mut else RATE_SPLIT):
        return x
    signed = x - (1 << 64) if x >> 63 else x
    v = float(signed) * mult
    if bits64(v) & 0x7fff_ffff_ffff_ffff > 0x7fef_ffff_ffff_ffff:
        f = 0.0
    elif RATE_LO > v or v > RATE_HI:
        f = min(RATE_HI, max(RATE_LO, v))
    else:
        f = v
    if f != f:
        i = 0
    elif f > RATE_SAT:
        i = (1 << 63) - 1
    else:
        i = int(f)
    if i < 0 and i == -(1 << 63):
        return "panic_neg"
    limit = RATE_LIMIT - 1 if "limit_minus" in mut else RATE_LIMIT
    if abs(i) > limit:
        i = min(max(i, -limit), limit)
    return max(i, 0) if "no_floor" not in mut else i & U64


def make_rate_case(i):
    rng = random.Random("rate-%d" % i)
    x = rng.choice((RATE_SPLIT, RATE_SPLIT + 1, RATE_SPLIT - 1, 1 << 63, (1 << 63) - 1, U64, U64 - 1, 1 << 62, 5, 0,
                    rng.getrandbits(64), rng.getrandbits(40), rng.getrandbits(63)))
    mult = rng.choice((0.0, -0.0, 1.0, 0.01, 100.0, -1.0, -4.0, 2.0 ** 63, -(2.0 ** 63), 1e19, -1e19, 1e-300, 1e300,
                       float("inf"), float("-inf"), float("nan"), 0.5, 3.5, 1e-3, 1e5, 2.0 ** 64))
    if rng.random() < 0.4:
        mult = f64(rng.getrandbits(64))
    return x, mult


def rate_run(image, x, mult):
    m = run_leaf(image, RATE_ENTRY, {}, 8)
    put(m, LEAF_OBJ + 0x4e0, bits64(mult))
    m.set_reg(cpu.RDI, LEAF_OBJ)
    m.set_reg(cpu.RSI, x)
    m.pc = RATE_ENTRY
    done = finish(m)
    if done.how == "ret":
        return m.get(cpu.RAX, 64)
    return done.how


def rowget_spec(length, base, idx, mut=()):
    if idx > length if "idx_gt" in mut else idx >= length:
        return "panic_row"
    return (base + idx * (0x511 if "stride" in mut else ROW_STRIDE)) & U64


def make_rowget_case(i):
    rng = random.Random("rowget-%d" % i)
    length = rng.randint(0, 6)
    return length, rng.getrandbits(48), rng.choice((0, 1, length - 1, length, length + 1, U64, rng.getrandbits(64), 3)) & U64


def rowget_run(image, length, base, idx):
    m = run_leaf(image, ROWGET_ENTRY, {}, 0x78)
    put(m, LEAF_OBJ + 0x10, length)
    put(m, LEAF_OBJ + 8, base)
    m.set_reg(cpu.RDI, LEAF_OBJ)
    m.set_reg(cpu.RSI, idx)
    m.pc = ROWGET_ENTRY
    done = finish(m)
    if done.how != "ret":
        return done.how
    if m.trace != [("drop_tag", 0, 0x156)]:
        raise cpu.ToolError("row getter drop trace changed")
    return m.get(cpu.RAX, 64)


def usdc_run(image, block):
    m = run_leaf(image, USDC_ENTRY, {"block": block}, 0x10)
    m.set_reg(cpu.RDI, OUT)
    m.pc = USDC_ENTRY
    done = finish(m)
    if done.how != "ret":
        return done.how
    return (m.trace, m.load(OUT, 8), m.load(OUT + 8, 8), m.load(OUT + 0x10, 8), m.rd(block, 4))


def usdc_spec(block):
    if block == 0:
        return "alloc_error"
    return ([("alloc", 4)], 4, block, 4, b"USDC")


LEAF_CASES = 4000
RATE_MUTANTS = (("split_off", "early-out limit one too high"), ("limit_minus", "saturation limit one lower"),
                ("no_floor", "negative results not floored"))
LEAF_PATCHES = (
    ("rate_split", RATE_ENTRY, 224, b"\x48\xb8\x5c\x8f\xc2\xf5\x28\x5c\x8f\x02", 2, 0x5d, "early-out constant +1"),
    ("rate_limit", RATE_ENTRY, 224, b"\x48\xba\xae\x47\xe1\x7a\x14\xae\x47\x01", 2, 0xaf, "saturation constant +1"),
    ("rate_mul", RATE_ENTRY, 224, b"\xf2\x0f\x59\x87\xe0\x04\x00\x00", 4, 0xe8, "multiplier field +8"),
    ("rate_cmov", RATE_ENTRY, 224, b"\x48\x0f\x4f\xc1", 2, 0x4c, "cmovg -> cmovl"),
    ("row_stride", ROWGET_ENTRY, 113, b"\x48\x69\xde\x10\x05\x00\x00", 4, 0x06, "row stride 0x510 -> 0x610"),
    ("row_bound", ROWGET_ENTRY, 113, b"\x48\x3b\x77\x10\x73", 4, 0x72, "bounds branch inverted"),
    ("usdc_text", USDC_ENTRY, 66, b"\xc7\x00\x55\x53\x44\x43", 2, 0x54, "name byte U -> T"),
    ("usdc_len", USDC_ENTRY, 66, b"\x48\xc7\x43\x10\x04\x00\x00\x00", 4, 5, "length 4 -> 5"),
)


def leaf_patched(image, patch):
    name, entry, size, pattern, index, value, _ = patch
    data = bytearray(image.data)
    off = image.file_offset(entry)
    at = bytes(data[off:off + size]).find(pattern)
    if at < 0:
        raise cpu.ToolError("pattern %s not in %#x" % (name, entry))
    data[off + at + index] = value
    clone = copy.copy(image)
    clone.data = data
    clone.cache = {}
    return clone


def leaf_sweep(image, count, mut=()):
    """Return the first failing leaf case or None."""
    for i in range(count):
        x, mult = make_rate_case(i)
        try:
            if rate_run(image, x, mult) != rate_spec(x, mult, mut):
                return "rate", i
        except (cpu.ToolError, cpu.Done, KeyError, ValueError, TypeError, struct.error, OverflowError):
            return "rate", i
        length, base, idx = make_rowget_case(i)
        try:
            if rowget_run(image, length, base, idx) != rowget_spec(length, base, idx, mut):
                return "rowget", i
        except (cpu.ToolError, cpu.Done, KeyError, ValueError, TypeError, struct.error, OverflowError):
            return "rowget", i
        block = random.Random("usdc-%d" % i).choice((0, 0x7300_0000 + 16 * (i % 50)))
        try:
            if usdc_run(image, block) != usdc_spec(block):
                return "usdc", i
        except (cpu.ToolError, cpu.Done, KeyError, ValueError, TypeError, struct.error, OverflowError):
            return "usdc", i
    return None


# ---------------------------------------------------------------------------
# Verification driver, negative controls and evidence files
# ---------------------------------------------------------------------------
CASES_PER_BODY = 6000
CONTROL_CASES = 900

SPEC_MUTANTS = (
    ("limit_minus", "refusal limit one lower"), ("limit_ge", "refuse at the limit instead of above it"),
    ("mul10", "counter scaled by 10 instead of 100"), ("floor", "charge rounds down"),
    ("always_up", "charge rounds up even when exact"), ("zero_pushes", "zero charge still debits"),
    ("flag_inverted", "ledger flag test inverted"), ("keep_old_value", "ledger value not stored"),
    ("idx_gt", "first index check uses > instead of >="), ("no_wrap", "scale error passed through unwrapped"),
    ("skip_valid", "missing counter handle not refused"), ("swap_owner", "owner and index swapped in ledger"),
    ("swap_stack", "stack arguments swapped"), ("stride", "fee slot stride 144"),
    ("debit_fee", "debit the raw fee"), ("mode_inverted", "context lookup mode inverted"),
    ("no_neg", "event amount not negated"), ("div_1e5", "event divisor 1e5"),
)
# name, pattern, index, replacement byte (None flips bit 4), meaning
BYTE_PATCHES = (
    ("imul100", b"\x48\x6b\xc0\x64", 3, 0x65, "counter multiplier 100 -> 101"),
    ("limit", b"\x48\xb9" + LIMIT.to_bytes(8, "little"), 2, 0xca, "limit low byte lowered"),
    ("limit_hi", b"\x48\xb9" + LIMIT.to_bytes(8, "little"), 6, 0xd9, "limit raised in byte 4"),
    ("ja", b"\x48\x39\xc8\x0f\x87", 4, 0x83, "ja -> jae at the limit test"),
    ("seta", b"\x0f\x97\xc0", 1, 0x93, "seta -> setae in the remainder test"),
    ("ror", b"\x48\xc1\xc8\x02", 3, 3, "ror 2 -> 3"),
    ("jezero", b"\x4d\x85\xe4\x0f\x84", 4, 0x85, "zero charge branch inverted"),
    ("jneflag", b"\x80\x3c\x08\x00\x75", 4, 0x74, "ledger flag branch inverted"),
    ("tag_limit", b"\x66\xc7\x03\xee\x00", 3, 0xef, "refusal tag 0xee -> 0xef"),
    ("tag_scale", b"\x66\xc7\x03\xae\x00", 3, 0xaf, "scale wrap tag 0xae -> 0xaf"),
    ("bounds0", b"\x48\x39\xf1\x0f\x83", 4, 0x82, "first bounds check inverted"),
    ("scale_arg", b"\xba\x01\x00\x00\x00", 1, 2, "scale edx 1 -> 2"),
    ("neg", b"\x49\xf7\xdc", 2, 0xd4, "neg -> not"),
    ("add_sub", b"\x49\x01\xd4", 1, 0x29, "add r12,rdx -> sub"),
    ("shr_a", b"\x48\xc1\xe8\x02", 3, 3, "shr 2 -> 3 before the multiply"),
    ("shr_b", b"\x48\xc1\xea\x02", 3, 3, "shr 2 -> 3 after the multiply"),
    ("alloc", b"\xbe\x14\x00\x00\x00", 1, 0x13, "address copy size 20 -> 19"),
    ("mode", b"\x41\x83\x3e\x01", 3, 2, "mode compare 1 -> 2"),
    ("valid", b"\x49\x83\xbe", 3, None, "counter handle offset shifted"),
    ("lea90", b"\x49\x8d\xb6\x90\x00\x00\x00", 3, 0x98, "user table offset 0x90 -> 0x98"),
    ("row_stride", b"\x48\x69\xcd\x58\x01\x00\x00", 3, 0x59, "row stride 0x158 -> 0x159"),
    ("row_flag", b"\x48\xc7\x00\x01\x00\x00\x00", 3, 2, "ledger flag value 1 -> 2"),
    ("row_val", b"\x4c\x89\x60\x08", 3, 0x10, "ledger value slot +8 -> +0x10"),
    ("fee_stride", b"\x49\xc1\xe0\x05", 3, 4, "fee slot shift 5 -> 4"),
    ("ok_tag", b"\x3d\xa2\x01\x00\x00", 1, 0xa3, "first Ok tag 0x1a2 -> 0x1a3"),
    ("debit2_arg", b"\x41\xb8\x01\x00\x00\x00", 2, 2, "second debit r8d 1 -> 2"),
    ("divisor", b"\xf2\x0f\x5e\x05", 4, None, "divisor constant moved"),
)


def check_digest(data):
    return hashlib.sha256(data).hexdigest() == SHA


def body_extent(image, start):
    lo, hi = image.fde_of(start)
    if lo != start:
        raise cpu.ToolError("%#x is not an FDE start" % start)
    return hi - lo


def patched_image(image, patch):
    name, pattern, index, value, _ = patch
    data = bytearray(image.data)
    for body, (start, size, _) in BODIES.items():
        off = image.file_offset(start)
        at = bytes(data[off:off + size]).find(pattern)
        if at < 0:
            raise cpu.ToolError("pattern %s not in %s" % (name, body))
        data[off + at + index] = value if value is not None else data[off + at + index] ^ 0x10
    clone = copy.copy(image)
    clone.data = data
    clone.cache = {}
    return clone


def run_bodies(image, count, mut=(), bodies="ABC"):
    """Return the first (body, i) where the machine and the specification disagree, else None."""
    for body in bodies:
        for i in range(count):
            try:
                ok, _, _ = compare(image, body, make_case(body, i), mut)
            except (cpu.ToolError, cpu.Done, KeyError, ValueError, TypeError, OverflowError, struct.error, IndexError):
                return body, i
            if not ok:
                return body, i
    return None


def misc_controls(image):
    """Out-of-range inputs and damaged bytes; each entry is (name, meaning, detected)."""
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
    out.append(("fde_start", "an address inside a body is refused as a start",
                raises(lambda: body_extent(image, 0x2c57094), cpu.ToolError)))
    m = Recorder(image)
    m.setup("A", {})
    out.append(("unknown_site", "a call outside the site table is refused",
                raises(lambda: m.call(0, 0x2c57091), cpu.ToolError)))
    out.append(("unwritten_read", "a stub read of unwritten memory is refused",
                raises(lambda: m.rd(0x1234, 4), cpu.ToolError)))
    out.append(("bad_location", "a non-Location address is refused",
                raises(lambda: decode_location(image, 0x400100), cpu.ToolError)))
    out.append(("ror_zero", "rotate by zero is outside the modelled domain",
                raises(lambda: m.shift(1, 5, 0, 64), cpu.ToolError)))
    out.append(("wide_value", "a 65-bit value cannot enter a 64-bit slot",
                raises(lambda: put(m, 0x10, 1 << 64), OverflowError)))
    return out


def write_lines(path, lines):
    with open(path, "w", newline="\n") as f:
        for line in lines:
            f.write(line + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if not check_digest(data):
        raise SystemExit("node #115 digest mismatch")
    image = cpu.Image(data)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    counts, targets, locations, total, mismatches = {}, {}, {}, 0, 0
    for body, (start, size, _) in BODIES.items():
        if body_extent(image, start) != size:
            raise SystemExit("body %s extent changed" % body)
        for i in range(CASES_PER_BODY):
            ok, got, tg = compare(image, body, make_case(body, i))
            total += 1
            mismatches += not ok
            key = (body, classify(got))
            counts[key] = counts.get(key, 0) + 1
            targets.setdefault(body, {}).update(tg)
            if got[0] == "panic":
                prev = locations.setdefault((body, got[1]), got[2])
                if prev != got[2]:
                    raise SystemExit("panic site %s moved" % got[1])
    lookup_targets = {}
    for name in LOOKUPS:
        for i in range(CASES_PER_BODY):
            ok, got, tg = lookup_compare(image, name, make_lookup_case(name, i))
            total += 1
            mismatches += not ok
            key = (name, classify(got))
            counts[key] = counts.get(key, 0) + 1
            lookup_targets.setdefault(name, {}).update(tg)
            if got[0] == "panic":
                prev = locations.setdefault((name, got[1]), got[2])
                if prev != got[2]:
                    raise SystemExit("panic site %s moved" % got[1])
    for i in range(LEAF_CASES):
        x, mult = make_rate_case(i)
        got = rate_run(image, x, mult)
        kind = got if isinstance(got, str) else "early" if x > RATE_SPLIT else "zero" if got == 0 else "scaled"
        counts[("rate", kind)] = counts.get(("rate", kind), 0) + 1
        mismatches += got != rate_spec(x, mult)
        length, base, idx = make_rowget_case(i)
        got = rowget_run(image, length, base, idx)
        counts[("rowget", got if isinstance(got, str) else "row")] = counts.get(("rowget", got if isinstance(got, str) else "row"), 0) + 1
        mismatches += got != rowget_spec(length, base, idx)
        block = random.Random("usdc-%d" % i).choice((0, 0x7300_0000 + 16 * (i % 50)))
        got = usdc_run(image, block)
        counts[("usdc", got if isinstance(got, str) else "name")] = counts.get(("usdc", got if isinstance(got, str) else "name"), 0) + 1
        mismatches += got != usdc_spec(block)
        total += 3
    for site, va in sorted(LEAF_LOCS.items()):
        if site.startswith("panic"):
            locations[("leaf", site)] = decode_location(image, va)
    if mismatches:
        raise SystemExit("%d mismatches" % mismatches)
    controls = []
    for name, meaning in SPEC_MUTANTS:
        controls.append(("spec:" + name, meaning, run_bodies(image, CONTROL_CASES, (name,))))
    for patch in BYTE_PATCHES:
        controls.append(("byte:" + patch[0], patch[4], run_bodies(patched_image(image, patch), CONTROL_CASES)))
    for name, meaning in LOOKUP_MUTANTS:
        controls.append(("lookup-spec:" + name, meaning, lookup_run(image, CONTROL_CASES, (name,))))
    for patch in LOOKUP_PATCHES:
        controls.append(("lookup-byte:" + patch[0], patch[4], lookup_run(patched_lookup_image(image, patch), CONTROL_CASES)))
    for name, meaning in RATE_MUTANTS + (("idx_gt", "row getter bound uses >"), ("stride", "row getter stride 0x511")):
        controls.append(("leaf-spec:" + name, meaning, leaf_sweep(image, LEAF_CASES // 4, (name,))))
    for patch in LEAF_PATCHES:
        controls.append(("leaf-byte:" + patch[0], patch[6], leaf_sweep(leaf_patched(image, patch), LEAF_CASES // 4)))
    for name, meaning, detected in misc_controls(image):
        controls.append(("misc:" + name, meaning, ("-", 0) if detected else None))
    detected = sum(1 for c in controls if c[2] is not None)

    write_lines(out / "callees.tsv", ["body\tsite_offset\tsite\ttarget"] + [
        "%s\t%#x\t%s\t%#x" % (body, off, name, targets[body][name])
        for body in BODIES for off, name in sorted(SITE_MAP[body].items()) if name in targets[body]] + [
        "%s\t%#x\t%s\t%#x" % (copy_name, off, name, lookup_targets[copy_name][name])
        for copy_name in LOOKUPS for off, name in sorted(LOOKUP_SITES.items()) if name in lookup_targets[copy_name]])
    write_lines(out / "locations.tsv", ["body\tsite\tfile\tline\tcolumn"] + [
        "%s\t%s\t%s\t%d\t%d" % (b, s, *locations[(b, s)]) for (b, s) in sorted(locations)])
    write_lines(out / "outcomes.tsv", ["body\toutcome\tcases"] + [
        "%s\t%s\t%d" % (b, o, n) for (b, o), n in sorted(counts.items())])
    write_lines(out / "controls.tsv", ["control\tmeaning\tfirst_mismatch"] + [
        "%s\t%s\t%s" % (n, m_, "undetected" if h is None else "%s:%d" % h) for n, m_, h in controls])
    write_lines(out / "measure.json", [json.dumps({"cases": total, "negative_controls": len(controls),
                                                    "negative_detected": detected, "mismatches": mismatches},
                                                   indent=1, sort_keys=True)])
    if detected != len(controls):
        raise SystemExit("undetected controls: " + ", ".join(c[0] for c in controls if c[2] is None))


if __name__ == "__main__":
    main()
