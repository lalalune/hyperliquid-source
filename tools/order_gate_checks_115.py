#!/usr/bin/env python3
"""Reconstruct three node #115 order-gate checks from ELF bytes.

The merged order value gate packet (RE-004-order-value-gate-115) calls a scale resolver, a
market-state check and a ring search and only names them. This tool runs the real bytes of

  0x29aea00   resolve: asset index -> record -> decimals kind; value / 10^(8-kind) or refusal 0x6a
  0x22e7f80   market check: eight ordered refusals, a keyed set lookup (ring or B-tree), four host checks
  0x24cd450   ring (VecDeque) binary search over 0xd0-byte rows with 20-byte keys

on the shared concrete evaluator `decimal_scaled_u64` (bytes are read, never executed natively)
and compares every run with pure-Python rules. Host calls (the four slot checks, the map lookup,
memcmp and the two panic helpers) are recorded stubs; their arguments are checked in every run.

Usage: python3 tools/order_gate_checks_115.py --out <folder>
"""
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import decimal_scaled_u64 as cpu  # noqa: E402

SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
U64 = cpu.U64
RAX, RCX, RDX, RSI, RDI = cpu.RAX, cpu.RCX, cpu.RDX, cpu.RSI, cpu.RDI
R8, R9 = cpu.R8, cpu.R9
STEP_LIMIT = 6000
MIN64 = 1 << 63

SLOT_MEMCMP = 0x64dfb50      # imported compare, no local addend
SLOT_PANIC = 0x64df620       # bounds-check panic helper
SLOT_PANIC2 = 0x64df830      # second panic helper (unwrap-style, one argument)
SLOT_CHECK_A, SLOT_CHECK_B, SLOT_CHECK_C, SLOT_CHECK_D = 0x64e4ec0, 0x64e4ec8, 0x64e4ed0, 0x64e4ed8
TARGET_MAP_GET = 0x2db0710
SLOT_PANIC3 = 0x64df848      # subtraction-overflow panic helper
SLOT_PARSE, SLOT_SCALE = 0x64e4e60, 0x64e6468
TARGET_DROP = 0x277e390
MEMCMP_MARK = 0x7e000001

CTX, STATE, OUT, KEYP, TBL, NODES, RING, VALS, REC1, REC2 = (
    0x7300_0000, 0x7310_0000, 0x7320_0000, 0x7330_0000, 0x7340_0000, 0x7350_0000, 0x7360_0000, 0x7370_0000,
    0x7380_0000, 0x7390_0000)
ELEM_D0 = 0xd0

BODIES = (("resolve", 0x29aea00), ("market_check", 0x22e7f80), ("margin_check", 0x292a0c0), ("ring_search_d0", 0x24cd450))
CASES = {"resolve": 4200, "market_check": 5200, "margin_check": 5200, "ring_search_d0": 2600}
BATTERY = 130          # cases per mutant run
STATUS = {0x62: "zero-amount", 0x75: "check-a", 0x103: "flag", 0x1d: "key-in-set", 0x195: "check-b-1",
          0x193: "check-b-other", 0x192: "check-c", 0x6a: "no-entry", 0x6b: "limit", 0x1a2: "ok",
          0xdb: "no-bound", 0xda: "ref-order", 0xd9: "pair-order", 0xad: "scale", 0x158: "text-too-long"}


class ToolError(Exception):
    pass


def fail(message):
    raise ToolError(message)


class Lcg:
    def __init__(self, seed):
        self.s = seed & U64

    def next(self):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & U64
        return self.s >> 24

    def below(self, n):
        return self.next() % n

    def pick(self, items):
        return items[self.below(len(items))]

    def word(self):
        mode = self.below(6)
        if mode == 0:
            return self.next() | (self.next() << 40) & U64
        if mode == 1:
            return U64 - self.below(3)
        if mode == 2:
            return self.below(1000)
        if mode == 3:
            return (U64 >> 1) + self.below(3)
        if mode == 4:
            return (1 << 32) + self.below(5) - 2
        return self.next() << 20 & U64


class Box:
    def __init__(self, **kw):
        self.__dict__.update(kw)


# ---------------------------------------------------------------- machine

class Machine(cpu.Machine):
    """Concrete evaluator plus cdqe, call-through-register and the SSE forms these bodies use."""

    def __init__(self, image, hooks):
        super().__init__(image)
        self.hooks, self.log, self.reads = hooks, [], collections.Counter()

    def load(self, at, size):
        self.reads[(at, size)] += 1
        return super().load(at, size)

    def reload(self, reg, at, size):
        self.reads[(at, size)] += 1
        return super().reload(reg, at, size)

    def call(self, target, where):
        hook = self.hooks.get(target)
        if hook is None:
            return super().call(target, where)
        result = hook(self)
        rdx = None
        if isinstance(result, tuple):
            result, rdx = result
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        self.flags = [None, None, None, None]
        if result is not None:
            self.set_reg(RAX, result & U64)
        if rdx is not None:
            self.set_reg(RDX, rdx & U64)
        return None

    def step(self):
        insn = self.image.fetch(self.pc)
        key, data, here = insn.key, self.image.data, self.pc
        if key == 0x98 and insn.rex & 8:                      # cdqe / cltq
            self.seen.add(here)
            self.pc = here + insn.size
            low = self.get(RAX, 32)
            if low is None:
                fail(f"cltq of an unknown value at {here:#x}")
            self.set_reg(RAX, low | (U64 ^ 0xffffffff) if low >> 31 else low)
            return
        if key == 0xff and data[insn.modrm] >> 6 == 3 and (data[insn.modrm] >> 3) & 7 == 2:
            self.seen.add(here)
            self.pc = here + insn.size
            target = self.get((data[insn.modrm] & 7) | ((insn.rex & 1) << 3), 64)
            if target is None:
                fail(f"call through an unknown register at {here:#x}")
            self.call(target, here)
            return
        super().step()


def new_machine(image, hooks):
    image.slots[SLOT_MEMCMP] = MEMCMP_MARK   # imported symbol, no local addend: modelled as a host call
    m = Machine(image, hooks)
    m.hooks[MEMCMP_MARK] = memcmp_hook
    m.set_reg(cpu.RSP, cpu.STACK)
    m.store(cpu.STACK, 8, cpu.RETURN_MARK)
    return m


def run(m, start):
    m.pc = start
    for _ in range(STEP_LIMIT):
        try:
            m.step()
        except cpu.Done as done:
            return done.how
    fail(f"no stop from {start:#x}")


def put(m, at, blob):
    for i, b in enumerate(blob):
        m.mem[at + i] = b


def put_word(m, at, value, size=8):
    put(m, at, (value & ((1 << 8 * size) - 1)).to_bytes(size, "little"))


def memcmp_hook(m):
    a, b, n = (m.get(r, 64) for r in (RDI, RSI, RDX))
    m.log.append(("cmp", n))
    for i in range(n):
        x, y = m.mem[a + i], m.mem[b + i]
        if x != y:
            return (x - y) & U64
    return 0


def panic_hook(tag):
    def hook(m):
        m.log.append(("panic", tag) + tuple(m.get(r, 64) for r in (RDI, RSI)))
        raise cpu.Done("panic", m.pc)
    return hook


# ---------------------------------------------------------------- byte facts

def body_extent(image, start):
    lo, hi = image.fde_of(start)
    if lo != start:
        fail(f"{start:#x} is not an FDE start")
    return lo, hi


def sweep(image, start, end):
    out, va = [], start
    while va < end:
        insn = image.fetch(va)
        out.append(insn)
        va += insn.size
    if va != end:
        fail(f"linear sweep of {start:#x} overran {end:#x}")
    return out


def lea_targets(image, insns):
    """(dest register, target VA) of every rip-relative lea, from the instruction bytes."""
    out = []
    data = image.data
    for insn in insns:
        if insn.key == 0x8d and data[insn.modrm] >> 6 == 0 and data[insn.modrm] & 7 == 5:
            disp = struct.unpack_from("<i", data, insn.off + insn.size - 4)[0]
            out.append((((data[insn.modrm] >> 3) & 7) | ((insn.rex & 4) << 1), insn.va + insn.size + disp))
    return out


def movw_status_constants(image, body):
    """Every 16-bit immediate stored or loaded as a status word, read from the instruction bytes."""
    lo, hi = body_extent(image, START[body])
    data, out = image.data, []
    for insn in sweep(image, lo, hi):
        if insn.wide16 and insn.key in (0xc7, 0xb9, 0xba) and insn.size >= 4:
            out.append((insn.va, struct.unpack_from("<H", data, insn.off + insn.size - 2)[0]))
    return out


# ---------------------------------------------------------------- resolve

def gen_resolve(rng):
    n1 = rng.pick((1, 1, 2, 4))
    n2 = rng.pick((1, 2, 3, 6))
    kinds = [rng.pick((0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 10, 0x40, 0xff)) for _ in range(n2)]
    index = [rng.below(n2 + (2 if rng.below(9) == 0 else 0)) for _ in range(n1)]
    idx = rng.below(n1 + (1 if rng.below(10) == 0 else 0))
    kind = kinds[index[idx]] if idx < n1 and index[idx] < n2 else 0
    mult = 10 ** (8 - kind) if kind <= 8 else 1
    mode = rng.pick(("exact", "exact", "exact", "off1", "random", "edge"))
    q = rng.pick((0, 1, 2, 7, 99, 12345, (1 << 32) // mult, (1 << 32) // mult + 1, (U64 // mult) - rng.below(3), rng.below(U64 // mult + 1)))
    q = min(q, U64 // mult)
    value = q * mult
    if mode == "off1":
        value = (value + 1) & U64
    elif mode == "random":
        value = rng.word()
    elif mode == "edge":
        value = rng.pick((0, 1, mult - 1, mult, mult + 1, U64, (1 << 32) - 1, 1 << 32, (1 << 32) + mult))
    return Box(index=index, kinds=kinds, idx=idx, value=value)


def resolve_expected(c, flaw=None):
    if c.idx >= len(c.index):
        return "panic", "bounds", ("panic", 1, c.idx, len(c.index))
    rec = c.index[c.idx]
    if rec >= len(c.kinds):
        return "panic", "record", ("panic", 2)
    kind = c.kinds[rec]
    limit = 9 if flaw == "kind9" else 8
    if kind > limit:
        return "ret", 0x6a, None
    mult = 10 ** (kind if flaw == "unscaled" else 8 - kind)
    if c.value % mult and flaw != "floor":
        return "ret", 0x6a, None
    return "ret", 0x1a2, c.value // mult


def resolve_actual(image, c):
    hooks = {image.slots[SLOT_PANIC]: panic_hook(1), image.slots[SLOT_PANIC2]: panic_hook(2)}
    m = new_machine(image, hooks)
    put_word(m, TBL + 0x10, len(c.index))
    put_word(m, TBL + 8, REC1)
    put_word(m, TBL + 0x28, len(c.kinds))
    put_word(m, TBL + 0x20, REC2)
    for i, rec in enumerate(c.index):
        put_word(m, REC1 + 0x20 * i, rec)
    for i, kind in enumerate(c.kinds):
        m.mem[REC2 + 0x158 * i + 0x48] = kind
    put_word(m, OUT, 0xffff, 2)
    for r, v in ((RDI, OUT), (RSI, c.value), (RDX, c.idx), (RCX, TBL)):
        m.set_reg(r, v)
    how = run(m, START["resolve"])
    if how == "panic":
        return "panic", ("bounds" if m.log[0][1] == 1 else "record"), m.log[0], m
    status = m.load(OUT, 2)
    return "ret", status, (m.load(OUT + 8, 8) if status == 0x1a2 else None), m


def resolve_eval(image, c, flaw=None):
    exp = resolve_expected(c, flaw)
    how, a, b, m = resolve_actual(image, c)
    if exp[0] == "panic":
        ok = how == "panic" and a == exp[1] and b[:len(exp[2])] == exp[2]
    else:
        ok = (how, a, b) == exp
    kind = "panic-" + a if how == "panic" else STATUS.get(a, hex(a))
    return ok, f"{kind} kind={'big' if (c.kinds[c.index[c.idx]] if c.idx < len(c.index) and c.index[c.idx] < len(c.kinds) else 0) > 8 else 'ok'}", "-", m


# ---------------------------------------------------------------- trees and rings

LEAF_CAP = 11


def gen_keys(rng, n):
    prefix = bytes(rng.below(256) for _ in range(rng.pick((0, 4, 16, 19))))
    seen, keys = set(), []
    while len(keys) < n:
        k = (prefix + bytes(rng.below(256) for _ in range(20)))[:20]
        if k not in seen:
            seen.add(k)
            keys.append(k)
    return keys


def build_tree(rng, pairs, height):
    if height == 0:
        return ("leaf", pairs)
    cap, low = [LEAF_CAP], [1]
    for _ in range(height):
        cap.append(12 * cap[-1] + LEAF_CAP)
        low.append(1 + 2 * low[-1])
    k = 1 + rng.below(3)
    while k > 1 and k + (k + 1) * low[height - 1] > len(pairs):
        k -= 1
    sizes = [low[height - 1]] * (k + 1)
    for _ in range(len(pairs) - k - sum(sizes)):
        j = rng.below(k + 1)
        if sizes[j] < cap[height - 1]:
            sizes[j] += 1
    seps, kids, at = [], [], 0
    for j, size in enumerate(sizes):
        kids.append(build_tree(rng, pairs[at:at + size], height - 1))
        at += size
        if j < k:
            seps.append(pairs[at])
            at += 1
    return ("node", seps, kids)


class Alloc:
    def __init__(self):
        self.next = NODES

    def take(self):
        at, self.next = self.next, self.next + 0x1000
        return at


ALLOC = Alloc()


def write_tree(m, plan):
    """Node layout read from the bytes of 0x22e7f80: keys at +0x7f0 (20 bytes each), count u16 at +0x8ce, children at +0x8d0."""
    at = ALLOC.take()
    if plan[0] == "leaf":
        entries, kids = plan[1], []
    else:
        entries, kids = plan[1], [write_tree(m, child) for child in plan[2]]
    for i, key in enumerate(entries):
        put(m, at + 0x7f0 + 0x14 * i, key)
    put_word(m, at + 0x8ce, len(entries), 2)
    for i, kid in enumerate(kids):
        put_word(m, at + 0x8d0 + 8 * i, kid)
    return at


def tree_keys_of(plan):
    if plan[0] == "leaf":
        return list(plan[1])
    out = []
    for i, kid in enumerate(plan[2]):
        out += tree_keys_of(kid)
        if i < len(plan[1]):
            out.append(plan[1][i])
    return out


def make_set(rng, force=None):
    """A key set kept either as a ring (cap, ptr, head, len) or as a B-tree behind the niche word."""
    kind = rng.pick(("empty", "ring", "ring", "ring", "tree", "tree", "tree2", "treeroot"))
    if kind == "empty":
        return Box(kind="ring", keys=[], cap=rng.below(3), head=0)
    if kind == "ring":
        n = rng.pick((1, 2, 3, 5, 8, 13))
        cap = n + rng.below(4)
        return Box(kind="ring", keys=sorted(gen_keys(rng, n)), cap=cap, head=rng.below(cap))
    if kind == "treeroot":
        return Box(kind="tree", keys=[], plan=None, height=0)
    height = 0 if kind == "tree" else rng.pick((1, 2))
    n = rng.pick((1, 3, 6, 11)) if height == 0 else rng.pick((9, 14, 20, 40)) if height == 1 else rng.pick((20, 40, 60))
    keys = sorted(gen_keys(rng, n))
    plan = build_tree(rng, keys, height)
    return Box(kind="tree", keys=tree_keys_of(plan), plan=plan, height=height)


def place_set(m, box, at, stride, key_at=0):
    if box.kind == "ring":
        n = len(box.keys)
        put_word(m, at, box.cap)
        put_word(m, at + 8, RING)
        put_word(m, at + 0x10, box.head)
        put_word(m, at + 0x18, n)
        for i, key in enumerate(box.keys):
            put(m, RING + stride * ((box.head + i) % box.cap) + key_at, key)
    else:
        put_word(m, at, MIN64)
        if box.plan is None:
            put_word(m, at + 8, 0)
            put_word(m, at + 0x10, 0)
        else:
            put_word(m, at + 8, write_tree(m, box.plan))
            put_word(m, at + 0x10, box.height)


def pick_key(rng, box, keys_pool):
    mode = rng.pick(("in", "in", "out", "near"))
    if mode == "in" and keys_pool:
        return rng.pick(keys_pool)
    if mode == "near" and keys_pool:
        base = bytearray(rng.pick(keys_pool))
        base[rng.below(20)] ^= 1 << rng.below(8)
        key = bytes(base)
        return key if key not in keys_pool else bytes(19 - i for i in range(20)) + b"\x00"
    key = gen_keys(rng, 1)[0]
    return key if key not in keys_pool else bytes(range(20))


# ---------------------------------------------------------------- ring search

def ring_case(rng):
    box = make_set(rng)
    while box.kind != "ring" or not box.keys:
        box = make_set(rng)
    return Box(box=box, key=pick_key(rng, box, box.keys))


def ring_expected(c, flaw=None):
    pos = bisect.bisect_left(c.box.keys, c.key)
    if pos < len(c.box.keys) and c.box.keys[pos] == c.key:
        return 0, pos
    return 1, pos + (1 if flaw == "late" else 0)


def ring_actual(image, c):
    m = new_machine(image, {})
    place_set(m, c.box, OUT, ELEM_D0)
    put(m, KEYP, c.key)
    m.set_reg(RDI, OUT)
    m.set_reg(RSI, KEYP)
    run(m, START["ring_search_d0"])
    return (m.get(RAX, 8), m.get(RDX, 64)), m


def ring_eval(image, c, flaw=None):
    value, m = ring_actual(image, c)
    box = c.box
    wrap = box.head + len(box.keys) > box.cap
    label = f"rows={len(box.keys) if len(box.keys) < 4 else '4+'} wrap={int(wrap)} -> {'found' if value[0] == 0 else 'absent'}"
    return value == ring_expected(c, flaw), label, f"cmp{min(len(m.log), 9)}", m


# ---------------------------------------------------------------- market check

def make_market(rng):
    box = make_set(rng)
    nreg = rng.pick((1, 2, 3, 5))
    regs = [rng.word() for _ in range(nreg)]
    idx = rng.below(nreg + (1 if rng.below(8) == 0 else 0))
    key = pick_key(rng, box, box.keys)
    stage = rng.pick(("early", "mid", "late", "late", "late", "late"))
    pick = (lambda *opts: rng.pick(opts))
    value = rng.word()
    c = Box(box=box, regs=regs, idx=idx, key=key, amount=rng.pick((0, 1, 1, 5, 1000, rng.word())),
            flag=rng.pick((0, 0, 0, 1, 2)), check_a=pick(0, 0, 0, 0, 1, 255), check_b=pick(0, 0, 0, 1, 2, 7),
            byte228=pick(0, 1, 1, 2), check_c=pick(0, 0, 0, 1, 255), entry=pick(None, value, value, value),
            ret_rax=pick(1, 1, 1, 0, 2), ret_rdx=0, junk=rng.next())
    c.amount = c.amount if rng.below(12) else 0
    if stage == "early":
        c.check_b, c.check_c = 0, 0
    elif stage == "mid":
        c.check_a, c.flag = 0, 0
    else:
        c.check_a, c.flag = 0, 0
        c.check_b = c.check_b if rng.below(3) == 0 else 0
        c.check_c = c.check_c if rng.below(3) == 0 else 0
    if c.entry is not None:
        threshold = c.entry >> 1
        c.ret_rdx = rng.pick((0, 1, threshold, min(threshold + 1, U64), rng.below(threshold + 1), rng.word()))
    return c


def market_expected(c, flaw=None):
    """Rule: ordered refusals, each named by its status word; host checks consulted in this order."""
    log = []
    if c.amount == 0:
        return "ret", 0x62, None, log
    log.append(("check_a", CTX, c.idx))
    if c.check_a & 0xff:
        return "ret", 0x75, None, log
    if c.flag & 0xff:
        return "ret", 0x103, None, log
    if c.key in c.box.keys and flaw != "no_set":
        return "ret", 0x1d, None, log
    if c.idx >= len(c.regs):
        return "panic", "bounds", ("panic", 1, c.idx, len(c.regs)), log
    reg = c.regs[c.idx]
    log.append(("check_b", CTX + 0x58, reg))
    if c.check_b & 0xff:
        if c.check_b == 1 and flaw != "b_any":
            return "ret", 0x195, None, log
        if c.byte228 == 1 and flaw != "no_228":
            return "ret", 0x193, 7, log
    log.append(("check_c", CTX + 0x58, reg))
    if c.check_c & 0xff:
        return "ret", 0x192, None, log
    log.append(("map", CTX + 0x510, reg))
    if c.entry is None:
        return "ret", 0x6a, None, log
    log.append(("check_d", CTX + 0x10, reg, c.amount))
    half = c.entry >> (0 if flaw == "no_half" else 1)
    if c.ret_rax == 1 and c.ret_rdx <= half:
        return "ret", 0x1a2, None, log
    return "ret", 0x6b, None, log


def market_actual(image, c):
    log = []

    def host(name, result):
        def hook(m):
            args = tuple(m.get(r, 64) for r in (RDI, RSI, RDX))
            log.append((name,) + args[:{"check_a": 2, "check_b": 2, "check_c": 2, "map": 2, "check_d": 3}[name]])
            if name == "map":
                log[-1] = ("map", args[0], m.load(args[1], 8))
                return VALS if c.entry is not None else 0
            return result
        return hook
    hooks = {image.slots[SLOT_PANIC]: panic_hook(1), image.slots[SLOT_PANIC2]: panic_hook(2),
             image.slots[SLOT_CHECK_A]: host("check_a", c.check_a), image.slots[SLOT_CHECK_B]: host("check_b", c.check_b),
             image.slots[SLOT_CHECK_C]: host("check_c", c.check_c), image.slots[SLOT_CHECK_D]: host("check_d", (c.ret_rax, c.ret_rdx)),
             TARGET_MAP_GET: host("map", None)}
    m = new_machine(image, hooks)
    put_word(m, CTX + 0x18, REC1)
    put_word(m, CTX + 0x20, len(c.regs))
    for i, reg in enumerate(c.regs):
        put_word(m, REC1 + 0x20 * i, reg)
    m.mem[CTX + 0x228] = c.byte228
    if c.entry is not None:
        put_word(m, VALS, c.entry)
    place_set(m, c.box, STATE + 0xa18, ELEM_D0)
    put(m, KEYP, c.key)
    put_word(m, OUT, 0xffff, 2)
    put_word(m, cpu.STACK + 8, STATE)
    for r, v in ((RDI, OUT), (RSI, CTX), (RDX, KEYP), (RCX, c.idx), (R8, c.amount), (R9, c.flag)):
        m.set_reg(r, v)
    how = run(m, START["market_check"])
    if how == "panic":
        return "panic", "bounds", m.log[-1], log, m
    status = m.load(OUT, 2)
    return "ret", status, (m.mem[OUT + 2] if status == 0x193 else None), log, m


def market_eval(image, c, flaw=None):
    exp = market_expected(c, flaw)
    how, a, b, log, m = market_actual(image, c)
    if exp[0] == "panic":
        ok = how == "panic" and b[:4] == exp[2][:4] and log == exp[3]
    else:
        ok = (how, a, b, log) == exp
    name = "panic-bounds" if how == "panic" else STATUS.get(a, hex(a))
    sig = "+".join(entry[0] for entry in log) or "-"
    return ok, f"{c.box.kind}-set -> {name}", sig, m


# ---------------------------------------------------------------- margin check

def gen_bound(rng, slot):
    """One optional bound: absent, or a (pointer, length) text that the parse stub answers for."""
    if rng.below(4) == 0:
        return None
    ln = rng.pick((0, 1, 5, 20, 99, 100, 101, 1000))
    status = 0x1a2 if rng.below(5) else rng.pick((0x10, 0x55, 0x1a3, 0x7fff))
    payload = bytes(rng.below(256) for _ in range(16))
    scale_status = 0x1a2 if rng.below(5) else rng.pick((0x77, 0x1a1, 0x300))
    value = rng.pick((0, 1, 2, 100, 1000, rng.word(), rng.below(50), U64))
    return Box(len=ln, status=status, payload=payload, scale_status=scale_status, value=value, ptr=VALS + 0x1000 * slot + 0x100 * rng.below(8) + 0x40)


def make_margin(rng):
    nidx = rng.pick((1, 2, 3))
    nrec = rng.pick((1, 2, 3, 5))
    kinds = [rng.below(12) for _ in range(nrec)]
    index = []
    for _ in range(nidx):
        x, y = rng.below(nrec + (1 if rng.below(12) == 0 else 0)), rng.below(nrec + (1 if rng.below(12) == 0 else 0))
        index.append((y, x))
    idx = rng.below(nidx + (1 if rng.below(10) == 0 else 0))
    a, b = gen_bound(rng, 1), gen_bound(rng, 2)
    ref = rng.pick((0, 1, 50, 100, 1000, rng.word()))
    pool = [v.value for v in (a, b) if v is not None] + [ref, ref + 1, ref - 1 if ref else 0]
    for bound in (a, b):
        if bound is not None and rng.below(3) == 0:
            bound.value = rng.pick(pool) & U64
    return Box(a=a, b=b, a_byte=rng.pick((0, 1, 2, 3, 0xff)), idx=idx, flag=rng.pick((0, 0, 1, 1, 2, 0x101, 0xff00)), ref=ref,
               index=index, kinds=kinds, a_tag=rng.pick((0, 1, 64, MIN64 - 1, MIN64 + 1)), b_tag=rng.pick((0, 7, U64)))


def margin_value(c, bound, log):
    """Parse text, look up the pair of records, rescale: ('ret', status) on a refusal, ('val', n) on success; panics raise."""
    if bound.len >= 0x65:
        return "ret", 0x158
    log.append(("parse", bound.ptr, bound.len))
    if bound.status != 0x1a2:
        return "ret", bound.status
    if c.idx >= len(c.index):
        raise Panic("bounds", ("panic", 1, c.idx, len(c.index)))
    y, x = c.index[c.idx]
    if x >= len(c.kinds) or y >= len(c.kinds):
        raise Panic("record", ("panic", 2))
    diff = c.kinds[x] - c.kinds[y]
    if diff < 0:
        raise Panic("borrow", ("panic", 3))
    log.append(("scale", bound.payload, 2, diff))
    if bound.scale_status != 0x1a2:
        log.append(("drop", bound.scale_status))
        return "ret", 0xad
    if bound.value == 0:
        return "ret", 0xad
    log.append(("drop", 0xad))
    return "val", bound.value


class Panic(Exception):
    def __init__(self, kind, entry):
        super().__init__(kind)
        self.kind, self.entry = kind, entry


def margin_expected(c, flaw=None):
    """Rule: lower bound A is optional; B optional; compare B against A (or against the reference when A is absent)."""
    log = []
    try:
        if c.a is None and c.b is None:
            return "ret", 0xdb, None, log
        first, byte = None, 2
        if c.a is not None:
            kind, v = margin_value(c, c.a, log)
            if kind == "ret":
                return "ret", v, (CTX if v == 0x158 else None), log
            first, byte = v, c.a_byte
            if c.b is None:
                return "ret", 0x1a2, (0, first, byte), log
        kind, second = margin_value(c, c.b, log)
        if kind == "ret":
            return "ret", second, (CTX + 0x20 if second == 0x158 else None), log
        eq_ref = byte == 2
        other = c.ref if eq_ref else first
        lt = second < other
        v = ((c.flag & 0xff) ^ (0 if flaw == "no_flag" else int(lt))) | int(second == other)
        if v & 0xff:
            return "ret", (0xda if eq_ref else 0xd9), None, log
        return "ret", 0x1a2, (second, None if eq_ref else first, byte), log
    except Panic as p:
        return "panic", p.kind, p.entry, log


def margin_actual(image, c):
    log = []
    answers = collections.deque()
    for bound in (c.a, c.b):
        if bound is not None:
            answers.append(bound)

    def parse_hook(m):
        rdi, ptr, ln = (m.get(r, 64) for r in (RDI, RSI, RDX))
        which = next(bd for bd in (c.a, c.b) if bd is not None and bd.ptr == ptr and bd.len == ln)
        log.append(("parse", ptr, ln))
        put(m, rdi, bytes(0x70))                       # the whole result block is copied around by the body
        put_word(m, rdi, which.status, 2)
        put(m, rdi + 4, which.payload[0:4])
        put(m, rdi + 8, which.payload[4:12])
        put(m, rdi + 0x10, which.payload[12:16])
        return rdi

    def scale_hook(m):
        rdi, rsi, edx, ecx = (m.get(r, 64) for r in (RDI, RSI, RDX, RCX))
        blob = bytes(m.mem[rsi + i] for i in range(16))
        which = next(bd for bd in (c.a, c.b) if bd is not None and bd.payload == blob)
        log.append(("scale", blob, edx & U64, ecx & 0xff))
        put(m, rdi, bytes(0x70))
        put_word(m, rdi, which.scale_status, 2)
        put_word(m, rdi + 8, which.value)
        return rdi

    def drop_hook(m):
        log.append(("drop", m.load(m.get(RDI, 64), 2)))
        return None
    hooks = {image.slots[SLOT_PANIC]: panic_hook(1), image.slots[SLOT_PANIC2]: panic_hook(2), image.slots[SLOT_PANIC3]: panic_hook(3),
             image.slots[SLOT_PARSE]: parse_hook, image.slots[SLOT_SCALE]: scale_hook, TARGET_DROP: drop_hook}
    m = new_machine(image, hooks)
    put_word(m, TBL + 0x10, len(c.index))
    put_word(m, TBL + 8, REC1)
    put_word(m, TBL + 0x28, len(c.kinds))
    put_word(m, TBL + 0x20, REC2)
    for i, (y, x) in enumerate(c.index):
        put_word(m, REC1 + 0x20 * i, y)
        put_word(m, REC1 + 0x20 * i + 8, x)
    for i, kind in enumerate(c.kinds):
        m.mem[REC2 + 0x158 * i + 0x48] = kind
        m.mem[REC2 + 0x158 * i + 0x49] = kind
    put_word(m, CTX, c.a_tag if c.a is not None else MIN64)
    if c.a is not None:
        put_word(m, CTX + 8, c.a.ptr)
        put_word(m, CTX + 0x10, c.a.len)
        m.mem[CTX + 0x18] = c.a_byte
    put_word(m, CTX + 0x20, c.b_tag if c.b is not None else MIN64)
    if c.b is not None:
        put_word(m, CTX + 0x28, c.b.ptr)
        put_word(m, CTX + 0x30, c.b.len)
    put_word(m, OUT, 0xffff, 2)
    for r, v in ((RDI, OUT), (RSI, CTX), (RDX, c.idx), (RCX, c.flag), (R8, c.ref), (R9, TBL)):
        m.set_reg(r, v)
    how = run(m, START["margin_check"])
    if how == "panic":
        return "panic", {1: "bounds", 2: "record", 3: "borrow"}[m.log[-1][1]], m.log[-1], log, m
    status = m.load(OUT, 2)
    body = m.load(OUT + 8, 8) if status == 0x158 else None     # the refusal hands back the bound that was too long
    if status == 0x1a2:
        body = (m.load(OUT + 8, 8), m.load(OUT + 0x10, 8), m.mem[OUT + 0x18])
    return "ret", status, body, log, m


def margin_eval(image, c, flaw=None):
    exp = margin_expected(c, flaw)
    how, a, b, log, m = margin_actual(image, c)
    if exp[0] == "panic":
        ok = how == "panic" and a == exp[1] and b[:len(exp[2])] == exp[2] and log == exp[3]
        name = "panic-" + a
    else:
        want = exp[2]
        if isinstance(want, tuple) and want[1] is None and b is not None:     # lower bound absent: the field is stack garbage
            b = (b[0], None, b[2])
        ok = (how, a, b, log) == exp
        name = STATUS.get(a, hex(a))
    sig = "+".join(entry[0] for entry in log) or "-"
    return ok, f"a={'-' if c.a is None else 'set'} b={'-' if c.b is None else 'set'} -> {name}", sig, m


# ---------------------------------------------------------------- case battery

START = dict(BODIES)
EVAL = {"resolve": resolve_eval, "market_check": market_eval, "margin_check": margin_eval, "ring_search_d0": ring_eval}
MAKE = {"resolve": gen_resolve, "market_check": make_market, "margin_check": make_margin, "ring_search_d0": ring_case}
FLAWS = {"resolve": ("kind9", "unscaled", "floor"), "market_check": ("no_set", "b_any", "no_228", "no_half"),
         "margin_check": ("no_flag",), "ring_search_d0": ("late",)}


def seed_of(body):
    return int.from_bytes(hashlib.sha256(body.encode()).digest()[:8], "little")


def cases(body, count):
    rng = Lcg(seed_of(body))
    for _ in range(count):
        ALLOC.next = NODES
        yield MAKE[body](rng)


def attempt(image, body, case, flaw=None):
    """evaluate() that treats an evaluator refusal as a detection (the run left the modelled domain)."""
    ALLOC.next = NODES
    try:
        return EVAL[body](image, case, flaw)[0]
    except (ToolError, cpu.ToolError, cpu.Done, KeyError, TypeError, ValueError, OverflowError, IndexError):
        return False


def region(addr):
    for name, base, size in (("state", STATE, 0x10000), ("ctx", CTX, 0x1000), ("out", OUT, 0x100), ("key", KEYP, 0x40),
                             ("table", TBL, 0x100), ("index", REC1, 0x1000), ("records", REC2, 0x1000),
                             ("ring", RING, 0x2000), ("node", NODES, 0x100000), ("value", VALS, 0x10)):
        if base <= addr < base + size:
            off = addr - base
            if name == "ring":
                off %= ELEM_D0
            elif name == "node":
                off %= 0x1000
            elif name == "index":
                off %= 0x20
            elif name == "records":
                off %= 0x158
            return name, off
    return None


def run_battery(image, entries):
    summary = {"cases": 0, "mismatches": 0}
    labels, sigs, reads = collections.Counter(), collections.Counter(), collections.Counter()
    for body, _ in BODIES:
        for case in cases(body, CASES[body]):
            ok, label, sig, m = EVAL[body](image, case)
            summary["cases"] += 1
            summary["mismatches"] += not ok
            labels[(body, label)] += 1
            sigs[(body, sig)] += 1
            for (addr, size), n in m.reads.items():
                where = region(addr)
                if where is not None:
                    reads[(body, where[0], where[1], size)] += n
    entries["cases"] = [f"{b}\t{lab}\t{n}" for (b, lab), n in sorted(labels.items())]
    entries["hooks"] = [f"{b}\t{s}\t{n}" for (b, s), n in sorted(sigs.items())]
    entries["reads"] = [f"{b}\t{r}\t{o:#x}\t{sz}\t{n}" for (b, r, o, sz), n in sorted(reads.items())]
    return summary


# ---------------------------------------------------------------- mutants

def patch(image, va, new):
    off = image.file_offset(va)
    old = bytes(image.data[off:off + len(new)])
    image.data[off:off + len(new)] = new
    image.cache.clear()
    return old


def mutation_sites(image, body):
    """(address of the patched byte, kind, new byte): conditional branches flipped, imm8 nudged, status immediates nudged."""
    lo, hi = body_extent(image, START[body])
    data, out = image.data, []
    for insn in sweep(image, lo, hi):
        key = insn.key
        if isinstance(key, int) and 0x70 <= key <= 0x7f:
            out.append((insn.va, "jcc-flip", data[insn.off] ^ 1))
        elif isinstance(key, tuple) and key[0] == 0x0f and 0x80 <= key[1] <= 0x8f:
            out.append((insn.va + 1, "jcc-flip", data[insn.off + 1] ^ 1))
        elif key in (0x83, 0xc1, 0x6b, 0x80) and data[insn.modrm] & 7 != 4:
            out.append((insn.va + insn.size - 1, "imm8+1", (data[insn.off + insn.size - 1] + 1) & 0xff))
        elif insn.wide16 and key in (0xc7, 0xb9, 0xba) and insn.size >= 4:
            out.append((insn.va + insn.size - 2, "status+1", (data[insn.off + insn.size - 2] + 1) & 0xff))
    return out


def mutant_rows(image, entries):
    rows, killed, survived = [], 0, 0
    for body, _ in BODIES:
        battery = list(cases(body, BATTERY))
        for va, kind, new in mutation_sites(image, body):
            old = patch(image, va, bytes([new]))
            try:
                caught = any(not attempt(image, body, case) for case in battery)
            finally:
                patch(image, va, old)
            rows.append(f"{body}\t{va:#x}\t{kind}\t{old.hex()}\t{new:02x}\t{'killed' if caught else 'survived'}")
            killed += caught
            survived += not caught
    entries["mutants"] = rows
    return killed, survived


def flaw_rows(image, entries):
    rows, detected, total = [], 0, 0
    for body, _ in BODIES:
        for flaw in FLAWS[body]:
            hit = any(not attempt(image, body, case, flaw) for case in cases(body, 600))
            rows.append(f"{body}\t{flaw}\t{'detected' if hit else 'missed'}")
            detected += hit
            total += 1
    entries["flaws"] = rows
    return detected, total


def damage_rows(image, entries):
    """Byte damage and out-of-range inputs; each must be refused or detected."""
    rows, detected = [], 0

    def record(name, caught):
        nonlocal detected
        rows.append(f"{name}\t{'detected' if caught else 'missed'}")
        detected += bool(caught)

    off = image.file_offset(START["resolve"])
    image.data[off] ^= 0x01
    record("flipped byte changes the binary digest", digest(image.data) != SHA256)
    image.data[off] ^= 0x01
    record("digest is restored after the flip", digest(image.data) == SHA256)
    for body, start in BODIES:
        try:
            body_extent(image, start + 1)
            record(f"{body}: mid-function start is refused", False)
        except ToolError:
            record(f"{body}: mid-function start is refused", True)
    rng = Lcg(5)
    c = gen_resolve(rng)
    c.idx = len(c.index) + 3
    ok, label, _, _ = resolve_eval(image, c)
    record("resolve: index past the end is a bounds panic, not a status", ok and label.startswith("panic-bounds"))
    m = new_machine(image, {})
    m.set_reg(RDI, OUT)
    m.set_reg(RSI, 5)
    m.set_reg(RDX, 0)
    m.set_reg(RCX, TBL)
    try:
        run(m, START["resolve"])
        record("resolve: unpopulated table is refused", False)
    except (ToolError, cpu.ToolError, KeyError, cpu.Done):
        record("resolve: unpopulated table is refused", True)
    c = ring_case(rng)
    m = new_machine(image, {})
    m.set_reg(RDI, OUT)
    m.set_reg(RSI, 0x1234)
    try:
        run(m, START["ring_search_d0"])
        record("ring_search_d0: unpopulated ring is refused", False)
    except (ToolError, cpu.ToolError, KeyError, cpu.Done):
        record("ring_search_d0: unpopulated ring is refused", True)
    entries["damage"] = rows
    return detected, len(rows)


# ---------------------------------------------------------------- evidence

def function_rows(image):
    rows = []
    for body, start in BODIES:
        lo, hi = body_extent(image, start)
        off = image.file_offset(lo)
        rows.append(f"{body}\t{lo:#x}\t{hi:#x}\t{hi - lo}\t{len(sweep(image, lo, hi))}\t{digest(bytes(image.data[off:off + hi - lo]))}")
    return rows


def site_rows(image):
    rows = []
    for body, start in BODIES:
        lo, hi = body_extent(image, start)
        for insn in sweep(image, lo, hi):
            rows.append(f"{body}\t{insn.va:#x}\t{insn.size}\t{bytes(image.data[insn.off:insn.off + insn.size]).hex()}")
    return rows


def status_rows(image):
    rows = []
    for body in ("resolve", "market_check", "margin_check"):
        for va, value in movw_status_constants(image, body):
            rows.append(f"{body}\t{va:#x}\t{value:#x}\t{STATUS.get(value, '-')}")
    return rows


def slot_rows(image):
    rows = [f"{SLOT_PANIC:#x}\trelative\t{image.slots[SLOT_PANIC]:#x}\tbounds-check panic helper",
            f"{SLOT_PANIC2:#x}\trelative\t{image.slots[SLOT_PANIC2]:#x}\tone-argument panic helper",
            f"{SLOT_MEMCMP:#x}\timported\t-\tcompare of 20 bytes, sign of the result decides"]
    for slot, role in ((SLOT_CHECK_A, "check a: (ctx, index) -> bool"), (SLOT_CHECK_B, "check b: (ctx+0x58, record) -> byte"),
                       (SLOT_CHECK_C, "check c: (ctx+0x58, record) -> bool"), (SLOT_CHECK_D, "check d: (ctx+0x10, record, amount) -> (flag, bound)")):
        rows.append(f"{slot:#x}\trelative\t{image.slots[slot]:#x}\t{role}, stubbed")
    for slot, role in ((SLOT_PARSE, "parse text -> decimal (ptr, len) -> 16-byte payload"),
                       (SLOT_SCALE, "rescale (payload, 2, kind difference) -> (status, value)"),
                       (SLOT_PANIC3, "subtraction overflow panic helper")):
        rows.append(f"{slot:#x}\trelative\t{image.slots[slot]:#x}\t{role}, stubbed")
    lo, hi = body_extent(image, TARGET_DROP)
    rows.append(f"{TARGET_DROP:#x}\tcode\t{hi - lo}\tdrop glue for the status word, stubbed (status logged)")
    lo, hi = body_extent(image, TARGET_MAP_GET)
    rows.append(f"{TARGET_MAP_GET:#x}\tcode\t{hi - lo}\tmap lookup (ctx+0x510, &record) -> pointer or null, stubbed")
    return rows


def tsv(header, rows):
    return "\t".join(header) + "\n" + "".join(row + "\n" for row in rows)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def generate(out):
    data = bytearray(TARGET.read_bytes())
    if digest(data) != SHA256:
        fail("input binary digest differs from node #115")
    image = cpu.Image(data)
    entries = {}
    summary = run_battery(image, entries)
    killed, survived = mutant_rows(image, entries)
    detected_flaws, flaws = flaw_rows(image, entries)
    detected_damage, damage = damage_rows(image, entries)
    controls = killed + flaws + damage
    detected = killed + detected_flaws + detected_damage
    measure = {"cases": summary["cases"], "negative_controls": controls, "negative_detected": detected,
               "mismatches": summary["mismatches"], "mutants_killed": killed, "mutants_survived": survived,
               "spec_flaws": flaws, "damage_controls": damage}
    files = {
        "functions.tsv": tsv(("body", "start", "end", "bytes", "instructions", "sha256"), function_rows(image)),
        "sites.tsv": tsv(("body", "va", "size", "bytes"), site_rows(image)),
        "statuses.tsv": tsv(("body", "va", "status", "meaning"), status_rows(image)),
        "slots.tsv": tsv(("address", "kind", "value", "role"), slot_rows(image)),
        "cases.tsv": tsv(("body", "class", "count"), entries["cases"]),
        "hook-sequences.tsv": tsv(("body", "host calls", "count"), entries["hooks"]),
        "field-reads.tsv": tsv(("body", "region", "offset", "size", "reads"), entries["reads"]),
        "mutants.tsv": tsv(("body", "va", "kind", "from", "to", "result"), entries["mutants"]),
        "spec-flaws.tsv": tsv(("body", "flaw", "result"), entries["flaws"]),
        "damage.tsv": tsv(("control", "result"), entries["damage"]),
        "measure.json": json.dumps(measure, indent=1, sort_keys=True) + "\n",
    }
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text)
    return measure


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args()
    measure = generate(args.out)
    print(json.dumps(measure, sort_keys=True))
    return 0 if measure["mismatches"] == 0 and measure["negative_controls"] == measure["negative_detected"] else 1


if __name__ == "__main__":
    sys.exit(main())
