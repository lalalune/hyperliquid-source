#!/usr/bin/env python3
"""Reconstruct the node #115 keyed lookups behind the order value gate from ELF bytes.

The order value gate (merged packet RE-004-order-value-gate-115) calls a record-kind
lookup and two total readers and only stubs them. This tool runs the real bytes of
those callees on the shared concrete evaluator `decimal_scaled_u64` (bytes are read,
never executed natively) and compares every run with pure-Python rules:

  0x2a8a770            record lookup in the state map (zero / one / many rows) with default
  0x4ef4480            the same map lookup on a stand-alone map, null when absent
  0x55e8c30 0x55e8cb0  wrappers: map at state+0x968 / +0x14d8, default when absent
  0x2d35520 0x2d357d0  byte-identical total readers: two containers, saturating sum
  0x24c55a0            ring (VecDeque) binary search over 0x38-byte rows, 20-byte keys

Hash, bucket probe, Once slow path, panic helper and memcmp are host calls with
recorded stubs; their arguments are checked in every run.

Usage: python3 tools/order_value_lookups_115.py --out <folder>
"""
import argparse
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
R8 = cpu.R8
STEP_LIMIT = 6000
MIN64 = 1 << 63

SLOT_DEFAULT = 0x64e71a8     # pointer slot of the shared default record
SLOT_MEMCMP = 0x64dfb50      # imported compare, no local addend
SLOT_PANIC = 0x64df620
SLOT_ONCE = 0x64df9f0
MEMCMP_MARK = 0x7e000001
TARGET_HASH_STATE, TARGET_PROBE_STATE = 0x2b6e540, 0x26fe6d0
TARGET_HASH_MAP, TARGET_PROBE_MAP = 0x4ef4560, 0x4eff000

STATE, KEY, ROWS, BUCKET, TOTAL, RING1, RING2, NODES = (
    0x7200_0000, 0x7210_0000, 0x7220_0000, 0x7230_0000, 0x7240_0000, 0x7250_0000, 0x7260_0000, 0x7270_0000)
RING = 0x7280_0000
ROW_STRIDE, KEY_AT, ELEM = 0x60, 0x48, 0x38

BODIES = (
    ("state_lookup", 0x2a8a770), ("map_get", 0x4ef4480), ("state_map_a", 0x55e8c30), ("state_map_b", 0x55e8cb0),
    ("total_a", 0x2d35520), ("total_b", 0x2d357d0), ("ring_search", 0x24c55a0))
CASES = {"state_lookup": 2200, "map_get": 2200, "state_map_a": 1800, "state_map_b": 1800,
         "total_a": 2400, "total_b": 2400, "ring_search": 2200}
BATTERY = 140          # cases per mutant run
MAP_OFFSET = {"state_map_a": 0x968, "state_map_b": 0x14d8}


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
        mode = self.below(5)
        if mode == 0:
            return self.next() | (self.next() << 40) & U64
        if mode == 1:
            return U64 - self.below(3)
        if mode == 2:
            return self.below(1000)
        if mode == 3:
            return (U64 >> 1) + self.below(3)
        return self.next() << 20 & U64


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
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        self.flags = [None, None, None, None]
        if result is not None:
            self.set_reg(RAX, result & U64)
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
        if isinstance(key, tuple) and key[0] == 0x0f and insn.wide16 and key[1] in (0x6e, 0x74, 0xdb, 0xd7):
            self.seen.add(here)
            self.pc = here + insn.size
            self.sse(insn, key[1])
            return
        super().step()

    def sse(self, insn, op):
        data = self.image.data
        modrm = data[insn.modrm]
        reg, rm = (modrm >> 3) & 7, modrm & 7
        if op == 0xd7:                                          # pmovmskb r32, xmm
            src = self.xmm[rm]
            if src is None:
                fail("pmovmskb of an unknown vector")
            self.put(reg | ((insn.rex & 4) << 1), 32, sum(1 << i for i, b in enumerate(src) if b & 0x80))
            return
        if op == 0x6e:                                          # movd xmm, m32
            operand = self.operand(insn)
            value = self.read(operand, 32)
            self.xmm[reg] = None if value is None else struct.pack("<I", value) + bytes(12)
            return
        left, right = self.xmm[reg], self.xmm[rm]
        if left is None or right is None:
            fail("vector operation on an unknown value")
        if op == 0x74:
            self.xmm[reg] = bytes(0xff if a == b else 0 for a, b in zip(left, right))
        else:
            self.xmm[reg] = bytes(a & b for a, b in zip(left, right))


def new_machine(image, hooks):
    image.slots[SLOT_MEMCMP] = MEMCMP_MARK   # imported symbol, no local addend: modelled as a host call
    m = Machine(image, hooks)
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


def default_record(image):
    return image.slots[SLOT_DEFAULT]


def initial_once_byte(image):
    d = default_record(image) + 0x40
    addr, off, size = image.sections[".data"]
    return image.data[d - addr + off] if addr <= d < addr + size else None


# ---------------------------------------------------------------- lookup world

def hash_of(key, k0, k1):
    return ((int.from_bytes(key, "little") * 0x9e3779b97f4a7c15) ^ (k0 * 3) ^ k1) & U64


class Lookup:
    """One case: rows with 20-byte keys, a query key, and what the bucket probe answers."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def gen_keys(rng, n):
    prefix = bytes(rng.below(256) for _ in range(rng.pick((0, 4, 16, 19))))
    seen, keys = set(), []
    while len(keys) < n:
        k = (prefix + bytes(rng.below(256) for _ in range(20)))[:20]
        if k not in seen:
            seen.add(k)
            keys.append(k)
    return keys


def make_lookup(rng, which):
    n = rng.pick((0, 1, 1, 1, 2, 2, 3, 4, 7, 12))
    keys = gen_keys(rng, n)
    kind = rng.pick(("hit", "hit", "near", "far"))
    if kind == "hit" and n:
        key = rng.pick(keys)
    elif kind == "near" and n:
        base = bytearray(rng.pick(keys))
        base[rng.below(20)] ^= 1 << rng.below(8)
        key = bytes(base)
        if key in keys:
            kind, key = "far", gen_keys(rng, 1)[0]
    else:
        kind, key = "far", gen_keys(rng, 1)[0]
        if key in keys:
            key = bytes(20 - 1 - i for i in range(20))
    mode = rng.pick(("exact", "exact", "exact", "null", "oob", "last", "zero"))
    return Lookup(rows=keys, key=key, kind=kind, mode=mode, extra=rng.below(3), k0=rng.word(), k1=rng.word(),
                  once=rng.pick((0, 0, 1, 2, 4, 0x100)), junk=rng.next())


def probe_answer(case):
    """(bucket index to store, or None for a null answer) from the probe mode."""
    n = len(case.rows)
    if case.mode == "null":
        return None
    if case.mode == "oob":
        return n + case.extra
    if case.mode == "last":
        return n - 1
    if case.mode == "zero":
        return 0
    return case.rows.index(case.key) if case.key in case.rows else None


def build_lookup_world(image, case, body, start):
    name_hash = TARGET_HASH_STATE if body == "state_lookup" else TARGET_HASH_MAP
    name_probe = TARGET_PROBE_STATE if body == "state_lookup" else TARGET_PROBE_MAP
    base = map_base(body)
    hk_at = base + 0x38     # hasher key words sit at map+0x38/+0x40 (state+0x9a0/+0x9a8 for the state form)
    d = default_record(image)
    hooks = {}

    def hash_hook(m):
        args = tuple(m.get(r, 64) for r in (RDI, RSI, RDX))
        m.log.append(("hash",) + args)
        return hash_of(bytes(m.mem[args[2] + i] for i in range(20)), args[0], args[1])

    def probe_hook(m):
        args = tuple(m.get(r, 64) for r in (RDI, RSI, RDX))
        frame = tuple(m.load(args[2] + 8 * i, 8) for i in range(3))
        m.log.append(("probe",) + args + frame)
        idx = probe_answer(case)
        if idx is None:
            return 0
        put_word(m, BUCKET, idx)
        return BUCKET + 8

    def once_hook(m):
        m.log.append(("once",) + tuple(m.get(r, 64) for r in (RDI, RSI, RCX, R8)))
        return None

    def panic_hook(m):
        m.log.append(("panic",) + tuple(m.get(r, 64) for r in (RDI, RSI, RDX)))
        raise cpu.Done("panic", m.pc)

    hooks[name_hash], hooks[name_probe] = hash_hook, probe_hook
    hooks[image.slots[SLOT_PANIC]], hooks[image.slots[SLOT_ONCE]] = panic_hook, once_hook
    m = new_machine(image, hooks)
    n = len(case.rows)
    put_word(m, base + 8, ROWS)
    put_word(m, base + 0x10, n)
    put_word(m, hk_at, case.k0)
    put_word(m, hk_at + 8, case.k1)
    for i, key in enumerate(case.rows):
        put(m, ROWS + ROW_STRIDE * i + KEY_AT, key)
    put(m, KEY, case.key)
    put_word(m, SLOT_DEFAULT, d)
    put_word(m, d + 0x40, case.once, 4)
    m.set_reg(RDI, STATE)
    m.set_reg(RSI, KEY)
    return m


def map_base(body):
    """Address of the map object the body reads: state+0x968 / +0x14d8 for the state forms, the argument itself for map_get."""
    return {"state_lookup": STATE + 0x968, "map_get": STATE, "state_map_a": STATE + 0x968, "state_map_b": STATE + 0x14d8}[body]


def lookup_expected(image, case, body, consts, flaw=None):
    """Rule: zero rows -> miss; one row -> 20-byte compare; many -> hash, probe, bounds check; default when absent."""
    n = len(case.rows)
    d = default_record(image)
    log, found = [], None
    if n == 1:
        width = 16 if flaw == "cmp16" else 20
        found = ROWS + 8 if case.rows[0][:width] == case.key[:width] else None
        if flaw == "hash_for_one":
            log.append(("hash", case.k0, case.k1, KEY))
    elif n >= 2:
        h = hash_of(case.key, case.k0, case.k1)
        log.append(("hash", case.k0, case.k1, KEY))
        log.append(("probe", map_base(body) + 0x18, h, "frame"))
        idx = probe_answer(case)
        if flaw == "recheck" and idx is not None and idx < n and case.rows[idx] != case.key:
            idx = None
        if idx is not None:
            if idx > n if flaw == "bound_gt" else idx >= n:
                if flaw != "bound_gt":
                    log.append(("panic", idx, n, consts["panic"]))
                    return "panic", None, log
            found = ROWS + ROW_STRIDE * idx + 8
    if body != "map_get":
        if case.once and flaw != "no_once":
            log.append(("once", d + 0x40, 1, consts["once_rcx"], consts["once_r8"]))
        return "ret", (0 if flaw == "no_default" and found is None else d if found is None else found), log
    return "ret", (0 if found is None else found), log


def lookup_actual(image, case, body, start):
    m = build_lookup_world(image, case, body, start)
    how = run(m, start)
    log = []
    for entry in m.log:
        if entry[0] == "probe":
            frame_ok = entry[4:7] == (KEY, ROWS, len(case.rows))
            log.append(("probe", entry[1], entry[2], "frame" if frame_ok else entry[4:7]))
        else:
            log.append(entry)
    return how, (None if how == "panic" else m.get(RAX, 64)), log, m


# ---------------------------------------------------------------- total / ring world

LEAF_CAP = 11


def sorted_pairs(rng, n):
    keys = sorted(gen_keys(rng, n))
    return [(k, rng.word()) for k in keys]


def build_tree(rng, pairs, height):
    """Complete B-tree plan: ('leaf', pairs) or ('node', separators, children), all leaves at one depth."""
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
        at, self.next = self.next, self.next + 0x300
        return at


def write_tree(m, plan, alloc):
    at = alloc.take()
    if plan[0] == "leaf":
        entries, kids = plan[1], []
    else:
        entries, kids = plan[1], [write_tree(m, child, alloc) for child in plan[2]]
    for i, (key, value) in enumerate(entries):
        put(m, at + 0x168 + 0x14 * i, key)
        put_word(m, at + 0x18 + 0x20 * i, value)
    put_word(m, at + 0x246, len(entries), 2)
    for i, kid in enumerate(kids):
        put_word(m, at + 0x248 + 8 * i, kid)
    return at


def tree_pairs_of(plan):
    if plan[0] == "leaf":
        return list(plan[1])
    out = []
    for i, kid in enumerate(plan[2]):
        out += tree_pairs_of(kid)
        if i < len(plan[1]):
            out.append(plan[1][i])
    return out


class Box:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def make_container(rng):
    kind = rng.pick(("empty", "deque", "deque", "deque", "tree", "tree", "tree2", "treeroot"))
    if kind == "empty":
        return Box(kind="deque", pairs=[], cap=rng.below(3), head=0)
    if kind == "deque":
        n = rng.pick((1, 2, 3, 5, 8, 13))
        cap = n + rng.below(4)
        return Box(kind="deque", pairs=sorted_pairs(rng, n), cap=cap, head=rng.below(cap))
    if kind == "treeroot":
        return Box(kind="tree", pairs=[], plan=None)
    height = 0 if kind == "tree" else rng.pick((1, 2))
    n = rng.pick((1, 3, 6, 11)) if height == 0 else rng.pick((9, 14, 20, 40)) if height == 1 else rng.pick((20, 40, 60))
    pairs = sorted_pairs(rng, n)
    plan = build_tree(rng, pairs, height)
    return Box(kind="tree", pairs=tree_pairs_of(plan), plan=plan, height=height)


def place_container(m, box, at, ring_base):
    """Write one container at `at` (cap,ptr,head,len or MIN-niche,root,height) and return its pairs."""
    if box.kind == "deque":
        n = len(box.pairs)
        put_word(m, at, box.cap)
        put_word(m, at + 8, ring_base)
        put_word(m, at + 0x10, box.head)
        put_word(m, at + 0x18, n)
        for i, (key, value) in enumerate(box.pairs):
            slot = ring_base + ELEM * ((box.head + i) % box.cap)
            put(m, slot, key)
            put_word(m, slot + 0x30, value)
    else:
        put_word(m, at, MIN64)
        if box.plan is None:
            put_word(m, at + 8, 0)
            put_word(m, at + 0x10, 0)
        else:
            put_word(m, at + 8, write_tree(m, box.plan, ALLOC))
            put_word(m, at + 0x10, box.height)
    return box.pairs


ALLOC = Alloc()


def memcmp_hook(m):
    a, b, n = (m.get(r, 64) for r in (RDI, RSI, RDX))
    m.log.append(("cmp", n))
    for i in range(n):
        x, y = m.mem[a + i], m.mem[b + i]
        if x != y:
            return (x - y) & U64
    return 0


def total_machine(image, hooks):
    m = new_machine(image, hooks)
    put_word(m, SLOT_MEMCMP, MEMCMP_MARK)
    return m


def total_case(rng):
    first, second = make_container(rng), make_container(rng)
    pool = [k for k, _ in first.pairs + second.pairs]
    mode = rng.pick(("hit", "hit", "miss", "both"))
    if mode == "both" and first.pairs:
        key = first.pairs[0][0]
        for box in (second,):                       # force the same key into the second container
            if box.pairs and box.kind == "deque":
                box.pairs[0] = (key, box.pairs[0][1])
                box.pairs.sort()
    elif pool and mode == "hit":
        key = rng.pick(pool)
    else:
        key = gen_keys(rng, 1)[0]
    return Box(first=first, second=second, key=key)


def sorted_ok(box):
    keys = [k for k, _ in box.pairs]
    return keys == sorted(keys) and len(set(keys)) == len(keys)


def container_value(box, key):
    return dict(box.pairs).get(key, 0)


def total_expected(case, flaw=None):
    a, b = container_value(case.first, case.key), container_value(case.second, case.key)
    s = a + b
    if flaw == "wrap":
        return s & U64
    return U64 if s > U64 else s


def total_actual(image, case, start):
    ALLOC.next = NODES
    m = total_machine(image, {})
    m.hooks[MEMCMP_MARK] = memcmp_hook
    place_container(m, case.first, TOTAL + 0x18, RING1)
    place_container(m, case.second, TOTAL + 0x38, RING2)
    put(m, KEY, case.key)
    m.set_reg(RDI, TOTAL)
    m.set_reg(RSI, KEY)
    run(m, start)
    return m.get(RAX, 64), m


def ring_case(rng):
    box = make_container(rng)
    while box.kind != "deque" or not box.pairs:
        box = make_container(rng)
    pool = [k for k, _ in box.pairs]
    key = rng.pick(pool) if rng.below(2) else gen_keys(rng, 1)[0]
    return Box(box=box, key=key)


def ring_expected(case, flaw=None):
    keys = [k for k, _ in case.box.pairs]
    import bisect
    pos = bisect.bisect_left(keys, case.key)
    if pos < len(keys) and keys[pos] == case.key:
        return 0, pos
    return 1, pos + (1 if flaw == "late" else 0)


def ring_actual(image, case, start):
    m = total_machine(image, {})
    m.hooks[MEMCMP_MARK] = memcmp_hook
    place_container(m, case.box, RING, RING1)
    put(m, KEY, case.key)
    m.set_reg(RDI, RING)
    m.set_reg(RSI, KEY)
    run(m, start)
    return (m.get(RAX, 8), m.get(RDX, 64)), m


# ---------------------------------------------------------------- case battery

LOOKUP_BODIES = ("state_lookup", "map_get", "state_map_a", "state_map_b")
START = dict(BODIES)


def body_consts(image, body):
    """Panic-location and Once closure constants, read from the lea instructions of the body (wrappers use map_get's panic site)."""
    lo, hi = body_extent(image, START[body])
    out = {"panic": None, "once_rcx": None, "once_r8": None}
    for reg, target in lea_targets(image, sweep(image, lo, hi)):
        key = {2: "panic", 1: "once_rcx", 8: "once_r8"}.get(reg)
        if key:
            out[key] = target
    if body.startswith("state_map"):
        out["panic"] = body_consts(image, "map_get")["panic"]
    return out


def seed_of(body):
    return int.from_bytes(hashlib.sha256(body.encode()).digest()[:8], "little")


def cases(body, count):
    rng = Lcg(seed_of(body))
    for _ in range(count):
        if body in LOOKUP_BODIES:
            yield make_lookup(rng, body)
        elif body.startswith("total"):
            yield total_case(rng)
        else:
            yield ring_case(rng)


def label_of(body, case, outcome):
    if body in LOOKUP_BODIES:
        n = len(case.rows)
        return (f"rows={n if n < 3 else '3+'} key={case.kind if n else 'none'} probe={case.mode if n > 1 else '-'} "
                f"once={int(bool(case.once))} -> {outcome}")
    if body.startswith("total"):
        return f"first={case.first.kind} second={case.second.kind} -> {outcome}"
    box = case.box
    wrap = box.head + len(box.pairs) > box.cap
    return f"rows={len(box.pairs) if len(box.pairs) < 4 else '4+'} wrap={int(wrap)} -> {outcome}"


def evaluate(image, body, case, consts, flaw=None):
    """Run the real bytes once; return (matches the rule, label, host-call signature, machine)."""
    start = START[body]
    if body in LOOKUP_BODIES:
        how, value, log, m = lookup_actual(image, case, body, start)
        expected = lookup_expected(image, case, body, consts, flaw)
        sig = "+".join(entry[0] for entry in log) or "-"
        kind = how if how != "ret" else ("default" if value in (0, default_record(image)) else "row")
        return (how, value, log) == expected, label_of(body, case, kind), sig, m
    if body.startswith("total"):
        value, m = total_actual(image, case, start)
        expected = total_expected(case, flaw)
        kind = "saturated" if value == U64 else "zero" if value == 0 else "sum"
        return value == expected, label_of(body, case, kind), "cmp" if m.log else "-", m
    value, m = ring_actual(image, case, start)
    expected = ring_expected(case, flaw)
    return value == expected, label_of(body, case, "found" if value[0] == 0 else "absent"), f"cmp{min(len(m.log), 9)}", m


def attempt(image, body, case, consts, flaw=None):
    """evaluate() that treats an evaluator refusal as a detection (the run left the modelled domain)."""
    try:
        return evaluate(image, body, case, consts, flaw)[0]
    except (ToolError, cpu.ToolError, cpu.Done, KeyError, TypeError, ValueError, OverflowError):
        return False


FLAWS = {
    "state_lookup": ("cmp16", "bound_gt", "no_default", "no_once", "recheck", "hash_for_one"),
    "map_get": ("cmp16", "bound_gt", "recheck", "hash_for_one"),
    "state_map_a": ("cmp16", "bound_gt", "no_default", "no_once"),
    "state_map_b": ("cmp16", "no_default", "no_once", "recheck"),
    "total_a": ("wrap",),
    "total_b": ("wrap",),
    "ring_search": ("late",),
}


def region(addr, image):
    d = default_record(image)
    for name, base, size in (("state", STATE, 0x10000), ("row", ROWS, 0x1000), ("key", KEY, 0x40), ("bucket", BUCKET, 0x20),
                             ("set", TOTAL, 0x100), ("ring1", RING1, 0x1000), ("ring2", RING2, 0x1000), ("ring", RING, 0x1000),
                             ("node", NODES, 0x100000), ("default", d, 0x100), ("slot", 0x64d0000, 0x100000)):
        if base <= addr < base + size:
            off = addr - base
            if name == "row":
                off %= ROW_STRIDE
            elif name in ("ring1", "ring2", "ring"):
                off %= ELEM
                name = "ring"
            elif name == "node":
                off %= 0x300
            elif name == "slot":
                return name, addr
            return name, off
    return None


def run_battery(image, entries):
    """Main battery: every case runs the real bytes and is compared with the rule."""
    summary = {"cases": 0, "mismatches": 0}
    labels, sigs, reads = collections.Counter(), collections.Counter(), collections.Counter()
    for body, _ in BODIES:
        consts = body_consts(image, body)
        for case in cases(body, CASES[body]):
            ok, label, sig, m = evaluate(image, body, case, consts)
            summary["cases"] += 1
            summary["mismatches"] += not ok
            labels[(body, label)] += 1
            sigs[(body, sig)] += 1
            for (addr, size), n in m.reads.items():
                where = region(addr, image)
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
    """(address of the patched byte, kind, new byte): every conditional branch flipped, every imm8 of imul/shift/ALU nudged."""
    lo, hi = body_extent(image, START[body])
    data, out = image.data, []
    for insn in sweep(image, lo, hi):
        key = insn.key
        if isinstance(key, int) and 0x70 <= key <= 0x7f:
            out.append((insn.va, "jcc-flip", data[insn.off] ^ 1))
        elif isinstance(key, tuple) and key[0] == 0x0f and 0x80 <= key[1] <= 0x8f:
            out.append((insn.va + 1, "jcc-flip", data[insn.off + 1] ^ 1))
        elif key in (0x83, 0xc1, 0x6b) and data[insn.modrm] & 7 != 4:
            out.append((insn.va + insn.size - 1, "imm8+1", (data[insn.off + insn.size - 1] + 1) & 0xff))
    return out


def mutant_rows(image, entries):
    rows, killed, survived = [], 0, 0
    for body, _ in BODIES:
        consts = body_consts(image, body)
        battery = list(cases(body, BATTERY))
        for va, kind, new in mutation_sites(image, body):
            old = patch(image, va, bytes([new]))
            try:
                caught = any(not attempt(image, body, case, consts) for case in battery)
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
        consts = body_consts(image, body)
        for flaw in FLAWS[body]:
            hit = any(not attempt(image, body, case, consts, flaw) for case in cases(body, 600))
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

    off = image.file_offset(START["ring_search"])
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
    case = make_lookup(rng, "map_get")
    while len(case.rows) < 2:
        case = make_lookup(rng, "map_get")
    m = build_lookup_world(image, case, "map_get", START["map_get"])
    m.set_reg(RSI, 0x1234)
    try:
        run(m, START["map_get"])
        record("map_get: key pointer outside the modelled memory is refused", False)
    except (ToolError, cpu.ToolError, KeyError):
        record("map_get: key pointer outside the modelled memory is refused", True)
    m = total_machine(image, {})
    m.set_reg(RDI, TOTAL)
    m.set_reg(RSI, KEY)
    try:
        run(m, START["total_a"])
        record("total_a: unpopulated containers are refused", False)
    except (ToolError, cpu.ToolError):
        record("total_a: unpopulated containers are refused", True)
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


def slot_rows(image):
    d = default_record(image)
    rows = [f"{SLOT_DEFAULT:#x}\trelative\t{d:#x}\tpointer to the shared default record; Once word at +0x40 is {initial_once_byte(image)} in the file",
            f"{SLOT_PANIC:#x}\trelative\t{image.slots[SLOT_PANIC]:#x}\tbounds-check panic helper",
            f"{SLOT_ONCE:#x}\trelative\t{image.slots[SLOT_ONCE]:#x}\tOnce slow-path helper",
            f"{SLOT_MEMCMP:#x}\timported\t-\tcompare of 20 bytes, sign of the result decides"]
    for hook, role in ((TARGET_HASH_STATE, "state key hash"), (TARGET_PROBE_STATE, "state bucket probe"),
                       (TARGET_HASH_MAP, "map key hash"), (TARGET_PROBE_MAP, "map bucket probe")):
        lo, hi = body_extent(image, hook)
        rows.append(f"{hook:#x}\tcode\t{hi - lo}\t{role}, stubbed")
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
