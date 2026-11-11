#!/usr/bin/env python3
"""Reconstruct the node #115 order market host checks and their lookup callees from ELF bytes.

The market-state check of the order gate (0x22e7f80) consults four host slots and a keyed map and
the previous packet only stubbed them. This tool runs the real bytes of

  0x3c11a70  check a: record key -> per-key state byte (ring or B-tree map), 1 when absent
  0x3c07600  check b: key -> B-tree set, else key -> index map -> value -> second index map
  0x3c09af0  check c: key -> A map -> B map -> C map chain, then a field of the C entry equals the first value
  0x3c4b1a0  check d: amount * 10^(kind difference) with overflow flag (bitwise power-of-ten product)
  0x2db0710  map get: u64 key -> value pointer (ring or B-tree)
  0x4556d70  ring binary search over 16-byte rows (and its twin 0x24c5280)
  0x47172c0  SipHash-1-3 of one u64 (with the real hasher write 0x45927a0 behind it)
  0x3ed2180 / 0x3ed2280 / 0x3ed2b10  hashbrown group probes for entry strides 0x18 / 0xa0 / 0x78

on the shared concrete evaluator `decimal_scaled_u64` (bytes are read, never executed natively)
and compares every run with independent pure-Python rules. Only the panic helpers are stubs.

Usage: python3 tools/order_host_checks_115.py --out <folder>
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
STEP_LIMIT = 20000
MIN64 = 1 << 63
SLOT_PANIC_CAP, SLOT_PANIC, SLOT_PANIC2, SLOT_PANIC3 = 0x64df520, 0x64df620, 0x64df830, 0x64df848
SLOT_OF = {"check_a": 0x64e4ec0, "check_b": 0x64e4ec8, "check_c": 0x64e4ed0, "check_d": 0x64e4ed8}

CTX, OUT, KEYP, NODES, RING, REC1, REC2, MAP = (0x7300_0000, 0x7320_0000, 0x7330_0000, 0x7350_0000, 0x7360_0000,
                                                0x7380_0000, 0x7390_0000, 0x73a0_0000)
IMAP = (0x7600_0000, 0x7610_0000, 0x7620_0000)
CTRL_AT = 0x4000

BODIES = (("sip_hash", 0x47172c0), ("probe_a24", 0x3ed2180), ("probe_b160", 0x3ed2280), ("probe_c120", 0x3ed2b10),
          ("ring_search_16", 0x4556d70), ("ring_search_16_twin", 0x24c5280), ("map_get", 0x2db0710),
          ("check_a", 0x3c11a70), ("check_b", 0x3c07600), ("check_c", 0x3c09af0), ("check_d", 0x3c4b1a0))
START = dict(BODIES)
CASES = {"sip_hash": 1800, "probe_a24": 3600, "probe_b160": 2700, "probe_c120": 2700, "ring_search_16": 2400,
         "ring_search_16_twin": 1800, "map_get": 3600, "check_a": 3900, "check_b": 5400, "check_c": 5400, "check_d": 4500}
BATTERY = 160          # cases per mutant run
DIV = 1                # tests divide the case counts to stay fast


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
            return (self.next() | (self.next() << 40)) & U64
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
    """Concrete evaluator plus cdqe, call-through-register, rotates and the SSE forms the probes use."""

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
        hook(self)
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        self.flags = [None, None, None, None]
        return None

    def shift(self, kind, value, count, bits):
        if kind == 0 and value is not None and count is not None:        # rol
            count &= 63 if bits == 64 else 31
            if count == 0:
                return value
            res = ((value << count) | (value >> (bits - count))) & ((1 << bits) - 1)
            self.flags = [bool(res & 1), self.flags[1], self.flags[2], None]
            return res
        return super().shift(kind, value, count, bits)

    def xmm_source(self, operand):
        if operand[0] == "r":
            return self.xmm[operand[1]]
        at = self.address(operand)
        low, high = self.load(at, 8), self.load(at + 8, 8)
        return None if low is None or high is None else struct.pack("<QQ", low, high)

    def sse(self, insn, two, here):
        data = self.image.data
        modrm = data[insn.modrm]
        reg = ((modrm >> 3) & 7) | ((insn.rex & 4) << 1)
        self.seen.add(here)
        self.pc = here + insn.size
        if two == 0xd7:                                                    # pmovmskb r32, xmm
            src = self.xmm[(modrm & 7) | ((insn.rex & 1) << 3)]
            if src is None:
                fail(f"pmovmskb of an unknown register at {here:#x}")
            self.put(reg, 32, sum(1 << i for i in range(16) if src[i] & 0x80))
            return
        operand = self.operand(insn)
        if two == 0x6e:                                                    # movd xmm, r/m32
            value = self.read(operand, 32)
            self.xmm[reg] = None if value is None else struct.pack("<I", value) + bytes(12)
            return
        if two in (0x74, 0x76) and operand == ("r", reg):                  # compare with itself: all ones
            self.xmm[reg] = b"\xff" * 16
            return
        dst, src = self.xmm[reg], self.xmm_source(operand)
        if dst is None or src is None:
            fail(f"sse op {two:#x} on an unknown register at {here:#x}")
        if two == 0x60:                                                    # punpcklbw
            self.xmm[reg] = bytes(b for i in range(8) for b in (dst[i], src[i]))
        elif two == 0x74:                                                  # pcmpeqb
            self.xmm[reg] = bytes(255 if a == b else 0 for a, b in zip(dst, src))
        elif two == 0x76:                                                  # pcmpeqd
            self.xmm[reg] = b"".join(b"\xff" * 4 if dst[i:i + 4] == src[i:i + 4] else bytes(4) for i in range(0, 16, 4))
        elif two == 0x70:
            imm = data[insn.off + insn.size - 1]
            if insn.rep == 0xf2:                                           # pshuflw
                words = [src[2 * ((imm >> (2 * i)) & 3):2 * ((imm >> (2 * i)) & 3) + 2] for i in range(4)]
                self.xmm[reg] = b"".join(words) + src[8:]
            elif insn.wide16:                                              # pshufd
                self.xmm[reg] = b"".join(src[4 * ((imm >> (2 * i)) & 3):4 * ((imm >> (2 * i)) & 3) + 4] for i in range(4))
            else:
                fail(f"pshuf form at {here:#x}")
        else:
            fail(f"sse op {two:#x} at {here:#x}")

    def step(self):
        insn = self.image.fetch(self.pc)
        key, data, here = insn.key, self.image.data, self.pc
        if key == 0x98 and insn.rex & 8:                                   # cdqe
            self.seen.add(here)
            self.pc = here + insn.size
            low = self.get(RAX, 32)
            if low is None:
                fail(f"cltq of an unknown value at {here:#x}")
            self.set_reg(RAX, low | (U64 ^ 0xffffffff) if low >> 31 else low)
            return
        if isinstance(key, tuple) and key[0] == 0x0f and len(key) == 2 and key[1] in (0x6e, 0x60, 0x70, 0x74, 0x76, 0xd7):
            self.sse(insn, key[1], here)
            return
        super().step()


def new_machine(image, hooks):
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


def panic_hook(tag):
    def hook(m):
        m.log.append(("panic", tag) + tuple(m.get(r, 64) for r in (RDI, RSI)))
        raise cpu.Done("panic", m.pc)
    return hook


def panic_hooks(image):
    return {image.slots[SLOT_PANIC_CAP]: panic_hook(0), image.slots[SLOT_PANIC]: panic_hook(1),
            image.slots[SLOT_PANIC2]: panic_hook(2), image.slots[SLOT_PANIC3]: panic_hook(3)}


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


def lea_target_at(image, va):
    insn = image.fetch(va)
    data = image.data
    if not (insn.key == 0x8d and data[insn.modrm] >> 6 == 0 and data[insn.modrm] & 7 == 5):
        fail(f"no rip-relative lea at {va:#x}")
    return va + insn.size + struct.unpack_from("<i", data, insn.off + insn.size - 4)[0]


# ---------------------------------------------------------------- SipHash-1-3 and hashbrown models

def sip13(k0, k1, word):
    """Rust DefaultHasher (SipHash-1-3) of one u64 write: 8 message bytes then the length block."""
    def rol(v, n):
        return ((v << n) | (v >> (64 - n))) & U64
    v = [k0 ^ 0x736f6d6570736575, k1 ^ 0x646f72616e646f6d, k0 ^ 0x6c7967656e657261, k1 ^ 0x7465646279746573]

    def rnd():
        v[0] = (v[0] + v[1]) & U64
        v[1] = rol(v[1], 13) ^ v[0]
        v[0] = rol(v[0], 32)
        v[2] = (v[2] + v[3]) & U64
        v[3] = rol(v[3], 16) ^ v[2]
        v[0] = (v[0] + v[3]) & U64
        v[3] = rol(v[3], 21) ^ v[0]
        v[2] = (v[2] + v[1]) & U64
        v[1] = rol(v[1], 17) ^ v[2]
        v[2] = rol(v[2], 32)
    for block in (word, 8 << 56):
        v[3] ^= block
        rnd()
        v[0] ^= block
    v[2] ^= 0xff
    for _ in range(3):
        rnd()
    return v[0] ^ v[1] ^ v[2] ^ v[3]


EMPTY, DELETED = 0xff, 0x80


class Table:
    """hashbrown control bytes plus the index word stored below them, as the probes read them."""

    def __init__(self, buckets):
        self.buckets, self.mask = buckets, buckets - 1
        self.ctrl = bytearray([EMPTY]) * (buckets + 16)
        self.slot = [0] * buckets

    def set_ctrl(self, i, value):
        self.ctrl[i] = value
        self.ctrl[((i - 16) & self.mask) + 16] = value

    def insert_slot(self, h):
        pos, stride = h & self.mask, 0
        while True:
            bits = [i for i, b in enumerate(self.ctrl[pos:pos + 16]) if b & 0x80]
            if bits:
                slot = (pos + bits[0]) & self.mask
                if not self.ctrl[slot] & 0x80:
                    slot = [i for i, b in enumerate(self.ctrl[0:16]) if b & 0x80][0]
                return slot
            stride += 16
            pos = (pos + stride) & self.mask

    def insert(self, h, index):
        slot = self.insert_slot(h)
        self.set_ctrl(slot, h >> 57)
        self.slot[slot] = index


def build_table(rng, hashes, spare):
    """Table holding entry i at hash hashes[i]; `spare` extra dead (deleted) slots."""
    n = len(hashes)
    buckets = 4
    while buckets * 7 // 8 < n + spare:
        buckets *= 2
    if rng.below(4) == 0 and buckets < 64:
        buckets *= 2
    table = Table(buckets)
    for i, h in enumerate(hashes):
        table.insert(h, i)
    for _ in range(spare):
        h = rng.next() | (rng.next() << 40) & U64
        slot = table.insert_slot(h)
        table.set_ctrl(slot, DELETED)
    return table


def place_imap(m, which, base, table, keys, vals, stride, key_off, val_off, sip_keys=None):
    """Map header at `base` (entries +8, len +0x10, ctrl +0x18, mask +0x20, siphash keys +0x38/+0x40)."""
    ent, ctrl = IMAP[which], IMAP[which] + CTRL_AT
    put_word(m, base + 8, ent)
    put_word(m, base + 0x10, len(keys))
    put_word(m, base + 0x18, ctrl)
    put_word(m, base + 0x20, table.mask if table else 0)
    if sip_keys:
        put_word(m, base + 0x38, sip_keys[0])
        put_word(m, base + 0x40, sip_keys[1])
    for i, key in enumerate(keys):
        put_word(m, ent + stride * i + key_off, key)
        if vals is not None and val_off is not None:
            put_word(m, ent + stride * i + val_off, vals[key])
    if table:
        put(m, ctrl, bytes(table.ctrl))
        for slot in range(table.buckets):
            put_word(m, ctrl - 8 * (slot + 1), table.slot[slot])


# ---------------------------------------------------------------- B-tree and ring models

LEAF_CAP = 11
LAYOUT = {"set": Box(len=0x62, edge=0x68, val=None, vsz=0), "u8": Box(len=0x62, edge=0x70, val=0x64, vsz=1),
          "u64": Box(len=0xba, edge=0xc0, val=0x60, vsz=8)}


def gen_u64_keys(rng, n):
    mode = rng.below(3)
    seen = set()
    while len(seen) < n:
        if mode == 0:
            seen.add(1 + rng.below(4 * n + 4))
        elif mode == 1:
            seen.add(rng.word() or 1)
        else:
            seen.add((1 << 40) + rng.below(3 * n + 3))
    return sorted(seen)


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


def tree_keys_of(plan):
    if plan[0] == "leaf":
        return list(plan[1])
    out = []
    for i, kid in enumerate(plan[2]):
        out += tree_keys_of(kid)
        if i < len(plan[1]):
            out.append(plan[1][i])
    return out


class Alloc:
    def __init__(self):
        self.next = NODES

    def take(self):
        at, self.next = self.next, self.next + 0x1000
        return at


ALLOC = Alloc()


def write_tree(m, plan, lay, vals, where):
    at = ALLOC.take()
    entries = plan[1]
    kids = [] if plan[0] == "leaf" else [write_tree(m, child, lay, vals, where) for child in plan[2]]
    for i, key in enumerate(entries):
        put_word(m, at + 8 + 8 * i, key)
        if lay.val is not None:
            put_word(m, at + lay.val + lay.vsz * i, vals[key], lay.vsz)
            where[key] = at + lay.val + lay.vsz * i
    put_word(m, at + lay.len, len(entries), 2)
    for i, kid in enumerate(kids):
        put_word(m, at + lay.edge + 8 * i, kid)
    return at


def make_u64_map(rng, want=None):
    kind = want or rng.pick(("empty", "ring", "ring", "ring", "tree", "tree", "tree2", "treeroot"))
    if kind == "empty":
        return Box(kind="ring", keys=[], cap=rng.below(3), head=0)
    if kind == "ring":
        n = rng.pick((1, 2, 3, 5, 8, 13))
        cap = n + rng.below(4)
        return Box(kind="ring", keys=gen_u64_keys(rng, n), cap=cap, head=rng.below(cap))
    if kind == "treeroot":
        return Box(kind="tree", keys=[], plan=None, height=0)
    height = 0 if kind == "tree" else rng.pick((1, 2))
    n = rng.pick((1, 3, 6, 11)) if height == 0 else rng.pick((9, 14, 20, 40)) if height == 1 else rng.pick((20, 40, 60))
    plan = build_tree(rng, gen_u64_keys(rng, n), height)
    return Box(kind="tree", keys=tree_keys_of(plan), plan=plan, height=height)


def place_u64_map(m, box, at, lay_name, vals, where):
    """Header (cap-or-niche, ptr-or-root, head-or-height, len) with ring rows of 16 bytes: key, value."""
    lay = LAYOUT[lay_name]
    if box.kind == "ring":
        put_word(m, at, box.cap)
        put_word(m, at + 8, RING)
        put_word(m, at + 0x10, box.head)
        put_word(m, at + 0x18, len(box.keys))
        for i, key in enumerate(box.keys):
            row = RING + 16 * ((box.head + i) % box.cap)
            put_word(m, row, key)
            put_word(m, row + 8, vals[key], max(lay.vsz, 1))
            where[key] = row + 8
    else:
        put_word(m, at, MIN64)
        put_word(m, at + 8, write_tree(m, box.plan, lay, vals, where) if box.plan else 0)
        put_word(m, at + 0x10, box.height)


def pick_key(rng, pool):
    mode = rng.pick(("in", "in", "out", "near"))
    if mode == "in" and pool:
        return rng.pick(pool)
    if mode == "near" and pool:
        return max(1, rng.pick(pool) + rng.pick((-1, 1))) & U64
    return rng.word() or 7


# ---------------------------------------------------------------- sip hash

def gen_sip(rng):
    return Box(k0=rng.word(), k1=rng.word(), word=rng.word())


def sip_eval(image, c, flaw=None):
    m = new_machine(image, panic_hooks(image))
    for r, v in ((RDI, c.k0), (RSI, c.k1), (RDX, c.word)):
        m.set_reg(r, v)
    run(m, START["sip_hash"])
    want = sip13(c.k0, c.k1 ^ (1 if flaw == "key1" else 0), c.word)
    return m.get(RAX, 64) == want, "siphash13", "-", m


# ---------------------------------------------------------------- probes

PROBE = {"probe_a24": (24, 8), "probe_b160": (160, 0x98), "probe_c120": (0x78, 0x70)}


def gen_probe(rng, body):
    n = rng.pick((1, 2, 3, 5, 7, 12, 20, 33))
    keys = gen_u64_keys(rng, n)
    mode = rng.pick(("random", "cluster", "samepos", "h2only"))
    hashes = []
    for i in range(n):
        if mode == "random":
            hashes.append(rng.next() | (rng.next() << 40) & U64)
        elif mode == "cluster":
            hashes.append(((rng.below(3) + 1) << 57) | rng.below(2))
        elif mode == "samepos":
            hashes.append((rng.below(4) << 57) | (rng.below(2) * 16))
        else:
            hashes.append(((rng.below(2) + 3) << 57) | rng.below(1 << 30))
    spare = rng.pick((0, 0, 1, 2, 4))
    table = build_table(rng, hashes, spare)
    kind = rng.pick(("hit", "hit", "hit", "miss", "miss", "bad_index"))
    which = rng.below(n)
    key, h = keys[which], hashes[which]
    if kind == "miss":
        key = rng.pick((keys[which] + 1000003, rng.word() | 1 << 62))
        while key in keys:
            key = (key + 7) & U64
        if rng.below(2):
            h = hashes[which]                 # same hash, different key: must compare keys
        else:
            h = rng.pick((0, rng.next() | (rng.next() << 40) & U64, 5 << 57))
    bad = None
    if kind == "bad_index":
        bad = which
    return Box(keys=keys, hashes=hashes, table=table, key=key, hash=h, kind=kind, bad=bad)


def probe_expected(c, flaw=None):
    if c.kind == "bad_index":
        return "panic", 1, (c.bad_value, len(c.keys))
    if c.key in c.keys and c.kind == "hit":
        return "ret", 1, c.keys.index(c.key)
    return "ret", 0, None


def probe_eval_for(body):
    stride, key_off = PROBE[body]

    def evaluate(image, c, flaw=None):
        m = new_machine(image, panic_hooks(image))
        table = c.table
        if c.kind == "bad_index":
            slot = next(s for s in range(table.buckets) if table.slot[s] == c.bad and table.ctrl[s] == c.hashes[c.bad] >> 57)
            c.bad_value = len(c.keys) + 3
            table.slot[slot] = c.bad_value
        place_imap(m, 0, MAP, table, c.keys, None, stride, key_off, None)
        put_word(m, KEYP, c.key)
        for r, v in ((RDI, MAP), (RSI, c.hash), (RDX, KEYP)):
            m.set_reg(r, v)
        how = run(m, START[body])
        exp = probe_expected(c, flaw)
        if exp[0] == "panic":
            ok = how == "panic" and m.log[-1][1:4] == (1,) + exp[2]
            return ok, "panic-bounds", "-", m
        if how != "ret" and how != "return":
            return False, "no-return", "-", m
        al = m.get(RAX, 8)
        got = (al, m.get(RDX, 64) if al else None)
        want = (exp[1], exp[2])
        if flaw == "slot_off" and want[1] is not None:
            want = (want[0], want[1] + 1)
        return got == want, f"{c.kind}-{'found' if al else 'absent'}", "-", m
    return evaluate


# ---------------------------------------------------------------- ring search twins

def ring_case(rng):
    box = make_u64_map(rng, "ring")
    while not box.keys:
        box = make_u64_map(rng, "ring")
    return Box(box=box, key=pick_key(rng, box.keys))


def ring_eval_for(body):
    def evaluate(image, c, flaw=None):
        m = new_machine(image, panic_hooks(image))
        where = {}
        place_u64_map(m, c.box, MAP, "u64", {k: k for k in c.box.keys}, where)
        put_word(m, KEYP, c.key)
        m.set_reg(RDI, MAP)
        m.set_reg(RSI, KEYP)
        run(m, START[body])
        pos = bisect.bisect_left(c.box.keys, c.key)
        found = pos < len(c.box.keys) and c.box.keys[pos] == c.key
        want = (0, pos) if found else (1, pos + (1 if flaw == "late" else 0))
        got = (m.get(RAX, 8), m.get(RDX, 64))
        wrap = c.box.head + len(c.box.keys) > c.box.cap
        return got == want, f"rows={min(len(c.box.keys), 4)} wrap={int(wrap)} -> {'found' if found else 'absent'}", "-", m
    return evaluate


# ---------------------------------------------------------------- map get

def gen_map_get(rng):
    box = make_u64_map(rng)
    vals = {k: rng.word() for k in box.keys}
    return Box(box=box, vals=vals, key=pick_key(rng, box.keys))


def map_get_eval(image, c, flaw=None):
    m = new_machine(image, panic_hooks(image))
    where = {}
    place_u64_map(m, c.box, MAP, "u64", c.vals, where)
    put_word(m, KEYP, c.key)
    m.set_reg(RDI, MAP)
    m.set_reg(RSI, KEYP)
    run(m, START["map_get"])
    want = where.get(c.key, 0)
    if flaw == "first_row" and want and c.box.kind == "ring":
        want = where[c.box.keys[0]]
    got = m.get(RAX, 64)
    label = f"{c.box.kind}{'-h' + str(c.box.height) if c.box.kind == 'tree' else ''} -> {'hit' if want else 'miss'}"
    ok = got == want and (not want or m.load(got, 8) == c.vals[c.key])
    return ok, label, "-", m


# ---------------------------------------------------------------- check a

def gen_check_a(rng):
    box = make_u64_map(rng)
    vals = {k: rng.pick((0, 0, 1, 2, 3, 255)) for k in box.keys}
    nreg = rng.pick((1, 2, 3, 5))
    regs = [pick_key(rng, box.keys) for _ in range(nreg)]
    idx = rng.below(nreg + (1 if rng.below(9) == 0 else 0))
    return Box(box=box, vals=vals, regs=regs, idx=idx, junk=rng.next())


def check_a_eval(image, c, flaw=None):
    m = new_machine(image, panic_hooks(image))
    where = {}
    put_word(m, CTX + 0x18, REC1)
    put_word(m, CTX + 0x20, len(c.regs))
    for i, reg in enumerate(c.regs):
        put_word(m, REC1 + 0x20 * i, c.junk)
        put_word(m, REC1 + 0x20 * i + 8, reg)
    place_u64_map(m, c.box, CTX + 0x2f8, "u8", c.vals, where)
    m.set_reg(RDI, CTX)
    m.set_reg(RSI, c.idx)
    how = run(m, START["check_a"])
    if c.idx >= len(c.regs):
        return how == "panic" and m.log[-1][1:4] == (1, c.idx, len(c.regs)), "panic-bounds", "-", m
    key = c.regs[c.idx]
    want = c.vals[key] if key in c.vals else 1
    if flaw == "absent0" and key not in c.vals:
        want = 0
    if flaw == "first_key":
        key = c.regs[0]
        want = c.vals[key] if key in c.vals else 1
    return how != "panic" and m.get(RAX, 8) == want, f"{c.box.kind} -> {'state' if key in c.vals else 'absent'}", "-", m


# ---------------------------------------------------------------- check d

def gen_check_d(rng):
    nrec = rng.pick((1, 2, 3, 6))
    recs = [(rng.pick((0, 0, 1, 2, 3, 6, 8, 18, 40, 100, 0xf0)), 0) for _ in range(nrec)]
    recs = [(lo, (lo + rng.pick((0, 0, 1, 2, 3, 5, 7, 8, 11, 15, 16, 17, 19, 20, 24, 31, 32, 48, 255))) & 0xff
             if rng.below(14) else rng.below(256)) for lo, _ in recs]
    idx = rng.below(nrec + (1 if rng.below(10) == 0 else 0))
    amount = rng.pick((0, 1, 2, 7, 99, 12345, rng.word(), U64 // 10, U64 // 10 + 1, U64 // 10 ** 8, U64 // 10 ** 16, U64 // 10 ** 19,
                       rng.below(1 << 20)))
    return Box(recs=recs, idx=idx, amount=amount)


def check_d_eval(image, c, flaw=None):
    m = new_machine(image, panic_hooks(image))
    put_word(m, CTX + 0x20, REC2)
    put_word(m, CTX + 0x28, len(c.recs))
    for i, (lo, hi) in enumerate(c.recs):
        m.mem[REC2 + 0x158 * i + 0x48] = lo
        m.mem[REC2 + 0x158 * i + 0x49] = hi
    for r, v in ((RDI, CTX), (RSI, c.idx), (RDX, c.amount)):
        m.set_reg(r, v)
    how = run(m, START["check_d"])
    bounds_msg, scale_msg = lea_target_at(image, 0x3c4b267), lea_target_at(image, 0x3c4b25a)
    if c.idx >= len(c.recs):
        return how == "panic" and m.log[-1][1:3] == (2, bounds_msg), "panic-index", "-", m
    lo, hi = c.recs[c.idx]
    d = (hi - lo) & 0xff
    limit = 19 if flaw != "limit18" else 18
    if hi < lo or d > limit:
        return how == "panic" and m.log[-1][1:3] == (2, scale_msg), "panic-scale" + ("-borrow" if hi < lo else "-range"), "-", m
    mult = 10 ** (d if flaw != "d_plus" else d + (1 if d == 3 else 0))
    product = c.amount * mult
    want = (1 if product < 1 << 64 else 0, product & U64)
    if flaw == "overflow_ok":
        want = (1, product & U64)
    got = (m.get(RAX, 64), m.get(RDX, 64))
    return how != "panic" and got == want, f"d={'0' if d == 0 else '1-15' if d < 16 else '16+'} -> {'ok' if want[0] else 'overflow'}", "-", m


# ---------------------------------------------------------------- check b and c (index maps)

def make_chain_maps(rng, count):
    """`count` index maps over a shared small value universe so that lookups chain."""
    universe = gen_u64_keys(rng, 14)
    maps = []
    for i in range(count):
        n = rng.pick((0, 1, 1, 2, 3, 5, 8, 12))
        keys = rng.sample_distinct(universe, n)
        sipk = (rng.word(), rng.word())
        maps.append(Box(keys=keys, sip=sipk, universe=universe))
    return maps


def sample_distinct(self, items, n):
    items = list(items)
    out = []
    while items and len(out) < n:
        out.append(items.pop(self.below(len(items))))
    return out


Lcg.sample_distinct = sample_distinct


def imap_with_table(rng, mp, stride_name):
    hashes = [sip13(mp.sip[0], mp.sip[1], key) for key in mp.keys]
    mp.table = build_table(rng, hashes, rng.pick((0, 0, 1, 3)))
    return mp


def corrupt_slot(mp, key):
    """Point the slot of `key` past the entry list; the probe must refuse it with (index, length)."""
    i = mp.keys.index(key)
    h2 = sip13(mp.sip[0], mp.sip[1], key) >> 57
    slot = next(s for s in range(mp.table.buckets) if mp.table.slot[s] == i and mp.table.ctrl[s] == h2)
    mp.table.slot[slot] = len(mp.keys) + 3
    return (len(mp.keys) + 3, len(mp.keys))


def gen_check_b(rng):
    a, b = make_chain_maps(rng, 2)
    for mp in (a, b):
        imap_with_table(rng, mp, None)
    universe = a.universe
    a.vals = {k: rng.pick(b.keys + universe[:3]) if b.keys and rng.below(3) else rng.pick(universe) for k in a.keys}
    tree_keys = sorted(rng.sample_distinct(universe, rng.pick((0, 0, 1, 3, 6, 12))))
    height = 0
    plan = None
    if tree_keys:
        height = 0 if len(tree_keys) <= LEAF_CAP else 1
        plan = build_tree(rng, tree_keys, height) if len(tree_keys) > 2 or height == 0 else ("leaf", tree_keys)
        tree_keys = tree_keys_of(plan)
    key = rng.pick(a.keys) if a.keys and rng.below(2) else rng.pick(tree_keys) if tree_keys and rng.below(4) else pick_key(rng, a.keys + universe)
    panic = None
    which = rng.pick((None, None, None, "a", "b"))
    if key not in tree_keys and key in a.keys:
        if which == "a" and len(a.keys) >= 2:
            panic = corrupt_slot(a, key)
        elif which == "b" and len(b.keys) >= 2 and a.vals[key] in b.keys:
            panic = corrupt_slot(b, a.vals[key])
    return Box(a=a, b=b, tree_keys=tree_keys, plan=plan, height=height, key=key, junk=rng.next(), panic=panic)


def check_b_expected(c, flaw=None):
    if c.key in c.tree_keys and flaw != "no_tree":
        return 1
    if not c.a.keys:
        return 0
    if c.key not in c.a.keys:
        return 0
    v = c.a.vals[c.key]
    if not c.b.keys:
        return 1
    return 2 if v in c.b.keys else (2 if flaw == "b_always" else 1)


def place_tree_set(m, plan, height, at):
    if plan is None:
        put_word(m, at, 0)
        put_word(m, at + 8, 0)
    else:
        put_word(m, at, write_tree(m, plan, LAYOUT["set"], None, {}))
        put_word(m, at + 8, height)


def check_b_eval(image, c, flaw=None):
    m = new_machine(image, panic_hooks(image))
    place_imap(m, 0, CTX, c.a.table, c.a.keys, c.a.vals, 24, 8, 0x10, c.a.sip)
    place_imap(m, 1, CTX + 0x90, c.b.table, c.b.keys, {k: 0 for k in c.b.keys}, 160, 0x98, None, c.b.sip)
    place_tree_set(m, c.plan, c.height, CTX + 0x1b8)
    m.set_reg(RDI, CTX)
    m.set_reg(RSI, c.key)
    how = run(m, START["check_b"])
    if c.panic:
        return how == "panic" and m.log[-1][1:4] == (1,) + c.panic, "panic-bounds", "-", m
    want = check_b_expected(c, flaw)
    got = m.get(RAX, 8)
    stage = "tree" if c.key in c.tree_keys else "a-miss" if c.key not in c.a.keys else "chain"
    return how != "panic" and got == want, f"{stage} -> {want}", "-", m


def gen_check_c(rng):
    a, b, cm = make_chain_maps(rng, 3)
    for mp in (a, b, cm):
        imap_with_table(rng, mp, None)
    universe = a.universe
    a.vals = {k: rng.pick(b.keys) if b.keys and rng.below(4) else rng.pick(universe) for k in a.keys}
    b.vals = {k: rng.pick(cm.keys) if cm.keys and rng.below(4) else rng.pick(universe) for k in b.keys}
    cm.vals = {k: (rng.pick(list(a.vals.values())) if a.vals and rng.below(2) else rng.pick(universe)) for k in cm.keys}
    key = rng.pick(a.keys) if a.keys and rng.below(2) else pick_key(rng, a.keys + universe)
    panic = None
    which = rng.pick((None, None, None, "a", "b", "c"))
    if key in a.keys:
        va = a.vals[key]
        if which == "a" and len(a.keys) >= 2:
            panic = corrupt_slot(a, key)
        elif which == "b" and len(b.keys) >= 2 and va in b.keys:
            panic = corrupt_slot(b, va)
        elif which == "c" and va in b.keys and b.vals[va] in cm.keys and len(cm.keys) >= 2:
            panic = corrupt_slot(cm, b.vals[va])
    return Box(a=a, b=b, c=cm, key=key, panic=panic)


def check_c_expected(c, flaw=None):
    if not c.a.keys or c.key not in c.a.keys:
        return 0, "a-miss"
    va = c.a.vals[c.key]
    if not c.b.keys or va not in c.b.keys:
        return 0, "b-miss"
    vb = c.b.vals[va]
    if not c.c.keys or vb not in c.c.keys:
        return 0, "c-miss"
    if flaw == "no_compare":
        return 1, "c-hit"
    return int(c.c.vals[vb] == va), "c-hit" if c.c.vals[vb] == va else "c-differs"


def check_c_eval(image, c, flaw=None):
    m = new_machine(image, panic_hooks(image))
    place_imap(m, 0, CTX, c.a.table, c.a.keys, c.a.vals, 24, 8, 0x10, c.a.sip)
    place_imap(m, 1, CTX + 0x48, c.b.table, c.b.keys, c.b.vals, 24, 8, 0x10, c.b.sip)
    ent, ctrl = IMAP[2], IMAP[2] + CTRL_AT
    base = CTX + 0xd8
    put_word(m, base + 8, ent)
    put_word(m, base + 0x10, len(c.c.keys))
    put_word(m, base + 0x18, ctrl)
    put_word(m, base + 0x20, c.c.table.mask)
    put_word(m, base + 0x38, c.c.sip[0])
    put_word(m, base + 0x40, c.c.sip[1])
    for i, key in enumerate(c.c.keys):
        put_word(m, ent + 0x78 * i + 0x70, key)
        put_word(m, ent + 0x78 * i + 0x30, c.c.vals[key])
    put(m, ctrl, bytes(c.c.table.ctrl))
    for slot in range(c.c.table.buckets):
        put_word(m, ctrl - 8 * (slot + 1), c.c.table.slot[slot])
    m.set_reg(RDI, CTX)
    m.set_reg(RSI, c.key)
    how = run(m, START["check_c"])
    if c.panic:
        return how == "panic" and m.log[-1][1:4] == (1,) + c.panic, "panic-bounds", "-", m
    want, label = check_c_expected(c, flaw)
    return how != "panic" and m.get(RAX, 8) == want, f"{label}", "-", m


# ---------------------------------------------------------------- battery

EVAL = {"sip_hash": sip_eval, "probe_a24": probe_eval_for("probe_a24"), "probe_b160": probe_eval_for("probe_b160"),
        "probe_c120": probe_eval_for("probe_c120"), "ring_search_16": ring_eval_for("ring_search_16"),
        "ring_search_16_twin": ring_eval_for("ring_search_16_twin"), "map_get": map_get_eval, "check_a": check_a_eval,
        "check_b": check_b_eval, "check_c": check_c_eval, "check_d": check_d_eval}
MAKE = {"sip_hash": gen_sip, "probe_a24": lambda r: gen_probe(r, "probe_a24"), "probe_b160": lambda r: gen_probe(r, "probe_b160"),
        "probe_c120": lambda r: gen_probe(r, "probe_c120"), "ring_search_16": ring_case, "ring_search_16_twin": ring_case,
        "map_get": gen_map_get, "check_a": gen_check_a, "check_b": gen_check_b, "check_c": gen_check_c, "check_d": gen_check_d}
FLAWS = {"sip_hash": ("key1",), "probe_a24": ("slot_off",), "probe_b160": ("slot_off",), "probe_c120": ("slot_off",),
         "ring_search_16": ("late",), "ring_search_16_twin": ("late",), "map_get": ("first_row",), "check_a": ("absent0", "first_key"),
         "check_b": ("no_tree", "b_always"), "check_c": ("no_compare",), "check_d": ("limit18", "d_plus", "overflow_ok")}


def seed_of(body):
    return int.from_bytes(hashlib.sha256(body.encode()).digest()[:8], "little")


def cases(body, count):
    rng = Lcg(seed_of(body))
    for _ in range(count):
        ALLOC.next = NODES
        yield MAKE[body](rng)


def attempt(image, body, case, flaw=None):
    ALLOC.next = NODES
    try:
        return EVAL[body](image, case, flaw)[0]
    except (ToolError, cpu.ToolError, cpu.Done, KeyError, TypeError, ValueError, OverflowError, IndexError, StopIteration):
        return False


REGIONS = (("ctx", CTX, 0x1000), ("out", OUT, 0x100), ("key", KEYP, 0x40), ("map", MAP, 0x100), ("ring", RING, 0x2000),
           ("node", NODES, 0x100000), ("regs", REC1, 0x1000), ("records", REC2, 0x1000),
           ("entries0", IMAP[0], CTRL_AT), ("index0", IMAP[0] + CTRL_AT - 0x400, 0x400), ("ctrl0", IMAP[0] + CTRL_AT, 0x100),
           ("entries1", IMAP[1], CTRL_AT), ("entries2", IMAP[2], CTRL_AT))


def region(addr):
    for name, base, size in REGIONS:
        if base <= addr < base + size:
            off = addr - base
            if name == "node":
                off %= 0x1000
            elif name == "ring":
                off %= 16
            elif name == "regs":
                off %= 0x20
            elif name == "records":
                off %= 0x158
            elif name.startswith("entries"):
                off %= 0x78 if name == "entries2" else 160
            elif name == "index0":
                return "index0", 0
            elif name == "ctrl0":
                return "ctrl0", 0
            return name, off
    return None


def run_battery(image, entries):
    summary = {"cases": 0, "mismatches": 0}
    labels, reads = collections.Counter(), collections.Counter()
    for body, _ in BODIES:
        for case in cases(body, CASES[body] // DIV):
            ok, label, _, m = EVAL[body](image, case)
            summary["cases"] += 1
            summary["mismatches"] += not ok
            labels[(body, label)] += 1
            for (addr, size), n in m.reads.items():
                where = region(addr)
                if where is not None:
                    reads[(body, where[0], where[1], size)] += n
    entries["cases"] = [f"{b}\t{lab}\t{n}" for (b, lab), n in sorted(labels.items())]
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
    """Conditional branches flipped and imm8 nudged, found by decoding the instruction bytes."""
    lo, hi = body_extent(image, START[body])
    data, out = image.data, []
    for insn in sweep(image, lo, hi):
        key = insn.key
        if isinstance(key, int) and 0x70 <= key <= 0x7f:
            out.append((insn.va, "jcc-flip", data[insn.off] ^ 1))
        elif isinstance(key, tuple) and key[0] == 0x0f and len(key) == 2 and 0x80 <= key[1] <= 0x8f:
            out.append((insn.va + 1, "jcc-flip", data[insn.off + 1] ^ 1))
        elif key in (0x83, 0xc1, 0x6b, 0x80) and data[insn.modrm] & 7 != 4 and key != 0xc1:
            out.append((insn.va + insn.size - 1, "imm8+1", (data[insn.off + insn.size - 1] + 1) & 0xff))
    return out


def mutant_rows(image, entries):
    rows, killed, survived = [], 0, 0
    for body, _ in BODIES:
        battery = list(cases(body, BATTERY))
        sites = mutation_sites(image, body)
        for va, kind, new in sites:
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
            hit = any(not attempt(image, body, case, flaw) for case in cases(body, 500))
            rows.append(f"{body}\t{flaw}\t{'detected' if hit else 'missed'}")
            detected += hit
            total += 1
    entries["flaws"] = rows
    return detected, total


def damage_rows(image, entries):
    rows, detected = [], 0

    def record(name, caught):
        nonlocal detected
        rows.append(f"{name}\t{'detected' if caught else 'missed'}")
        detected += bool(caught)

    off = image.file_offset(START["check_d"])
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
    for body in ("check_a", "check_d"):
        m = new_machine(image, {})
        m.set_reg(RDI, CTX)
        m.set_reg(RSI, 0)
        m.set_reg(RDX, 1)
        try:
            run(m, START[body])
            record(f"{body}: unpopulated context is refused", False)
        except (ToolError, cpu.ToolError, KeyError, cpu.Done):
            record(f"{body}: unpopulated context is refused", True)
    entries["damage"] = rows
    return detected, len(rows)


# ---------------------------------------------------------------- evidence

def function_rows(image):
    rows = []
    for body, start in BODIES:
        lo, hi = body_extent(image, start)
        off = image.file_offset(lo)
        calls = sorted({f"{insn.target:#x}" for insn in sweep(image, lo, hi) if insn.key == 0xe8})
        rows.append(f"{body}\t{lo:#x}\t{hi:#x}\t{hi - lo}\t{len(sweep(image, lo, hi))}\t{','.join(calls) or '-'}\t"
                    f"{digest(bytes(image.data[off:off + hi - lo]))}")
    return rows


def slot_rows(image):
    rows = [f"{SLOT_PANIC_CAP:#x}\trelative\t{image.slots[SLOT_PANIC_CAP]:#x}\tcapacity/probe panic helper (stub)",
            f"{SLOT_PANIC:#x}\trelative\t{image.slots[SLOT_PANIC]:#x}\tbounds-check panic helper (stub)",
            f"{SLOT_PANIC2:#x}\trelative\t{image.slots[SLOT_PANIC2]:#x}\tone-argument panic helper (stub)"]
    for name, slot in SLOT_OF.items():
        rows.append(f"{slot:#x}\trelative\t{image.slots[slot]:#x}\t{name} host slot, body run for real")
    for va, what in ((0x3c4b25a, "check_d scale panic message"), (0x3c4b267, "check_d index panic message")):
        rows.append(f"{va:#x}\tlea\t{lea_target_at(image, va):#x}\t{what}")
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
        "functions.tsv": tsv(("body", "start", "end", "bytes", "instructions", "direct calls", "sha256"), function_rows(image)),
        "slots.tsv": tsv(("address", "kind", "value", "role"), slot_rows(image)),
        "cases.tsv": tsv(("body", "class", "count"), entries["cases"]),
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
