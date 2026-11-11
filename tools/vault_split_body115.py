#!/usr/bin/env python3
"""Reconstruct the node #115 vault share-split body 0x44af2f0 from the ELF bytes and prove it against a written rule list.

The body takes the vault state object, the depositor key, two signed limits, a three word ledger context and a rate. It sums the vault
base amount (callee 0x44a9430) with one amount per member of a B-tree key set, converts total * rate to a signed integer with the Rust
saturating cast, finds the key in a per-depositor map (a sorted VecDeque of 72 byte entries or a B-tree, chosen by a niche word), weighs
the ledger balance against the split, derives a clamped share count, debits and credits the ledger and fills a 0xe0 byte result. The real
bytes of the body and of the deque binary search 0x45578e0 run in a small x86-64 evaluator (the funding rate evaluator of this
repository, extended by three vector forms); the four direct callees, six runtime slots and the memcmp call are recording stubs. A separately written rule list
predicts every result, every call and every overflow event, 28 named wrong readings must be refused, and every reached condition,
immediate and field displacement of the subject code is edited. No objdump or readelf output is parsed and the binary is never executed.
Standard library only.

    python3 tools/vault_split_body115.py --out <dir>
"""

import argparse
import collections
import hashlib
import json
import math
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import funding_rate115 as F  # noqa: E402

EvidenceError, Halt, Panicked = F.EvidenceError, F.Halt, F.Panicked
MASK, SIGN = F.MASK, F.SIGN
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = F.RAX, F.RCX, F.RDX, F.RBX, F.RSP, F.RBP, F.RSI, F.RDI
R8, R9 = F.R8, F.R9
to_float, to_bits = F.to_float, F.to_bits
F.HEAP_SIZE = 0x60000
HEAP_BASE = F.HEAP_BASE

BINARY, SHA256 = F.BINARY, F.SHA256

ENTRY, ENTRY_END = 0x44AF2F0, 0x44B04B6
SEARCH = 0x45578E0
AMT, APPLY, CREDIT, ERRNEW = 0x44A9430, 0x44AD9E0, 0x4472EA0, 0x44E0810
SLOT_EVENT, SLOT_BAL, SLOT_DEBIT, SLOT_LAZY = 0x64E4EA8, 0x64E5078, 0x64E7170, 0x64DF9F0
SLOT_PANIC, SLOT_PANIC_LEN, SLOT_MEMCMP = 0x64DF830, 0x64DF6A0, 0x64DFB50
LAZY_WORD = 0x64F01D8
MARK_BASE = 0x7700000000

MIN64, MAX64 = -(1 << 63), (1 << 63) - 1
M64 = MASK[8]
NICHE = 1 << 63
TAG_OK, TAG_NONE, TAG_SOME = 0x8000000000000005, 0x8000000000000019, 0x8000000000000007

# heap layout of one run
OUT, KEY, CTX, STATE, LEDGER, ARENA = (HEAP_BASE + off for off in (0x100, 0x200, 0x240, 0x300, 0x400, 0x1000))
USED = 0x60000
FILL = 0xC7
OUT_SIZE = 0xF0
COUNTER = 0x4A8

# state object fields
S_TAG, S_SET_ROOT, S_SET_HEIGHT, S_SET_COUNT = 0x00, 0x08, 0x10, 0x18
S_MAP_WORD, S_MAP_PTR, S_MAP_HEIGHT, S_MAP_LEN, S_RATE, S_VAULT, S_LEADER = 0x50, 0x58, 0x60, 0x68, 0x70, 0x8C, 0xA0

# overflow event sites: call VA -> location record address read from the preceding lea
EVENT_SITES = {
    "acc": 0x44AF602, "cut": 0x44B0118, "rest": 0x44B0153, "diff": 0x44B0189, "diff_again": 0x44B01C2, "round": 0x44B020C,
    "units": 0x44AFE13, "debit": 0x44B02CD, "after": 0x44B0307, "keep": 0x44B033D, "credit_leader": 0x44B0468,
    "credit_depositor": 0x44B0369, "slot3": 0x44B03A2, "gap": 0x44B03EB, "gap2": 0x44B0434,
}
SITE_NAME = {va: name for name, va in EVENT_SITES.items()}
LAZY_SITES = (0x44AF98D, 0x44B027E)
PANIC_SITES = {"set_parent": 0x44B01A5, "set_state": 0x44B02A4, "relookup": 0x44B04AE, "negative_units": 0x44B04A1}

CONSTANTS = (
    (0x459808, "cast_floor", 8), (0x459360, "cast_ceiling", 8), (0x458E50, "cast_guard", 8), (0x450E80, "scale_pair", 16),
    (0x455810, "infinity_pair", 16), (0x459BA0, "tiny", 8), (0x459010, "infinity", 8), (0x4599A0, "scale", 8),
    (0x458FA0, "minus_tiny", 8), (0x456790, "low_mask", 16), (0x454DC0, "magic_low", 16), (0x452030, "magic_high", 16),
    (0x452040, "magic_bias", 16),
)


# --------------------------------------------------------------------------------------------------------------------------------
# Evaluator extension: three vector forms the funding body never used.

_base_decode = F.decode


def decode(read, va):
    window = bytes(read(va, 16))
    at = 0
    while window[at] in (0x66, 0xF2, 0xF3, 0x2E):
        at += 1
    if 0x40 <= window[at] <= 0x4F:
        at += 1
    if window[0] == 0x66 and window[at] == 0x0F and window[at + 1] in (0x14, 0x17):
        # unpcklpd == punpcklqdq on raw bits; movhpd store is decoded as the 16 byte store and relabelled
        rewritten = bytearray(window)
        rewritten[at + 1] = 0x6C if window[at + 1] == 0x14 else 0x11
        fake = bytes(rewritten)
        row = _base_decode(lambda a, n: fake[a - va:a - va + n], va)
        if window[at + 1] == 0x17:
            row.op, row.width = "movhpd", 8
        return row
    return _base_decode(read, va)


F.decode = decode


class Machine(F.Machine):
    def __init__(self, image, patches=None):
        super().__init__(image, patches)
        self.cur = None
        self.branches = {}
        self.counts = {}

    def step(self, row):
        self.cur = row
        self.counts[row.va] = self.counts.get(row.va, 0) + 1
        result = super().step(row)
        if row.op == "jcc":
            self.branches.setdefault(row.va, [0, 0])[result == row.target] += 1
        return result

    def step_vector(self, row, op):
        if op == "movhpd":
            self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] >> 64)
        elif op == "cmppd" and row.target in (0, 3):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                one, two = to_float((left >> shift) & M64), to_float((right >> shift) & M64)
                hit = one == two if row.target == 0 else (one != one or two != two)
                if hit:
                    value |= M64 << shift
            self.xmm[row.a[1]] = value
        else:
            super().step_vector(row, op)


# --------------------------------------------------------------------------------------------------------------------------------
# Float and integer rules shared by the rule list.

def f2i(value):
    """The saturating Rust `as i64` with the body's extra rule that an infinity or NaN input becomes 0."""
    bits = to_bits(value) & 0x7FFFFFFFFFFFFFFF
    if bits > 0x7FEFFFFFFFFFFFFF:
        return 0
    if value < -9223372036854775808.0:
        value = -9223372036854775808.0
    elif value > 9223372036854775808.0:
        value = 9223372036854775808.0
    if value > 9223372036854774784.0:
        return MAX64
    return int(value)


def flt(value):
    return float(value)


def ufloat(value):
    return float(value & M64)


# --------------------------------------------------------------------------------------------------------------------------------
# Cases

class Case:
    __slots__ = ("name", "store", "items", "cap", "head", "height", "chunks", "tag", "set_keys", "set_count", "set_height", "set_chunks",
                 "key", "vault", "leader", "rate", "ratio", "limit", "other", "ctx", "amounts", "default_amount", "balances", "lazy",
                 "effect", "rewrite", "counter", "fill", "rekey", "set_shape")

    def __init__(self, **fields):
        for slot in self.__slots__:
            setattr(self, slot, fields.get(slot))
        self.chunks = self.chunks or []
        self.set_chunks = self.set_chunks or []
        self.set_keys = self.set_keys or []
        self.lazy = self.lazy or 0
        self.effect = self.effect or "none"
        self.fill = 0xC3 if self.fill is None else self.fill


def lcg(seed):
    state = seed & M64
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & M64
        yield state >> 11


def pool_keys(count, seed):
    stream = lcg(seed)
    return sorted({bytes((next(stream) % 5) * 40 + 3 + 11 * (i % 3) for i in range(20)) for _ in range(count * 3)})[:count]


KEYS = pool_keys(14, 77)


def amount_of(case, key):
    return case.amounts.get(key, case.default_amount)


# --------------------------------------------------------------------------------------------------------------------------------
# The rule list: what the body must do, written from the byte reading and checked against the bytes.

VARIANTS = (
    "cast_rounds_to_nearest", "cast_inf_saturates", "units_signed_compare", "sum_skips_set", "sum_wraps", "sum_only_set",
    "ratio_inverted", "diff_not_clamped", "gap_uses_base", "rate_on_held", "tiny_guard_dropped", "tiny_negative_divides",
    "tag_not_checked", "count_ignored", "relookup_cached", "leader_credit_always", "depositor_credit_uses_leader",
    "slot3_uses_clamped", "second_balance_ignored", "debit_unclamped", "scale_missing", "lazy_ignored", "units_borrow_wraps",
    "gap_not_subtracted", "apply_sign_flipped", "missing_is_panic", "cap_check_dropped", "round_event_dropped",
)


def cast(value, flags):
    """The body's saturating f64 -> i64 conversion."""
    if "cast_inf_saturates" in flags and value in (math.inf, -math.inf):
        return MAX64 if value > 0 else MIN64
    if "cast_rounds_to_nearest" in flags and value == value and abs(value) < 9e18:
        return int(round(value))
    return f2i(value)


def wrap64(value):
    return (value + (1 << 63)) % (1 << 64) - (1 << 63)


def spec(case, flags=frozenset()):
    """Return (outcome, log, memory) for one case. log entries are tuples in call order; memory is (counter, units, slot3)."""
    log = []
    state = {"counter": case.counter}
    book = {key: list(value) for key, value in case.items.items()}

    def event(name):
        log.append(("event", EVENT_SITES[name], LOCATION[name]))

    def ssat(value, name):
        if value > MAX64:
            event(name)
            return MAX64
        if value < MIN64:
            event(name)
            return MIN64
        return value

    def memory():
        return (state["counter"], tuple((book[k][1], book[k][2]) for k in sorted(book)))

    def finish(outcome):
        return outcome, log, memory()

    ctx = tuple(case.ctx)
    scale = 1000000.0
    log.append(("amount", ctx, case.vault))
    total = amount_of(case, case.vault)
    if "sum_only_set" in flags:
        total = 0
    walk = (case.tag == 2 or "tag_not_checked" in flags) and len(case.set_keys) > 0 and case.set_count > 0
    if walk and "sum_skips_set" not in flags:
        count = len(case.set_keys) if "count_ignored" in flags else case.set_count
        for index in range(count):
            if index >= len(case.set_keys):
                return finish(("panic", PANIC_SITES["set_parent"]))
            member = case.set_keys[index]
            log.append(("amount", ctx, member))
            added = total + amount_of(case, member)
            total = wrap64(added) if "sum_wraps" in flags else ssat(added, "acc")
    ratio = to_float(case.ratio)
    cut = cast(ratio * flt(total), flags)
    rest = ssat(total - cut, "cut")
    base = ssat(total - rest, "rest")
    entry = book.get(case.key)
    if entry is None:
        return finish(("none",) if "missing_is_panic" not in flags else ("panic", PANIC_SITES["relookup"]))
    v = to_float(entry[0])
    units_before = entry[1]
    log.append(("balance", case.ctx[0], case.vault))
    balance = case.balances[0]
    exact = base - balance
    diff = ssat(exact, "diff")
    gap = diff if "diff_not_clamped" in flags else max(diff, 0)
    if "gap_uses_base" in flags:
        gap = max(base, 0)
    if exact <= 0:
        held = base
        g = ratio
        if g > v:
            return finish(("none",))
    else:
        low, high = ufloat(base) / scale, ufloat(balance) / scale
        if 1e-15 > low:
            return finish(("none",))
        quotient = low / high if "ratio_inverted" in flags and high else high / low
        if exact > MAX64:
            event("diff_again")
        if not MIN64 <= rest + wrap64(exact) <= MAX64 and "round_event_dropped" not in flags:
            event("round")
        g = ratio * quotient
        if case.lazy and "lazy_ignored" not in flags:
            log.append(("lazy", LAZY_SITES[0]))
        if g > v:
            return finish(("none",))
        held = balance
    if units_before < 0:
        return finish(("panic", PANIC_SITES["negative_units"]))
    if to_bits(g) & 0x7FFFFFFFFFFFFFFF > 0x7FEFFFFFFFFFFFFF or to_bits(v) & 0x7FFFFFFFFFFFFFFF > 0x7FEFFFFFFFFFFFFF:
        return finish(("none",))
    tiny = 1e-15
    if g < 0:
        if g <= -tiny or v < tiny:
            return finish(("none",))
        q = g / v if "tiny_negative_divides" in flags else 0.0 / v
    else:
        if v < tiny and "tiny_guard_dropped" not in flags:
            return finish(("none",))
        q = F.fdiv(g, v)
    if to_bits(q) & 0x7FFFFFFFFFFFFFFF > 0x7FEFFFFFFFFFFFFF:
        return finish(("none",))
    units = cast(q * flt(units_before), flags)
    if case.lazy and "lazy_ignored" not in flags:
        log.append(("lazy", LAZY_SITES[1]))
    if units < 0:
        return finish(("none",))
    log.append(("balance", case.ctx[0], case.vault))
    again = case.balances[1]
    if held > again and "cap_check_dropped" not in flags and "second_balance_ignored" not in flags:
        log.append(("error", 0x34))
        return finish(("error",))
    spend = held if "debit_unclamped" in flags else max(held, 0)
    log.append(("debit", case.ctx[0], case.vault, spend))
    state["counter"] = ssat(state["counter"] - spend, "debit")
    negative = cast(g * flt(total), flags) if "apply_sign_flipped" in flags else (MAX64 if cast(g * flt(total), flags) == MIN64 else -cast(g * flt(total), flags))
    log.append(("apply", case.key, negative, total, case.other, ctx))
    if case.effect == "drop":
        book.clear()
    elif case.effect == "rewrite" and case.key in book:
        book[case.key][1], book[case.key][2] = case.rewrite
    key_now = case.rekey if case.effect == "rekey" else case.key
    entry = book.get(key_now)
    if entry is None:
        return finish(("panic", PANIC_SITES["relookup"]))
    now = units_before if "relookup_cached" in flags else entry[1]
    borrow = now < units if "units_signed_compare" in flags else (now & M64) < units
    if borrow and "units_borrow_wraps" not in flags:
        event("units")
        entry[1] = 0
    elif borrow:
        entry[1] = wrap64(now - units)
    else:
        entry[1] = wrap64((now & M64) - units)
    left = ssat(held - units, "after")
    raw = cast(flt(held if "rate_on_held" in flags else left) * to_float(case.rate), flags)
    leader = max(raw, 0)
    if raw > 0 or "leader_credit_always" in flags:
        log.append(("credit", case.ctx[0], case.leader, leader))
        state["counter"] = ssat(state["counter"] + leader, "credit_leader")
    keep = ssat(held - leader, "keep")
    paid = max(keep, 0)
    if "depositor_credit_uses_leader" in flags:
        paid = leader
    log.append(("credit", case.ctx[0], key_now, paid))
    state["counter"] = ssat(state["counter"] + paid, "credit_depositor")
    entry[2] = ssat(entry[2] - (max(keep, 0) if "slot3_uses_clamped" in flags else keep), "slot3")
    gap_a = ssat(case.limit - held, "gap")
    gap_b = gap_a if "gap_not_subtracted" in flags else ssat(gap_a - gap, "gap2")
    div = 1.0 if "scale_missing" in flags else scale
    out = {
        0: struct.pack("<Q", TAG_OK),
        8: struct.pack("<dd", flt(case.limit) / div, flt(leader) / div),
        0x18: struct.pack("<dd", flt(gap_b) / div, flt(units) / div),
        0x28: struct.pack("<d", flt(keep) / div),
        0x30: case.vault,
        0x44: key_now,
        0xB0: struct.pack("<qQ", keep, TAG_SOME if raw > 0 else TAG_NONE),
        0xC0: struct.pack("<d", flt(leader) / div),
    }
    if raw > 0:
        out[0xC8] = case.leader
    return finish(("ok", tuple(sorted(out.items()))))


LOCATION = {}   # event site name -> location record address, read from the bytes before any run


# --------------------------------------------------------------------------------------------------------------------------------
# Evaluator harness

class Arena:
    def __init__(self, memory):
        self.memory, self.top = memory, ARENA

    def alloc(self, size):
        at = self.top
        self.top = (self.top + size + 15) & ~15
        if self.top > HEAP_BASE + USED:
            raise Halt("arena exhausted")
        return at


class Harness:
    def __init__(self, image, patches=None, limit=None):
        self.image = image
        machine = Machine(image, patches)
        if limit:
            machine.step_limit = limit
        self.machine = machine
        machine.real = frozenset({SEARCH})
        for target, hook in ((AMT, self.on_amount), (APPLY, self.on_apply), (CREDIT, self.on_credit), (ERRNEW, self.on_error)):
            machine.calls[target] = hook
        statics = machine.memory.statics
        for slot, hook in ((SLOT_EVENT, self.on_event), (SLOT_BAL, self.on_balance), (SLOT_DEBIT, self.on_debit), (SLOT_LAZY, self.on_lazy),
                           (SLOT_PANIC, self.on_panic), (SLOT_PANIC_LEN, self.on_panic), (SLOT_MEMCMP, self.on_memcmp)):
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.case, self.log, self.vaddr, self.calls_seen, self.dropped = None, [], {}, 0, False

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    # stubs ------------------------------------------------------------------------------------------------------------------
    def on_amount(self, machine):
        regs, mem = machine.regs, machine.memory
        ctx = tuple(mem.read(regs[RDI] + 8 * i, 8) for i in range(3))
        key = mem.bytes_at(regs[RSI], 20)
        self.log.append(("amount", ctx, key))
        regs[RAX] = amount_of(self.case, key) & M64

    def on_balance(self, machine):
        regs = machine.regs
        key = machine.memory.bytes_at(regs[RSI], 20)
        self.log.append(("balance", regs[RDI], key))
        index = min(self.calls_seen, 1)
        self.calls_seen += 1
        regs[RAX] = self.case.balances[index] & M64

    def on_debit(self, machine):
        regs = machine.regs
        self.log.append(("debit", regs[RDI], machine.memory.bytes_at(regs[RSI], 20), self.signed(regs[RDX])))

    def on_credit(self, machine):
        regs = machine.regs
        self.log.append(("credit", regs[RDI], machine.memory.bytes_at(regs[RSI], 20), self.signed(regs[RDX])))

    def on_apply(self, machine):
        regs, mem = machine.regs, machine.memory
        ctx = tuple(mem.read(regs[R9] + 8 * i, 8) for i in range(3))
        self.log.append(("apply", mem.bytes_at(regs[RSI], 20), self.signed(regs[RDX]), self.signed(regs[RCX]), self.signed(regs[R8]), ctx))
        case = self.case
        if case.effect == "drop":
            self.dropped = True
            mem.write(STATE + S_MAP_LEN, 8, 0)
            mem.write(STATE + S_MAP_PTR, 8, 0)
        elif case.effect == "rekey":
            mem.put_bytes(KEY, case.rekey)
        elif case.effect == "rewrite" and case.key in self.vaddr:
            mem.write(self.vaddr[case.key] + 8, 8, case.rewrite[0] & M64)
            mem.write(self.vaddr[case.key] + 16, 8, case.rewrite[1] & M64)

    def on_error(self, machine):
        self.log.append(("error", machine.memory.read(machine.regs[RDI], 2)))

    def on_event(self, machine):
        self.log.append(("event", machine.cur.va, machine.regs[RSI]))

    def on_lazy(self, machine):
        regs, mem = machine.regs, machine.memory
        self.expect(regs[RDI] == LAZY_WORD and regs[RSI] == 1 and regs[RCX] == 0x63FE250 and regs[R8] == 0x63FE278, "lazy call arguments")
        self.expect(mem.read(mem.read(regs[RDX], 8), 8) == 0x64F01C0, "lazy closure environment")
        self.log.append(("lazy", machine.cur.va))

    def on_panic(self, machine):
        if machine.cur.va == PANIC_SITES["negative_units"]:
            self.expect(machine.regs[RSI] == 0x2B, "message length")
        raise Panicked(str(machine.cur.va))

    def on_memcmp(self, machine):
        regs, mem = machine.regs, machine.memory
        self.expect(regs[RDX] == 20, "memcmp length")
        left, right = mem.bytes_at(regs[RDI], 20), mem.bytes_at(regs[RSI], 20)
        result = 0
        for a, b in zip(left, right):
            if a != b:
                result = a - b
                break
        regs[RAX] = result & MASK[4]

    @staticmethod
    def signed(value):
        return value - (1 << 64) if value & SIGN[8] else value

    # memory image -----------------------------------------------------------------------------------------------------------
    def build_set(self, arena, shape, height):
        memory = self.machine.memory
        keys, children = shape
        node = arena.alloc(0xE8 + 8 * (len(keys) + 1) + 8 if children is not None else 0xF0)
        memory.put_bytes(node, bytes((0xE8 + 8 * (len(keys) + 1) + 8 if children is not None else 0xF0) * [self.case.fill]))
        memory.write(node, 8, 0)
        for index, key in enumerate(keys):
            memory.put_bytes(node + 8 + 20 * index, key)
        memory.write(node + 0xE6, 2, len(keys))
        if children is not None:
            for index, child in enumerate(children):
                address = self.build_set(arena, child, height - 1)
                memory.write(node + 0xE8 + 8 * index, 8, address)
                memory.write(address, 8, node)
                memory.write(address + 0xE4, 2, index)
        return node

    def build_map_node(self, arena, shape, height):
        memory = self.machine.memory
        keys, children = shape
        node = arena.alloc(0x360)
        memory.put_bytes(node, bytes(0x360 * [self.case.fill]))
        for index, (key, value) in enumerate(keys):
            memory.put_bytes(node + 0x218 + 20 * index, key)
            self.write_value(node + 0x30 * index, key, value)
        memory.write(node + 0x2F6, 2, len(keys))
        if children is not None:
            for index, child in enumerate(children):
                memory.write(node + 0x2F8 + 8 * index, 8, self.build_map_node(arena, child, height - 1))
        return node

    def write_value(self, address, key, value):
        memory = self.machine.memory
        memory.write(address, 8, value[0])
        memory.write(address + 8, 8, value[1] & M64)
        memory.write(address + 16, 8, value[2] & M64)
        self.vaddr[key] = address

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [F.POISON | F.POISON << 64] * 16
        self.case, self.log, self.vaddr, self.calls_seen, self.dropped = case, [], {}, 0, False
        memory.put_bytes(OUT, bytes([FILL]) * OUT_SIZE)
        memory.put_bytes(STATE, bytes((0x30 + 3 * index) & 0xFF for index in range(0xC0)))
        memory.put_bytes(LEDGER, bytes((0x50 + index) & 0xFF for index in range(0x4C0)))
        memory.put_bytes(KEY, case.key)
        for index, word in enumerate(case.ctx):
            memory.write(CTX + 8 * index, 8, word)
        arena = Arena(memory)
        memory.write(LEDGER + COUNTER, 8, case.counter & M64)
        memory.write(STATE + S_TAG, 4, case.tag)
        memory.put_bytes(STATE + S_VAULT, case.vault)
        memory.put_bytes(STATE + S_LEADER, case.leader)
        memory.write(STATE + S_RATE, 8, case.rate)
        memory.statics[LAZY_WORD] = case.lazy
        # the key set
        if case.set_keys:
            shape = case.set_shape or F.split_tree(sorted(case.set_keys), case.set_height, list(case.set_chunks))
            root = self.build_set(arena, shape, case.set_height)
            memory.write(STATE + S_SET_ROOT, 8, root)
        else:
            memory.write(STATE + S_SET_ROOT, 8, 0)
        memory.write(STATE + S_SET_HEIGHT, 8, case.set_height)
        memory.write(STATE + S_SET_COUNT, 8, case.set_count)
        # the per-depositor map
        items = sorted(case.items.items())
        if case.store == "ring":
            ring = arena.alloc(72 * case.cap + 16)
            for physical in range(case.cap):
                memory.put_bytes(ring + 72 * physical, bytes([case.fill ^ 0x5E]) * 72)
            for index, (key, value) in enumerate(items):
                at = ring + 72 * ((case.head + index) % case.cap)
                memory.put_bytes(at, key)
                self.write_value(at + 0x18, key, value)
            for offset, word in ((0, case.cap), (8, ring), (0x10, case.head), (0x18, len(items))):
                memory.write(STATE + S_MAP_WORD + offset, 8, word)
        else:
            if items:
                shape = F.split_tree(items, case.height, list(case.chunks))
                root = self.build_map_node(arena, shape, case.height)
            else:
                root = 0
            for offset, word in ((0, NICHE), (8, root), (0x10, case.height), (0x18, len(items))):
                memory.write(STATE + S_MAP_WORD + offset, 8, word)
        return None

    def run(self, case):
        self.fresh(case)
        machine = self.machine
        memory = machine.memory
        machine.xmm[0] = case.ratio
        try:
            machine.run(ENTRY, {RDI: OUT, RSI: STATE, RDX: KEY, RCX: case.limit & M64, R8: case.other & M64, R9: CTX})
        except Panicked as problem:
            return ("panic", int(str(problem))), self.log, self.final_memory(case)
        out = memory.bytes_at(OUT, OUT_SIZE)
        tag = struct.unpack_from("<Q", out)[0]
        mem = self.final_memory(case)
        if tag == TAG_NONE:
            if any(self.log[-1:]) and self.log[-1][0] == "error":
                return ("error",), self.log, mem
            return ("none",), self.log, mem
        self.expect(tag == TAG_OK, "unknown result tag %#x" % tag)
        some = struct.unpack_from("<Q", out, 0xB8)[0] == TAG_SOME
        pieces = {}
        for offset, size in ((0, 8), (8, 16), (0x18, 16), (0x28, 8), (0x30, 20), (0x44, 20), (0xB0, 16), (0xC0, 8)):
            pieces[offset] = out[offset:offset + size]
        if some:
            pieces[0xC8] = out[0xC8:0xDC]
        covered = bytearray(OUT_SIZE)
        for offset, data in pieces.items():
            covered[offset:offset + len(data)] = bytes([1]) * len(data)
        for offset in range(OUT_SIZE):
            if not covered[offset] and not (0xC8 <= offset < 0xDC) and offset >= 0x58 and out[offset] != FILL and offset < 0xB0:
                raise Halt("byte written outside the result fields at %#x" % offset)
        return ("ok", tuple(sorted(pieces.items()))), self.log, mem

    def final_memory(self, case):
        memory = self.machine.memory
        counter = self.signed(memory.read(LEDGER + COUNTER, 8))
        if self.dropped:
            return (counter, ())
        return (counter, tuple((self.signed(memory.read(self.vaddr[k] + 8, 8)), self.signed(memory.read(self.vaddr[k] + 16, 8)))
                               for k in sorted(self.vaddr)))


# --------------------------------------------------------------------------------------------------------------------------------
# Case generation

NAN = float("nan")
INF = float("inf")
RATIOS = (0.25, 0.5, 0.0, 1.0, 0.123456789, -0.25, 1.5, NAN, INF, -INF, 1e300, 1e-300, 0.9, 0.01, 0.75, 0.3, 0.6, -1e-16, -3e-16)
VALUES = (0.5, 0.9, 1.0, 0.3, 0.0, 1e-16, 1e-15, 2.0, NAN, INF, 0.05, 0.12, -0.5, 100.0, 0.7, 0.8)
UNITS = (1000, 5000, 0, 1, 10 ** 9, 1 << 40, MAX64, -1, 7, 123456, 3, 99999)
SLOTS3 = (0, 123, 10 ** 6, MIN64, MAX64, -5, 4000, 77)
RATES = (0.1, 0.5, 0.0, 0.02, 1.0, -0.1, NAN, INF, 1e-9, 0.3, 0.25, 2.0, 3.5, 1e12, 1e300)
COUNTERS = (0, 10 ** 9, MIN64 + 5, MAX64 - 5, -100, 42, MAX64)
BIG = (MAX64, MIN64, 1 << 62, -(1 << 62), MAX64 - 1, MIN64 + 1, 0, 1, -1)


def pick(stream, options):
    return options[next(stream) % len(options)]


def make_case(index, stream):
    typical = next(stream) % 100 < 55
    members = [KEYS[i] for i in range(len(KEYS)) if next(stream) % 3 == 0][:12]
    if next(stream) % 9 == 0:
        members = []
    vault = pick(stream, KEYS)
    leader = pick(stream, KEYS)
    amounts = {}
    for key in KEYS:
        if typical:
            amounts[key] = (1 + next(stream) % 9) * 1000000 * (1 + next(stream) % 40)
        else:
            amounts[key] = pick(stream, (0, 1, -1, 1000000, 5000000, 123456789, -1000000, 1 << 61, MAX64, MIN64, 3 << 60, 77))
    default_amount = pick(stream, (0, 1000000, 2500000, -5, 7)) if typical else pick(stream, BIG + (1000000,))
    tag = 2 if next(stream) % 100 < 85 else pick(stream, (0, 1, 3))
    count = len(members)
    roll = next(stream) % 100
    if roll < 6:
        count += 1
    elif roll < 14 and count:
        count = next(stream) % count
    elif roll < 18:
        count = 0
    set_height = 0
    if len(members) >= 12 and next(stream) % 2:
        set_height = 2
    elif len(members) >= 5 and next(stream) % 2:
        set_height = 1
    if len(members) > 11 and set_height == 0:
        set_height = 1
    set_chunks = [2 + next(stream) % 3 for _ in range(4)] if set_height else []
    ratio = to_bits(pick(stream, RATIOS[:6] + RATIOS[11:] if typical else RATIOS))
    # the map: pool subset
    present = [key for key in KEYS if next(stream) % 3 == 0]
    key = pick(stream, KEYS)
    if next(stream) % 100 < 88 and key not in present:
        present.append(key)
    present = sorted(present)[:13]
    if key not in present and next(stream) % 100 < 88:
        present = sorted(present[:12] + [key])
    items = {}
    for stored in present:
        value = to_bits(pick(stream, VALUES[:5] + VALUES[10:] if typical else VALUES))
        items[stored] = (value, pick(stream, UNITS[:3] + UNITS[8:] if typical else UNITS), pick(stream, SLOTS3))
    store = "ring" if next(stream) % 2 else "tree"
    cap = max(1, len(items) + next(stream) % 4)
    head = next(stream) % cap
    height = 0
    if len(items) >= 12 and next(stream) % 2:
        height = 2
    elif len(items) >= 5 and next(stream) % 2:
        height = 1
    if len(items) > 11 and height == 0:
        height = 1
    chunks = [2 + next(stream) % 3 for _ in range(4)] if height else []
    guess = amounts.get(vault, default_amount) if vault in amounts else default_amount
    guess += sum(amounts.get(k, default_amount) for k in members[:count]) if tag == 2 and count else 0
    guess = max(MIN64, min(MAX64, guess))
    cut = f2i(to_float(ratio) * flt(guess))
    if typical:
        b0 = pick(stream, (0, cut // 3, cut // 2, cut - 1, cut + 1, cut * 2, 5, cut // 4, -7, guess // 7, 1000000))
    else:
        b0 = pick(stream, (0, cut // 3, cut // 2, cut, cut + 1, cut * 2, -cut, MIN64, MAX64, -7, 1 << 62, -(1 << 62), guess // 2, guess))
    b0 = max(MIN64, min(MAX64, b0))
    b1 = pick(stream, (b0, b0, b0, b0, b0 + 1 if b0 < MAX64 else b0, b0 - 1 if b0 > MIN64 else b0, b0 * 2 if abs(b0) < 1 << 61 else b0))
    limit = pick(stream, (guess * 2, guess, 10 ** 12, 0, -5, 123456789, MAX64, MIN64, cut + 5, b0 + 1000))
    limit = max(MIN64, min(MAX64, limit))
    other = pick(stream, BIG + (12345, -777))
    effect_roll = next(stream) % 100
    effect = "drop" if effect_roll < 4 else "rewrite" if effect_roll < 14 else "rekey" if effect_roll < 22 else "none"
    rewrite = (pick(stream, UNITS + (MAX64, 0, 10)), pick(stream, SLOTS3))
    return Case(
        name="r%05d" % index, store=store, items=items, cap=cap, head=head, height=height, chunks=chunks, tag=tag, set_keys=sorted(members),
        set_count=count, set_height=set_height, set_chunks=set_chunks, key=key, vault=vault, leader=leader, rate=to_bits(pick(stream, RATES)),
        ratio=ratio, limit=limit, other=other, ctx=(LEDGER, next(stream) & M64, next(stream) & M64), amounts=amounts,
        default_amount=default_amount, balances=(b0, b1), lazy=1 if next(stream) % 100 < 20 else 0, effect=effect, rewrite=rewrite,
        counter=pick(stream, COUNTERS), fill=pick(stream, (0xC3, 0x00, 0xFF, 0x5A)), rekey=pick(stream, KEYS),
    )


def random_cases(count, seed=0xC0FFEE01):
    stream = lcg(seed)
    for index in range(count):
        yield make_case(index, stream)


def named_cases():
    """Hand built cases that pin the clean paths and the single edge each rule list line turns on."""
    base = dict(store="ring", items={KEYS[3]: (to_bits(0.9), 5000, 4000)}, cap=2, head=1, height=0, chunks=[], tag=2, set_keys=[KEYS[1], KEYS[5]],
                set_count=2, set_height=0, set_chunks=[], key=KEYS[3], vault=KEYS[0], leader=KEYS[7], rate=to_bits(0.1), ratio=to_bits(0.25),
                limit=100000000, other=5, ctx=(LEDGER, 11, 22), amounts={KEYS[0]: 4000000, KEYS[1]: 3000000, KEYS[5]: 1000000},
                default_amount=0, balances=(1000000, 1000000), lazy=0, effect="none", rewrite=(0, 0), counter=10 ** 9)

    def make(name, **changes):
        fields = dict(base)
        fields.update(changes)
        return Case(name=name, **fields)

    out = [make("clean-ring"), make("clean-tree", store="tree"),
           make("balance-covers-cut", balances=(3000000, 3000000)),
           make("balance-zero", balances=(0, 0)),
           make("second-balance-smaller", balances=(1000000, 999999)),
           make("lazy-flag", lazy=1),
           make("missing-key", key=KEYS[9]),
           make("effect-drop", effect="drop"), make("effect-drop-tree", effect="drop", store="tree"),
           make("effect-rewrite", effect="rewrite", rewrite=(2, 9)),
           make("tag-other", tag=3), make("count-short", set_count=1), make("count-long", set_count=3), make("no-members", set_keys=[], set_count=0),
           make("zero-vault", amounts={}, default_amount=0, set_keys=[], set_count=0),
           make("rate-zero", rate=to_bits(0.0)), make("leader-credit", rate=to_bits(0.5)),
           make("negative-units", items={KEYS[3]: (to_bits(0.9), -1, 4000)})]
    two = {KEYS[3]: (to_bits(0.9), 5000, 4000), KEYS[6]: (to_bits(0.8), 300, 9)}
    out += [make("rekey-present-ring", items=two, effect="rekey", rekey=KEYS[6]),
            make("rekey-present-tree", items=two, store="tree", effect="rekey", rekey=KEYS[6]),
            make("rekey-missing-ring", items=two, effect="rekey", rekey=KEYS[9]),
            make("rekey-missing-tree", items=two, store="tree", effect="rekey", rekey=KEYS[9]),
            make("min-cast", amounts={KEYS[0]: MIN64}, set_keys=[], set_count=0, ratio=to_bits(1.5), items={KEYS[3]: (to_bits(2.0), 5000, 4000)},
                 balances=(1 << 62, 1 << 62)),
            make("max-cast", amounts={KEYS[0]: MAX64}, set_keys=[], set_count=0, ratio=to_bits(1.5), items={KEYS[3]: (to_bits(2.0), 5000, 4000)},
                 balances=(1 << 62, 1 << 62))]
    wide = [b"\x07" * 18 + index.to_bytes(2, "big") for index in range(255)]
    huge = [b"\x07" * 18 + index.to_bytes(2, "big") for index in range(511)]
    out += [make("deep9-set-root", set_keys=huge, set_count=300, set_height=9, set_shape=complete_shape(huge, 9)),
            make("deep9-set-all", set_keys=huge, set_count=511, set_height=9, set_shape=complete_shape(huge, 9))]
    out += [make("deep-set-all", set_keys=wide, set_count=255, set_height=8, set_shape=complete_shape(wide, 8)),
            make("deep-set-part", set_keys=wide, set_count=129, set_height=8, set_shape=complete_shape(wide, 8)),
            make("deep-set-over", set_keys=wide, set_count=256, set_height=8, set_shape=complete_shape(wide, 8)),
            make("deep-set-wide-leaf", set_keys=wide[:127], set_count=127, set_height=6, set_shape=complete_shape(wide[:127], 6))]
    return out


def complete_shape(keys, height):
    """A tree whose internal nodes hold one key each and whose leaves are empty: the smallest image with `height` levels."""
    if height == 0:
        return (list(keys), None)
    middle = len(keys) // 2
    return ([keys[middle]], [complete_shape(keys[:middle], height - 1), complete_shape(keys[middle + 1:], height - 1)])


# --------------------------------------------------------------------------------------------------------------------------------
# Comparison drivers

def run_case(harness, case):
    try:
        return harness.run(case)
    except (Halt, EvidenceError, struct.error, ValueError, IndexError, KeyError, OverflowError, ZeroDivisionError) as problem:
        return ("halt", str(problem)), [], None


def check_stream(harness, cases, variants=(), keep=0, hits=None):
    stats = {"cases": 0, "mismatches": 0, "first_mismatch": None, "kinds": collections.Counter(), "stores": collections.Counter()}
    caught = {name: [0, None] for name in variants}
    rows = []
    for index, case in enumerate(cases):
        got = run_case(harness, case)
        expected = spec(case)
        stats["cases"] += 1
        kind = expected[0][0] if expected[0][0] != "panic" else "panic:%s" % hex(expected[0][1])
        stats["kinds"][kind] += 1
        stats["stores"][case.store] += 1
        if got != expected:
            stats["mismatches"] += 1
            if stats["first_mismatch"] is None:
                stats["first_mismatch"] = (index, case.name, got, expected)
        for name in variants:
            if spec(case, frozenset((name,))) != got:
                caught[name][0] += 1
                if caught[name][1] is None:
                    caught[name][1] = index
        if hits is not None:
            hits.update(harness.machine.seen)
        if keep and index % keep == 0:
            rows.append((index, case.name, case.store, case.tag, case.set_count, len(case.set_keys), kind, len(harness.log),
                         hashlib.sha256(repr(got).encode()).hexdigest()[:12]))
    return stats, caught, rows


# --------------------------------------------------------------------------------------------------------------------------------
# Byte level controls

def entry_extents(image):
    return (image.exact_fde(ENTRY), image.exact_fde(SEARCH))


def mutants_of(image, reached):
    out = []
    for start, end in entry_extents(image):
        for row in F.decode_range(image, start, end):
            if row.va not in reached:
                continue
            data = row.data
            if row.op == "jcc":
                at = 0 if 0x70 <= data[0] <= 0x7F else 1
                out.append((row.va, "condition", row.va + at, data[at], data[at] ^ 1))
                continue
            if row.imm_at is not None and row.imm_size in (1, 4) and row.op not in ("call", "jmp"):
                out.append((row.va, "immediate", row.va + row.imm_at, data[row.imm_at], data[row.imm_at] ^ 1))
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is not None and 0x20 <= abs(operand[4]) < 0x400:
                    disp = operand[4]
                    packed = struct.pack("<i", disp) if abs(disp) >= 128 else struct.pack("<b", disp)
                    spot = bytes(data).find(packed)
                    if spot >= 0 and bytes(data).count(packed) == 1:
                        out.append((row.va, "displacement", row.va + spot, data[spot], data[spot] ^ 8))
    return out


def run_mutants(image, mutants, cases):
    rows = []
    expected = [spec(case) for case in cases]
    for va, kind, at, old, new in mutants:
        harness = Harness(image, {at: new}, limit=60000)
        killed, first = False, ""
        for index, case in enumerate(cases):
            if run_case(harness, case) != expected[index]:
                killed, first = True, "%d" % index
                break
        rows.append((va, kind, at, old, new, killed, first))
    return rows


def locations(image):
    """Read the overflow event sites from the bytes: the lea rsi before each call through the event slot."""
    rows = list(F.decode_range(image, *image.exact_fde(ENTRY)))
    out = {}
    for position, row in enumerate(rows):
        if row.op == "calli" and row.a[0] == "m" and row.a[4] == SLOT_EVENT:
            for earlier in reversed(rows[:position]):
                if earlier.op == "lea" and earlier.a == ("r", RSI):
                    out[row.va] = earlier.b[4]
                    break
    return out


def structural_controls(image, harness, cases):
    out = []

    def raises(name, thunk, *errors):
        try:
            thunk()
        except errors or (EvidenceError,) as problem:
            out.append((name, True, type(problem).__name__))
            return
        out.append((name, False, "no error"))

    clean = cases[0]
    raises("wrong image digest", lambda: F.load_image(BINARY, "0" * 64), EvidenceError)
    raises("mid-function address is not an FDE start", lambda: image.exact_fde(ENTRY + 1), EvidenceError)
    raises("address in a NOBITS section has no file bytes", lambda: image.offset(image.named[".bss"]["address"] + 8), EvidenceError)
    raises("decoder refuses a window that ends inside the body", lambda: F.decode_range(image, ENTRY, image.exact_fde(ENTRY)[1] - 1), EvidenceError)
    raises("truncated section table", lambda: F.Image(bytes(image.blob[:48])), Exception)
    plain = Harness(image)
    plain.machine.real = frozenset()
    raises("binary search not run as real code", lambda: plain.run(clean), Halt)
    stripped = Harness(image)
    del stripped.machine.calls[AMT]
    raises("amount callee without a model", lambda: stripped.run(clean), Halt)
    trapped = Harness(image, {ENTRY: 0xCC})
    raises("entry byte replaced by int3", lambda: trapped.run(clean), Halt)
    spun = Harness(image, {0x44AF3D3: 0xEB, 0x44AF3D4: 0xFE}, limit=3000)
    raises("endless loop is cut by the step limit", lambda: spun.run(clean), Halt)

    changed = dict(LOCATION)
    changed["acc"] ^= 8
    saved = dict(LOCATION)
    LOCATION.update(changed)
    try:
        wide = [case for case in cases if case.name == "clean-ring"][0]
        wide = Case(**{slot: getattr(wide, slot) for slot in Case.__slots__ if slot != "amounts"}, amounts={**wide.amounts, wide.vault: MAX64, wide.set_keys[0]: 5})
        out.append(("tampered event location is refused", run_case(harness, wide) != spec(wide), "mismatch"))
    finally:
        LOCATION.clear()
        LOCATION.update(saved)
    return out


# --------------------------------------------------------------------------------------------------------------------------------
# Evidence tables

def hexa(value):
    return "0x%x" % value


def constant_rows(image):
    out = []
    for va, name, size in CONSTANTS:
        data = bytes(image.blob[image.offset(va):image.offset(va) + size])
        if size == 8:
            out.append((hexa(va), name, data.hex(), repr(to_float(int.from_bytes(data, "little")))))
        else:
            low, high = (to_float(int.from_bytes(data[i:i + 8], "little")) for i in (0, 8))
            out.append((hexa(va), name, data.hex(), "%r|%r" % (low, high) if name != "low_mask" else "lane masks"))
    return out


def callee_rows(image):
    rows = list(F.decode_range(image, *image.exact_fde(ENTRY)))
    names = {AMT: "amount of one key (vault base or set member)", APPLY: "apply the split to the vault state", CREDIT: "credit a key on the ledger",
             ERRNEW: "build the 0x34 error value", SEARCH: "deque binary search over 72 byte entries (run as real code)"}
    slot_names = {SLOT_EVENT: "overflow event with a Location record", SLOT_BAL: "ledger balance of a key", SLOT_DEBIT: "ledger debit of a key",
                  SLOT_LAZY: "one-time initialisation call guarded by the word at 0x64f01d8", SLOT_PANIC: "panic with a message record",
                  SLOT_PANIC_LEN: "panic on a failed integer conversion", SLOT_MEMCMP: "memcmp of 20 byte keys (indirect call)"}
    relative = image.relative()
    out = []
    for row in rows:
        if row.op == "call":
            out.append((hexa(row.va), "direct", hexa(row.target), names.get(row.target, "unnamed")))
        elif row.op == "calli" and row.a[0] == "m":
            slot = row.a[4]
            out.append((hexa(row.va), "slot", hexa(slot), slot_names.get(slot, "unnamed"), hexa(relative.get(slot, 0))))
        elif row.op == "calli":
            out.append((hexa(row.va), "register", "rbx or r15 loaded from slot 0x64dfb50", slot_names[SLOT_MEMCMP]))
    return out


def site_rows(image, sites):
    relative = image.relative()
    out = []
    for name, va in sorted(EVENT_SITES.items(), key=lambda item: item[1]):
        location = sites[va]
        try:
            path, line, column = image.location(location, relative)
        except (EvidenceError, UnicodeDecodeError, struct.error, KeyError):
            path, line, column = "?", 0, 0
        out.append((name, hexa(va), hexa(location), path, line, column))
    return out


def layout_rows():
    return (
        ("state", "0x00", "u32", "set tag: the key set is walked only when it is 2", "0x44af376"),
        ("state", "0x08", "ptr", "key set B-tree root", "0x44af392"),
        ("state", "0x10", "u64", "key set height", "0x44af3b1"),
        ("state", "0x18", "u64", "key set length: the number of members visited", "0x44af396"),
        ("state", "0x50", "u64", "depositor map word: capacity of the VecDeque, or 0x8000000000000000 for a B-tree", "0x44af6d7"),
        ("state", "0x58", "ptr", "deque buffer pointer, or B-tree root", "0x44af6f8"),
        ("state", "0x60", "u64", "deque head, or B-tree height", "0x44af705"),
        ("state", "0x68", "u64", "deque length", "0x44af7bd"),
        ("state", "0x70", "f64", "rate applied to the remainder to size the leader credit", "0x44afe41"),
        ("state", "0x8c", "[u8;20]", "vault key: amount base, ledger balance key, debit key", "0x44af35c"),
        ("state", "0xa0", "[u8;20]", "leader key: receives the leader credit", "0x44afec6"),
        ("set node", "0x00", "ptr", "parent", "0x44afe..."),
        ("set node", "0x08 + 20*i", "[u8;20]", "member key i (11 slots)", "0x44af57e"),
        ("set node", "0xe4", "u16", "index in parent", "0x44af4bf"),
        ("set node", "0xe6", "u16", "length", "0x44af3de"),
        ("set node", "0xe8 + 8*i", "ptr", "edge i (12 slots)", "0x44af420"),
        ("map node", "0x30*i", "value", "f64 at +0, i64 units at +8, i64 slot3 at +0x10", "0x44af7ee"),
        ("map node", "0x210", "ptr", "parent (never read by the body)", ""),
        ("map node", "0x218 + 20*i", "[u8;20]", "key i (11 slots)", "0x44af715"),
        ("map node", "0x2f6", "u16", "length", "0x44af71c"),
        ("map node", "0x2f8 + 8*i", "ptr", "edge i", "0x44af79e"),
        ("deque entry", "0x00", "[u8;20]", "key (72 byte stride)", "0x45579c1"),
        ("deque entry", "0x18", "value", "f64 at +0x18, i64 units at +0x20, i64 slot3 at +0x28", "0x44af7db"),
        ("ledger", "0x4a8", "i64", "running counter the body debits and credits", "0x44afbc3"),
        ("result", "0x00", "u64", "0x8000000000000005 when a split was made, 0x8000000000000019 for the empty variant", "0x44af9b0"),
        ("result", "0x08", "f64 x2", "limit / 1e6, leader credit / 1e6", "0x44b008e"),
        ("result", "0x18", "f64 x2", "remaining gap / 1e6, share units / 1e6", "0x44b0095"),
        ("result", "0x28", "f64", "kept amount / 1e6", "0x44b009c"),
        ("result", "0x30", "[u8;20]", "vault key copy", "0x44b00ab"),
        ("result", "0x44", "[u8;20]", "depositor key copy", "0x44b0080"),
        ("result", "0xb0", "i64", "kept amount", "0x44b00bd"),
        ("result", "0xb8", "u64", "Option tag of the leader record: 0x8000000000000007 present, 0x8000000000000019 absent", "0x44b00c5"),
        ("result", "0xc0", "f64", "leader credit / 1e6", "0x44b00cd"),
        ("result", "0xc8", "[u8;20]", "leader key copy (written only when the leader record is present)", "0x44b00df"),
    )


# --------------------------------------------------------------------------------------------------------------------------------
# Equivalent mutants (hand analysed; every survivor must appear here or the tool fails)

CLAMP = ("The edit changes only which side of the redundant bound test of the saturating cast is taken: the lower bound is -2^63, where "
         "cvttsd2si already returns 0x8000000000000000, and the upper test is repeated by the cmova against 0x43dfffffffffffff, so every "
         "finite input still gives the same integer.")
DEQUE_UNUSED = ("This path of the deque search returns the not-found flag 1 (or the index of an empty ring), and the body reads the index "
                "only after a found flag and a bound check against the length, so the changed value is never consumed.")
EQUIVALENT = {
    0x44AF438: "This compare runs only after a remainder loop for a height whose low three bits are not zero, so the height is never exactly 8, "
               "the only value where comparing with 9 instead of 8 changes the branch (height 8 takes the other path at 0x44af413).",
    0x44AF51B: "This compare runs only after the remainder loop of a climb whose low three bits are not zero, so the climb length is never exactly "
               "8, the only value where comparing with 9 instead of 8 changes the branch (length 8 takes the other path at 0x44af4ee).",
    0x44AF557: "The lea feeds the next iteration of the 8-way unrolled edge walk, which runs twice only when a walk climbs at least 16 levels; "
               "a B-tree whose nodes hold at least 5 keys needs more than 6^16 leaves for that, which no machine can store.",
    0x44AF65A: CLAMP, 0x44AF664: CLAMP, 0x44AFADD: CLAMP, 0x44AFAE7: CLAMP, 0x44AFC49: CLAMP, 0x44AFC53: CLAMP, 0x44AFE6E: CLAMP, 0x44AFE78: CLAMP,
    0x44AFB4E: "The edit redirects the last four bytes of a second stack copy of the vault key, but the slot already holds the same four bytes "
               "from the first copy made at 0x44af802, so the balance stub sees the same 20 bytes.",
    0x44B049B: "The argument names a zero sized conversion error object on the stack; the panic slot never reads it, so moving the "
               "pointer changes no observable value.",
    0x455794E: "Comparing with 0 instead of 1 sends a one element range through one extra loop turn with a zero step, an extra pure memcmp call "
               "that leaves the position and the result unchanged.",
    0x4557984: "The flag changes only for an empty range, which happens only for an empty ring; the body then compares the returned index 0 "
               "with the ring length 0 and still takes the not-found exit.",
    0x4557A32: "The flag is returned unchanged unless the remaining count is zero, but that count is the capacity minus the head, at least 1 "
               "for any head below the capacity, so the changed immediate is never returned.",
    0x4557A03: DEQUE_UNUSED, 0x4557AA9: DEQUE_UNUSED, 0x4557AA3: DEQUE_UNUSED,
    0x4557997: "Comparing with 0 instead of 1 sends a one element range through one extra loop turn with a zero step, an extra pure memcmp call "
               "that leaves the position and the result unchanged.",
    0x4557AB0: "The next instruction setne al overwrites the low byte of eax, and the other bytes of the immediate are zero in both forms, so "
               "the returned flag is the same.",
}


REGISTERS = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")


def operand_text(operand):
    if operand is None:
        return ""
    kind = operand[0]
    if kind == "r":
        return REGISTERS[operand[1]]
    if kind == "x":
        return "xmm%d" % operand[1]
    if kind == "i":
        return "%#x" % (operand[1] & M64)
    _, base, index, scale, disp, _ = operand
    parts = []
    if base is not None:
        parts.append(REGISTERS[base])
    if index is not None:
        parts.append("%s*%d" % (REGISTERS[index], scale))
    if base is None and index is None:
        return "[%#x]" % (disp & M64)
    return "[%s%+d]" % ("+".join(parts), disp)


def instruction_rows(image, counts):
    rows = []
    for start, end in entry_extents(image):
        for row in F.decode_range(image, start, end):
            target = hexa(row.target) if row.target is not None and row.op in ("jcc", "jmp", "call") else ""
            rows.append((hexa(row.va), row.size, bytes(row.data).hex(), row.op + ("." + str(row.cc) if row.cc is not None and row.op in ("jcc", "set", "cmov") else ""),
                         operand_text(row.a), operand_text(row.b), target, counts.get(row.va, 0)))
    return rows


def block_rows(image, counts):
    out = []
    for start, end in entry_extents(image):
        rows = list(F.decode_range(image, start, end))
        leaders = {start}
        for row in rows:
            if row.op in ("jcc", "jmp") and row.target is not None:
                leaders.add(row.target)
                leaders.add(row.next)
            elif row.op in ("ret", "ud2", "int3"):
                leaders.add(row.next)
        current = []
        for row in rows:
            if row.va in leaders and current:
                out.append(block_line(current, counts))
                current = []
            current.append(row)
        if current:
            out.append(block_line(current, counts))
    return out


def block_line(rows, counts):
    last = rows[-1]
    if last.op == "jcc":
        ends = "branch %s / %s" % (hexa(last.target), hexa(last.next))
    elif last.op == "jmp":
        ends = "jump %s" % hexa(last.target)
    elif last.op in ("ret", "ud2", "int3"):
        ends = last.op
    else:
        ends = "falls to %s" % hexa(last.next)
    return (hexa(rows[0].va), hexa(last.next), len(rows), ends, counts.get(rows[0].va, 0))


def tsv(name, header, rows):
    lines = ["\t".join(header)]
    lines.extend("\t".join(str(cell) for cell in row) for row in rows)
    return name, "\n".join(lines) + "\n"


def analyse(count=10000, mutant_cases=1200):
    image = F.load_image()
    sites = locations(image)
    if sorted(sites) != sorted(EVENT_SITES.values()):
        raise EvidenceError("event site set differs from the byte scan")
    for name, va in EVENT_SITES.items():
        LOCATION[name] = sites[va]
    harness = Harness(image)
    hits = set()
    stream = list(named_cases())
    stats, caught, rows = check_stream(harness, stream, VARIANTS, keep=1, hits=hits)
    bulk, bulk_caught, bulk_rows = check_stream(harness, random_cases(count), VARIANTS, keep=6, hits=hits)
    for key in ("cases", "mismatches"):
        stats[key] += bulk[key]
    stats["kinds"].update(bulk["kinds"])
    stats["stores"].update(bulk["stores"])
    if stats["first_mismatch"] is None:
        stats["first_mismatch"] = bulk["first_mismatch"]
    for name in VARIANTS:
        caught[name][0] += bulk_caught[name][0]
        if caught[name][1] is None and bulk_caught[name][1] is not None:
            caught[name][1] = len(stream) + bulk_caught[name][1]
    rows.extend(bulk_rows)
    branches = dict(harness.machine.branches)
    counts = dict(harness.machine.counts)
    mutants = mutants_of(image, hits)
    kill_cases = stream + list(random_cases(mutant_cases))
    mutant_rows = run_mutants(image, mutants, kill_cases)
    controls = structural_controls(image, harness, stream)
    return {"image": image, "sites": sites, "stats": stats, "caught": caught, "rows": rows, "mutants": mutant_rows, "controls": controls,
            "hits": hits, "branches": branches, "counts": counts, "kill_cases": len(kill_cases)}


def render(result):
    image, stats = result["image"], result["stats"]
    caught, mutants, controls = result["caught"], result["mutants"], result["controls"]
    files = dict([
        tsv("constants.tsv", ("address", "name", "bytes", "value"), constant_rows(image)),
        tsv("callees.tsv", ("call site", "kind", "target or slot", "role", "slot relocation addend"), callee_rows(image)),
        tsv("event-sites.tsv", ("site", "call site", "location record", "source path", "line", "column"), site_rows(image, result["sites"])),
        tsv("layout.tsv", ("object", "offset", "type", "meaning", "first access"), layout_rows()),
        tsv("cases.tsv", ("index", "name", "store", "set tag", "set count", "set size", "outcome", "log entries", "digest"), result["rows"]),
        tsv("outcomes.tsv", ("outcome", "cases"), sorted(stats["kinds"].items())),
        tsv("wrong-readings.tsv", ("reading", "cases refused", "first refusing case"), [(name, caught[name][0], caught[name][1]) for name in VARIANTS]),
    ])
    branch_rows = []
    for va in sorted(result["branches"]):
        not_taken, taken = result["branches"][va]
        branch_rows.append((hexa(va), taken, not_taken))
    files.update([tsv("instructions.tsv", ("address", "size", "bytes", "operation", "first operand", "second operand", "target", "executions"),
                      instruction_rows(image, result["counts"])),
                  tsv("blocks.tsv", ("start", "end", "instructions", "ends with", "executions of the first instruction"), block_rows(image, result["counts"]))])
    files.update([tsv("branches.tsv", ("jcc", "taken", "not taken"), branch_rows)])
    decoded = list(F.decode_range(image, *image.exact_fde(ENTRY))) + list(F.decode_range(image, *image.exact_fde(SEARCH)))
    reached = result["hits"]
    files.update([tsv("coverage.tsv", ("part", "instructions", "reached"), [
        ("0x44af2f0 body", len([r for r in decoded if ENTRY <= r.va < ENTRY_END]), len([r for r in decoded if ENTRY <= r.va < ENTRY_END and r.va in reached])),
        ("0x45578e0 deque search", len([r for r in decoded if SEARCH <= r.va < SEARCH + 0x200]), len([r for r in decoded if SEARCH <= r.va < SEARCH + 0x200 and r.va in reached])),
    ])])
    mutant_lines, survivors, equivalent = [], [], 0
    for va, kind, at, old, new, killed, first in mutants:
        status = "killed" if killed else "equivalent" if at in EQUIVALENT else "SURVIVED"
        if status == "equivalent":
            equivalent += 1
        if status == "SURVIVED":
            survivors.append((va, kind, at))
        mutant_lines.append((hexa(va), kind, hexa(at), "0x%02x" % old, "0x%02x" % new, status, first))
    files.update([tsv("mutants.tsv", ("instruction", "edit", "byte address", "old", "new", "status", "first refusing case"), mutant_lines)])
    files.update([tsv("equivalent-mutants.tsv", ("edit", "byte address", "why the edit cannot change any result"),
                      [(hexa(at), hexa(at), EQUIVALENT[at]) for at in sorted(EQUIVALENT) if any(r[2] == at for r in mutants)])])
    files.update([tsv("structural-controls.tsv", ("control", "detected", "how"), controls)])
    detected = sum(1 for name in VARIANTS if caught[name][0]) + sum(1 for row in controls if row[1]) + sum(1 for row in mutants if row[5])
    total = len(VARIANTS) + len(controls) + len(mutants)
    measure = {
        "cases": stats["cases"], "negative_controls": total, "negative_detected": detected, "equivalent": equivalent,
        "wrong_readings": len(VARIANTS), "structural_controls": len(controls), "byte_edits": len(mutants), "mismatches": stats["mismatches"],
        "kill_suite_cases": result["kill_cases"], "survivors": len(survivors),
    }
    files["measure.json"] = json.dumps(measure, indent=1, sort_keys=True) + "\n"
    return files, measure, survivors


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=10000)
    args = parser.parse_args(argv)
    result = analyse(args.cases)
    files, measure, survivors = render(result)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text)
    print(files["measure.json"], end="")
    ok = (measure["mismatches"] == 0 and not survivors and measure["negative_detected"] + measure["equivalent"] == measure["negative_controls"]
          and all(row[1] for row in result["controls"]))
    for row in survivors:
        print("survivor %s %s %s" % (hexa(row[0]), row[1], hexa(row[2])), file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
