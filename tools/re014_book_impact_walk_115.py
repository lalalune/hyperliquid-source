#!/usr/bin/env python3
"""Reconstruct the node #115 order-book impact walk (average fill price of a notional) from ELF bytes.

The function at 0x46a6370 walks one side of an order book from its best level outward, either a B-tree
map of levels (key = signed price, the walk uses |key|) or a ring buffer of (key, level) pairs, sums the
resting size of every level from a linked order list in an arena, and stops at the level where the running
notional reaches a target. It returns total notional divided by total size with the last level only taken
partially (floor), or zero when no price can be formed. Its B-tree step 0x37c5dd0 and the 0x46a6860 record
scaling helper (every money field times 100, checked) are reconstructed with it. The original bytes run in
a small x86-64 evaluator (engine imported from the merged mid-market builder tool) with only the overflow
callback, the log slot and the panic slot stubbed; an independently written pure-Python reconstruction
predicts the return value, every callback and every fault. Every conditional branch and immediate of the
three bodies is flipped to show the comparison can tell, and deliberately wrong reconstructions must be
caught. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import mid_market_order_builder_115 as eng  # noqa: E402
from mid_market_order_builder_115 import (  # noqa: E402
    BINARY, SHA256, EvidenceError, Halt, Machine, MASK, Panicked, decode_range, direct_sites, load_image,
    operand_text,
)

RDI, RSI, RDX, RCX, R8, R9 = eng.RDI, eng.RSI, eng.RDX, eng.RCX, eng.R8, eng.R9
HEAP = eng.HEAP_BASE
M64 = MASK[8]

WALK = 0x46A6370
SCALE = 0x46A6860
NEXT = 0x37C5DD0
FUNCTIONS = (("walk", WALK), ("scale", SCALE), ("next", NEXT))
NIL_TAG = 1 << 63
SLOT_OVERFLOW = 0x64E4EA8
SLOT_LOG = 0x64DF9F0
SLOT_PANIC = 0x64DF830
FLAG_WORD = 0x64F01D8
LOCATIONS = {"size_sum": 0x648BDA0, "notional_sum": 0x6493598, "partial_sum": 0x64935B0, "fill_sum": 0x64935C8,
             "scale_mul": 0x6493610}
SLOTS = (SLOT_OVERFLOW, SLOT_LOG, SLOT_PANIC)
PRICE_LIMIT = 0x7FFFFFFFFFFFFFFE

# Heap layout of one case (offsets from the heap base).
SELF, TARGET, CONT, STATE, IN, OUT = 0x100, 0x200, 0x300, 0x400, 0x500, 0x600
ARENA, DEQ, TREE = 0x1000, 0x3000, 0x5000
ARENA_STRIDE, DEQ_STRIDE, NODE_STRIDE = 0x110, 0x88, 0x680
BLOB = 0x16000
MAX_ARENA, MAX_NODES = 24, 40
KEYS_AT, VALS_STRIDE, PARENT_AT, PIDX_AT, LEN_AT, EDGES_AT = 0x588, 0x80, 0x580, 0x5E0, 0x5E2, 0x5E8

FIELD_RULES = (
    ("walk", "self +0x88", "arena base pointer"), ("walk", "self +0x90", "arena entry count"),
    ("walk", "arena +0x00 (dword)", "entry kind, 2 ends a chain"), ("walk", "arena +0x10", "continue flag, 0 ends a chain"),
    ("walk", "arena +0x18", "next entry index"), ("walk", "arena +0xe0", "entry size"),
    ("walk", "arena stride", "0x110"), ("walk", "level +0x00 (dword)", "must be 1"),
    ("walk", "level +0x08", "first arena index"), ("walk", "deque element", "key at +0, level at +8, stride 0x88"),
    ("walk", "container +0x00", "0x8000000000000000 selects the B-tree form, else the ring capacity"),
    ("next", "tree node +0x580/+0x5e0/+0x5e2/+0x5e8", "parent, index in parent, key count, edges"),
    ("next", "tree node +0x588 + 8i / +0x80 i", "key slot / level slot"),
)


class Rng:
    def __init__(self, seed):
        self.state = (seed * 0x9E3779B97F4A7C15 + 1) & M64

    def u64(self):
        self.state = (self.state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & M64
        x = self.state
        x ^= x >> 29
        x = (x * 0xBF58476D1CE4E5B9) & M64
        return x ^ (x >> 32)

    def below(self, count):
        return self.u64() % count

    def between(self, low, high):
        return low + self.below(high - low + 1)

    def pick(self, items):
        return items[self.below(len(items))]


SPECIAL = (0, 1, 2, 3, 99, 100, 0xFF, 0xFFFF, 0xFFFFFFFF, 0x100000000, 0x7FFFFFFF, 0x80000000, PRICE_LIMIT,
           PRICE_LIMIT + 1, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFE, M64,
           M64 // 100, M64 // 100 + 1, M64 // 3)


def magnitude(rng, profile, small, mid, big):
    """One value whose size depends on the profile (0 tiny .. 3 extreme, specials mixed in)."""
    if profile == 3 and rng.below(3) == 0:
        return rng.pick(SPECIAL)
    top = (small, mid, big, M64)[profile]
    shift = rng.below(max(1, top.bit_length()))
    return rng.u64() % (top + 1) >> shift


def signed(value):
    return value - (1 << 64) if value >> 63 else value


def case_levels(rng, profile, kind):
    """(key, tag, head index) rows in book order and a filled arena, as plain tuples."""
    count = rng.between(0, 7) if rng.below(12) else rng.between(8, 11)
    keys = set()
    rows = []
    for _ in range(count):
        key = magnitude(rng, profile, 60, 10 ** 6, 1 << 40)
        if profile == 3 and rng.below(4) == 0:
            key = rng.pick(SPECIAL)
        if rng.below(2):
            key = (-key) & M64
        keys.add(key)
    if kind == "btree":
        ordered = sorted(keys, key=signed)
    else:
        ordered = list(keys)
        for at in range(len(ordered) - 1, 0, -1):
            swap = rng.below(at + 1)
            ordered[at], ordered[swap] = ordered[swap], ordered[at]
        if rng.below(2):
            ordered.sort(key=signed)
    arena = []
    for key in ordered:
        if rng.below(30) == 0:
            rows.append((key, rng.pick((0, 2, 3, 7)), rng.below(5)))
            continue
        head = len(arena)
        chain = rng.between(1, 3)
        if head + chain >= MAX_ARENA:
            rows.append((key, 1, MAX_ARENA + 5 if rng.below(2) else 0))
            continue
        for link in range(chain):
            last = link == chain - 1
            size = magnitude(rng, profile, 30, 10 ** 6, 1 << 24)
            if profile == 3 and rng.below(6) == 0:
                size = rng.pick(SPECIAL)
            kind_word = 1
            if rng.below(40) == 0:
                kind_word = 2 if rng.below(2) else rng.pick((0, 3, 0x1_0000_0002))
            go = 0 if last and rng.below(2) else rng.pick((1, 5, 0xFFFFFFFF))
            if not last and rng.below(25) == 0:
                go = 0
            following = head + link + 1 if not last else rng.pick((MAX_ARENA + 2, 0xFFFFFFFFFFFFFFFF))
            if last and go == 0:
                following = rng.pick((0, head, MAX_ARENA + 2))
            arena.append((kind_word, go, following, size))
        rows.append((key, 1, head))
    return rows, arena


def chain_size(arena, count, head, variant, events):
    """Sum of entry sizes along one order chain (the loop at 0x46a6530)."""
    total, cursor, hops = 0, head, 0
    while True:
        hops += 1
        if hops > 64 or cursor >= len(arena):
            return total  # only a deliberately wrong variant can cycle or run off the arena
        kind, go, following, size = arena[cursor]
        if kind & MASK[4] == 2 and "chain-ignore-end-kind" not in variant:
            return total
        summed = total + size
        if summed > M64:
            events.append(("overflow", LOCATIONS["size_sum"]))
            summed = summed if "sat-wrap" in variant else M64
            if "sat-wrap" in variant:
                summed &= M64
        total = summed
        if go == 0 and "chain-ignore-continue" not in variant:
            return total
        if following >= count and "chain-bound-le" not in variant or following > count:
            return total
        cursor = following


def saturating(left, right, location, events, variant):
    total = left + right
    if total > M64:
        if "no-overflow-events" not in variant:
            events.append(("overflow", location))
        return total & M64 if "sat-wrap" in variant else M64
    return total


def spec_walk(case, variant=()):
    """Return the predicted outcome dict of the walk for one case."""
    events = []
    rows, arena, count, target, flag = case["rows"], case["arena"], case["count"], case["target"], case["flag"]
    order = list(reversed(rows)) if "reverse-order" in variant else rows

    def failed(slow):
        if slow and flag and "no-flag" not in variant:
            events.append(("slow", FLAG_WORD, 1))
        return {"ret": 0, "events": events}

    accumulated, fill = 0, 0
    for key, tag, head in order:
        price = key if key < 1 << 63 else (-signed(key)) & M64
        if "no-abs" in variant:
            price = key
        if "abs-min-zero" in variant and key == NIL_TAG:
            price = 0
        if tag & MASK[4] != 1 and "ignore-level-tag" not in variant:
            return failed(True)
        if (head >= count and "count-le" not in variant) or head > count:
            return failed(True)
        size = chain_size(arena, count, head, variant, events)
        if size == 0 and "zero-size-continue" not in variant:
            return failed(True)
        if size == 0:
            continue
        notional = price * size
        if notional > M64 or (notional > PRICE_LIMIT and "no-price-limit" not in variant):
            return {"ret": 0, "events": events}
        after = saturating(accumulated, notional, LOCATIONS["notional_sum"], events, variant)
        reached = after > target if "ge-to-gt" in variant else after >= target
        if not reached:
            accumulated = after
            fill = saturating(fill, size, LOCATIONS["fill_sum"], events, variant)
            continue
        remaining = target - accumulated
        if price == 0:
            return {"fault": "divide", "events": events}
        quotient = remaining // price + (1 if "ceil-div" in variant and remaining % price else 0)
        taken = price * quotient
        if taken > M64 or taken > PRICE_LIMIT:
            return {"ret": 0, "events": events}
        total = saturating(taken, accumulated, LOCATIONS["partial_sum"], events, variant)
        if "partial-uses-level" in variant:
            total = after
        counted = saturating(quotient, fill, LOCATIONS["fill_sum"], events, variant)
        if "fill-skip-partial" in variant:
            counted = fill
        blocked = counted > total if "final-gt" in variant else (counted - 1) & M64 >= total
        if blocked:
            return {"ret": 0, "events": events}
        return {"ret": total // counted, "events": events}
    return {"ret": 0, "events": events}


# ---- B-tree construction (shape only; keys and levels are filled afterwards) ----

def tree_bounds(height):
    if height == 0:
        return 1, 11
    low, high = tree_bounds(height - 1)
    return 2 * low + 1, 12 * high + 11


def split_total(total, parts, low, high, rng):
    sizes = [low] * parts
    extra = total - low * parts
    for _ in range(extra):
        while True:
            at = rng.below(parts)
            if sizes[at] < high:
                sizes[at] += 1
                break
    return sizes


def tree_shape(total, height, rng):
    """A node as (key count slots, children list); keys are assigned by in-order position later."""
    if height == 0:
        return {"len": total, "kids": []}
    low, high = tree_bounds(height - 1)
    choices = [c for c in range(2, 13) if c * low + c - 1 <= total <= c * high + c - 1]
    parts = rng.pick(choices)
    sizes = split_total(total - (parts - 1), parts, low, high, rng)
    return {"len": parts - 1, "kids": [tree_shape(size, height - 1, rng) for size in sizes]}


def tree_height(total, rng):
    options = [h for h in (0, 1, 2) if tree_bounds(h)[0] <= total <= min(tree_bounds(h)[1], 400)]
    if total <= 11 and rng.below(3):
        return 0
    return rng.pick(options)


def tree_inorder(node, out, path):
    """Append (node object, slot) pairs in key order."""
    for slot in range(node["len"]):
        if node["kids"]:
            tree_inorder(node["kids"][slot], out, path)
        out.append((node, slot))
    if node["kids"]:
        tree_inorder(node["kids"][node["len"]], out, path)


def tree_nodes(node, out):
    out.append(node)
    for kid in node["kids"]:
        tree_nodes(kid, out)


def build_tree(count, rng):
    """Return (root node, height, ordered (node, slot) list, node list); count rows, no more than MAX_NODES nodes."""
    while True:
        height = tree_height(count, rng)
        root = tree_shape(count, height, rng)
        nodes = []
        tree_nodes(root, nodes)
        if len(nodes) <= MAX_NODES:
            break
    order = []
    tree_inorder(root, order, None)
    return root, height, order, nodes


# ---- the evaluator harness ----

def sanitise(path):
    for marker in ("/l1/", "/library/", "/src/"):
        if marker in path:
            return path[path.rindex(marker) + 1:]
    return path.rsplit("/", 1)[-1]


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        self.relative = relative
        machine.slots = {}
        hooks = ((SLOT_OVERFLOW, self.on_overflow), (SLOT_LOG, self.on_log), (SLOT_PANIC, self.on_panic))
        for index, (slot, hook) in enumerate(hooks):
            if slot not in relative:
                raise EvidenceError("slot without a RELATIVE row: %#x" % slot)
            fake = eng.FAKE_SLOT_BASE + 0x10 * index
            machine.memory.statics[slot] = fake
            machine.slots[fake] = hook
        self.events = []

    def blob_new(self):
        return bytearray(bytes([eng.STACK_MARK]) * BLOB)

    def load(self, blob):
        machine = self.machine
        machine.memory.reset(0)
        machine.memory.put_bytes(HEAP, bytes(blob))
        self.events = []

    # --- stubs ---
    def on_overflow(self, machine):
        if machine.regs[RDI] != 0:
            raise Halt("overflow callback argument")
        self.events.append(("overflow", machine.regs[RSI]))

    def on_log(self, machine):
        regs = machine.regs
        self.events.append(("slow", regs[RDI], regs[RSI]))

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    # --- walk ---
    def book_blob(self, case):
        """Lay one walk case out in a heap blob."""
        blob = self.blob_new()
        struct.pack_into("<Q", blob, SELF + 0x88, HEAP + ARENA)
        struct.pack_into("<Q", blob, SELF + 0x90, case["count"])
        struct.pack_into("<Q", blob, TARGET, case["target"])
        for index, (kind, go, following, size) in enumerate(case["arena"]):
            at = ARENA + index * ARENA_STRIDE
            struct.pack_into("<Q", blob, at, kind)
            struct.pack_into("<Q", blob, at + 0x10, go)
            struct.pack_into("<Q", blob, at + 0x18, following)
            struct.pack_into("<Q", blob, at + 0xE0, size)
        rows = case["rows"]
        if case["kind"] == "deque":
            capacity, head = case["cap"], case["head"]
            struct.pack_into("<QQQQ", blob, CONT, capacity, HEAP + DEQ, head, len(rows))
            for index, (key, tag, first) in enumerate(rows):
                at = DEQ + ((head + index) % capacity) * DEQ_STRIDE
                struct.pack_into("<QQQ", blob, at, key, tag, first)
        else:
            self.tree_blob(blob, case["tree"], rows, CONT)
        return blob

    def tree_blob(self, blob, tree, rows, container):
        root, height, order, nodes = tree
        base = {id(node): TREE + index * NODE_STRIDE for index, node in enumerate(nodes)}
        parent = {}
        for node in nodes:
            for position, kid in enumerate(node["kids"]):
                parent[id(kid)] = (node, position)
        for node in nodes:
            at = base[id(node)]
            link = parent.get(id(node))
            struct.pack_into("<Q", blob, at + PARENT_AT, HEAP + base[id(link[0])] if link else 0)
            struct.pack_into("<H", blob, at + PIDX_AT, link[1] if link else 0)
            struct.pack_into("<H", blob, at + LEN_AT, node["len"])
            for position, kid in enumerate(node["kids"]):
                struct.pack_into("<Q", blob, at + EDGES_AT + 8 * position, HEAP + base[id(kid)])
        for (node, slot), (key, tag, first) in zip(order, rows):
            at = base[id(node)]
            struct.pack_into("<Q", blob, at + KEYS_AT + 8 * slot, key)
            struct.pack_into("<QQ", blob, at + VALS_STRIDE * slot, tag, first)
        struct.pack_into("<QQQQ", blob, container, NIL_TAG, HEAP + base[id(root)] if rows else 0,
                         height if rows else 0, len(rows))
        return base

    def run_walk(self, case):
        self.load(self.book_blob(case))
        machine = self.machine
        machine.memory.statics[FLAG_WORD] = case["flag"]
        machine.real = frozenset((NEXT,))
        try:
            value = machine.run(WALK, {RDI: HEAP + SELF, RSI: HEAP + TARGET, RDX: HEAP + CONT})
        except Panicked as stop:
            return {"panic": stop.args[0], "events": self.events}
        except Halt as stop:
            if "division by zero" in str(stop):
                return {"fault": "divide", "events": self.events}
            raise
        return {"ret": value, "events": self.events}

    # --- the B-tree step on its own ---
    def run_next(self, tree, rows):
        blob = self.blob_new()
        base = self.tree_blob(blob, tree, rows, CONT)
        root, height, order, nodes = tree
        count = len(rows)
        have = 1 if count else 0
        node = HEAP + base[id(root)] if count else 0
        struct.pack_into("<QQQQQQQQQ", blob, STATE, have, 0, node, height if count else 0, have, 0, node,
                         height if count else 0, count)
        self.load(blob)
        machine = self.machine
        machine.real = frozenset()
        seen = []
        for _ in range(count + 2):
            value = machine.run(NEXT, {RDI: HEAP + STATE})
            if value == 0:
                seen.append(None)
                continue
            seen.append((value, machine.regs[RDX]))
        return seen, base

    # --- the scaling helper ---
    def run_scale(self, record):
        blob = self.blob_new()
        for offset, value in record.items():
            struct.pack_into("<Q", blob, IN + offset, value)
        self.load(blob)
        machine = self.machine
        machine.real = frozenset()
        try:
            machine.run(SCALE, {RDI: HEAP + OUT, RSI: HEAP + IN})
        except Panicked as stop:
            return {"panic": stop.args[0]}
        defined = spec_scale_mask(record)
        data = machine.memory.bytes_at(HEAP + OUT, 0x78)
        return {"out": mask_bytes(data, defined)}


SCALE_FIELDS = (0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70)
DWORD_WORDS = (0x20, 0x58)
SCALE_GROUP_ONE = (0x10, 0x18, 0x20)
SCALE_GROUP_TWO = (0x48, 0x50, 0x58)


def spec_scale_mask(record):
    """Byte offsets of the output the helper defines for this input."""
    defined = {0x00, 0x28, 0x30, 0x60, 0x68, 0x70}
    if record[0x00] == 1:
        defined.add(0x08)
        defined.update(SCALE_GROUP_ONE)
    if (-signed(record[0x28])) < -(1 << 63) or signed(record[0x28]) != -(1 << 63):
        defined.update((0x38, 0x40))
        defined.update(SCALE_GROUP_TWO)
    else:
        defined.add(0x40)
    return defined


def mask_bytes(data, defined):
    words = []
    for offset in range(0, 0x78, 8):
        word = struct.unpack_from("<Q", data, offset)[0]
        words.append((word & MASK[4] if offset in DWORD_WORDS else word) if offset in defined else None)
    return tuple(words)


def spec_scale(record, variant=()):
    mul = (lambda value: value * 100) if "mul-99" not in variant else (lambda value: value * 99)
    out = {}

    def scaled(offset):
        product = mul(record[offset])
        if product > M64:
            raise OverflowError(offset)
        return product

    try:
        out[0x60] = scaled(0x60)
        out[0x68] = scaled(0x68)
        out[0x00] = 1 if record[0x00] == 1 else 0
        if record[0x00] == 1:
            out[0x08] = scaled(0x08)
            for offset in SCALE_GROUP_ONE:
                out[offset] = record[offset]
        out[0x28], out[0x30] = record[0x28], record[0x30]
        if signed(record[0x28]) != -(1 << 63) or "min-unguarded" in variant:
            out[0x40] = scaled(0x40)
            out[0x38] = record[0x38]
            for offset in SCALE_GROUP_TWO:
                out[offset] = record[offset]
        else:
            out[0x40] = record[0x40]
        out[0x70] = scaled(0x70)
    except OverflowError:
        return {"panic": ("panic", LOCATIONS["scale_mul"])}
    defined = spec_scale_mask(record)
    return {"out": tuple((out.get(offset) & (MASK[4] if offset in DWORD_WORDS else M64)) if offset in defined else None
                         for offset in range(0, 0x78, 8))}


# ---- cases ----

def walk_case(index, kind):
    rng = Rng(index * 2 + (kind == "btree") + 1000)
    profile = index % 4 if index % 7 else 3
    rows, arena = case_levels(rng, profile, kind)
    count = len(arena)
    if rng.below(8) == 0 and count:
        count = rng.between(0, count)
    case = {"label": "%s-%05d" % (kind, index), "kind": kind, "rows": rows, "arena": arena, "count": count,
            "flag": rng.pick((0, 0, 1, 3)), "target": 0}
    if kind == "deque":
        case["cap"] = len(rows) + rng.below(5)
        case["head"] = rng.below(case["cap"]) if case["cap"] else 0
    else:
        case["tree"] = build_tree(len(rows), rng) if rows else (None, 0, [], [])
    case["target"] = pick_target(case, rng, profile)
    return case


def pick_target(case, rng, profile):
    """Targets near the cumulative notional of each level, plus extremes, so every exit is reached."""
    probe = dict(case, target=M64)
    cumulative = []
    events = []
    total = 0
    for key, tag, head in case["rows"]:
        if tag & MASK[4] != 1 or head >= case["count"]:
            break
        size = chain_size(case["arena"], case["count"], head, (), events)
        price = key if key < 1 << 63 else (-signed(key)) & M64
        total = min(M64, total + price * size)
        cumulative.append(total)
    choice = rng.below(10)
    if choice == 0:
        return rng.pick((0, 1, 2, M64, M64 - 1, PRICE_LIMIT, PRICE_LIMIT + 1))
    if not cumulative or choice == 1:
        return magnitude(rng, profile, 1000, 10 ** 8, 1 << 50)
    level = rng.pick(cumulative)
    shift = rng.pick((0, 0, 1, -1, 2, -2))
    return max(0, min(M64, level + shift)) if choice < 7 else rng.below(level + 2)


def next_case(index):
    rng = Rng(index + 50000)
    count = rng.between(0, 60) if rng.below(3) else rng.between(0, 11)
    rows = [(rng.u64(), 1, index) for _ in range(count)]
    rows.sort(key=lambda row: signed(row[0]))
    tree = build_tree(count, rng) if count else (None, 0, [], [])
    return {"label": "next-%05d" % index, "rows": rows, "tree": tree}


def scale_case(index):
    rng = Rng(index + 90000)
    edge = M64 // 100
    record = {}
    for offset in SCALE_FIELDS:
        roll = rng.below(14)
        if roll == 0:
            record[offset] = rng.pick((edge, edge + 1, M64, 1 << 63, 0, edge - 1))
        else:
            record[offset] = rng.u64() >> rng.between(0, 63)
    if rng.below(3):
        record[0x00] = 1 if rng.below(2) else rng.pick((0, 2, 5))
    if rng.below(6) == 0:
        record[0x28] = 1 << 63
    if rng.below(2):
        for offset in (0x60, 0x68, 0x70, 0x08, 0x40):
            record[offset] = rng.below(edge)
    return {"label": "scale-%05d" % index, "record": record}


def format_outcome(outcome):
    parts = []
    for key in ("ret", "fault", "panic"):
        if key in outcome:
            value = outcome[key]
            parts.append("%s=%s" % (key, value if key == "fault" else "%#x" % (value[1] if key == "panic" else value)))
    for event in outcome.get("events", ()):
        parts.append("%s@%#x" % (event[0], event[1]))
    if "out" in outcome:
        parts.append(",".join("-" if word is None else "%x" % word for word in outcome["out"]))
    return ";".join(parts) or "none"


def compare_walk(harness, case, variant=()):
    try:
        actual = harness.run_walk(case)
    except (Halt, Panicked, EvidenceError, IndexError, struct.error, ValueError, KeyError, OverflowError) as error:
        return "%s: machine stopped: %s" % (case["label"], error)
    try:
        expected = spec_walk(case, variant)
    except (ZeroDivisionError, IndexError):
        return "%s: wrong reconstruction faulted" % case["label"]
    if actual != expected:
        return "%s: differs: %r != %r" % (case["label"], actual, expected)
    return None


def next_expected(case, base):
    root, height, order, nodes = case["tree"]
    expected = []
    for node, slot in order:
        at = HEAP + base[id(node)]
        expected.append((at + KEYS_AT + 8 * slot, at + VALS_STRIDE * slot))
    return expected + [None, None]


def compare_next(harness, case, variant=()):
    try:
        actual, base = harness.run_next(case["tree"], case["rows"])
    except (Halt, Panicked, EvidenceError, IndexError, struct.error, ValueError, KeyError, OverflowError) as error:
        return "%s: machine stopped: %s" % (case["label"], error)
    expected = next_expected(case, base) if case["rows"] else [None, None]
    if "next-skips-last" in variant:
        expected = expected[:max(0, len(case["rows"]) - 1)] + [None] * min(len(expected), 2 + (1 if case["rows"] else 0))
    if "next-stops-early" in variant and len(case["rows"]) > 1:
        expected = expected[:-3] + [None, None, None]
    if actual != expected:
        return "%s: differs" % case["label"]
    return None


def compare_scale(harness, case, variant=()):
    try:
        actual = harness.run_scale(case["record"])
    except (Halt, Panicked, EvidenceError, IndexError, struct.error, ValueError, KeyError, OverflowError) as error:
        return "%s: machine stopped: %s" % (case["label"], error)
    expected = spec_scale(case["record"], variant)
    return None if actual == expected else "%s: differs" % case["label"]


def outcome_class(case, outcome):
    if "fault" in outcome:
        return "fault-divide"
    if outcome.get("ret"):
        return "price"
    kinds = {event[0] for event in outcome["events"]}
    reason = "zero"
    if "slow" in kinds:
        reason = "zero-flag-log"
    return reason + ("-after-overflow" if "overflow" in kinds else "")


# ---- static pins ----

def decode_function(image, start):
    return decode_range(image, *image.exact_fde(start))


def static_tables(image):
    pins, branches, offsets = [], [], {}
    sites = direct_sites(image, [start for _, start in FUNCTIONS])
    for name, start in FUNCTIONS:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        body = bytes(image.blob[image.offset(begin):image.offset(begin) + end - begin])
        callers = sorted(site for site, _ in sites[start])
        pins.append((name, begin, end, end - begin, len(rows), hashlib.sha256(body).hexdigest()[:16],
                     ",".join("%#x" % site for site in callers) or "-"))
        for row in rows:
            if row.op == "jcc":
                branches.append((name, row.va, row.cc, row.target))
            for operand in (row.a, row.b):
                if isinstance(operand, tuple) and operand and operand[0] == "m" and operand[1] is not None:
                    key = (name, operand[4] & 0xFFFF if operand[4] >= 0 else operand[4])
                    offsets[key] = offsets.get(key, 0) + 1
    return pins, branches, offsets, sites


def location_rows(image, harness):
    rows = []
    for name, slot in sorted(LOCATIONS.items(), key=lambda item: item[1]):
        path, line, column = image.location(slot, harness.relative)
        rows.append((name, slot, sanitise(path), line, column))
    return rows


# ---- mutants ----

def byte_mutants(image):
    for name, start in FUNCTIONS:
        rows = decode_function(image, start)
        for row in rows:
            if row.op == "jcc":
                yield name, start, row.va, row.size - (2 if row.size == 2 else 5), "branch"
            elif row.op in ("set", "cmov"):
                yield name, start, row.va, None, row.op
            if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
                yield name, start, row.va, row.imm_at, "immediate"


def probe_sets(count):
    walk = [walk_case(index, "btree" if index % 2 else "deque") for index in range(count)]
    return walk


def run_byte_mutants(image, seen, walk_probe, next_probe, scale_probe):
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = eng.MUTANT_STEP_LIMIT
    results = []
    plans = {"walk": (walk_probe, compare_walk), "next": (next_probe, compare_next), "scale": (scale_probe, compare_scale)}
    for name, start, va, at, kind in byte_mutants(image):
        if va not in seen:
            results.append((name, va, kind, "unreached", ""))
            continue
        cases, check = plans[name]
        machine.patches = eng.mutate_patch(image, va, at)
        machine.cache.pop(va, None)
        failed = None
        for index, case in enumerate(cases):
            failed = check(harness, case)
            if failed:
                cases.insert(0, cases.pop(index))
                break
        machine.patches = {}
        machine.cache.pop(va, None)
        results.append((name, va, kind, "killed" if failed else "survived", failed.split(":")[0] if failed else ""))
    return results


WALK_VARIANTS = ("no-abs", "abs-min-zero", "sat-wrap", "ge-to-gt", "ceil-div", "fill-skip-partial",
                 "ignore-level-tag", "no-price-limit", "chain-ignore-continue", "chain-ignore-end-kind",
                 "count-le", "final-gt", "no-flag", "no-overflow-events", "partial-uses-level",
                 "zero-size-continue", "reverse-order", "chain-bound-le")
NEXT_VARIANTS = ("next-skips-last", "next-stops-early")
SCALE_VARIANTS = ("mul-99", "min-unguarded")


def run_variant_controls(harness, walk_cases, next_cases, scale_cases):
    rows = []
    for variant in WALK_VARIANTS:
        caught = ""
        for case in walk_cases:
            caught = compare_walk(harness, case, (variant,))
            if caught:
                break
        rows.append(("walk-variant", variant, bool(caught), caught.split(":")[0]))
    for variant in NEXT_VARIANTS:
        caught = next((c for c in (compare_next(harness, case, (variant,)) for case in next_cases) if c), "")
        rows.append(("next-variant", variant, bool(caught), caught.split(":")[0]))
    for variant in SCALE_VARIANTS:
        caught = next((c for c in (compare_scale(harness, case, (variant,)) for case in scale_cases) if c), "")
        rows.append(("scale-variant", variant, bool(caught), caught.split(":")[0]))
    return rows




def run_input_controls(image, harness, walk_cases, next_cases):
    """Damaged binary, out-of-range addresses, damaged case rows and a damaged B-tree length."""
    rows = []

    def expect(name, action):
        try:
            action()
        except EvidenceError as error:
            rows.append(("input", name, True, type(error).__name__))
        else:
            rows.append(("input", name, False, ""))

    flipped = bytearray(image.blob)
    flipped[0x1000] ^= 1

    def damaged_digest():
        if hashlib.sha256(bytes(flipped)).hexdigest() != SHA256:
            raise EvidenceError("digest mismatch")

    expect("binary byte flipped breaks the digest", damaged_digest)
    expect("wrong expected digest", lambda: load_image(BINARY, "0" * 64))
    expect("address outside every section", lambda: image.offset(0x10))
    expect("walk start plus four is not an FDE start", lambda: image.exact_fde(WALK + 4))
    expect("address past the last FDE", lambda: image.fde(0x7FFFFFFFF))
    expect("section start is not a function start", lambda: image.exact_fde(0x1000))
    priced = [case for case in walk_cases if spec_walk(case).get("ret")][:60]
    edits = (("target raised by a third", lambda c: dict(c, target=min(M64, c["target"] + 1 + c["target"] // 3))),
             ("level key flipped", lambda c: dict(c, rows=[(c["rows"][0][0] ^ 0x10,) + c["rows"][0][1:]] + c["rows"][1:])),
             ("arena size bumped", lambda c: dict(c, arena=[(c["arena"][0][0], c["arena"][0][1], c["arena"][0][2],
                                                           (c["arena"][0][3] + 1) & M64)] + c["arena"][1:])),
             ("arena count halved", lambda c: dict(c, count=max(0, c["count"] // 2))))
    for name, edit in edits:
        differs = False
        for case in priced:
            try:
                differs = harness.run_walk(edit(case)) != spec_walk(case)
            except (Halt, Panicked, IndexError, struct.error):
                differs = True
            if differs:
                break
        rows.append(("case-row", name, differs, "differs"))
    probe = next(case for case in next_cases if len(case["rows"]) > 12)
    full = next_expected(probe, harness.run_next(probe["tree"], probe["rows"])[1])
    short, _ = harness.run_next(probe["tree"], probe["rows"][:-1])
    rows.append(("tree", "length counter one short", short != full, "differs"))
    return rows


def walk_line(case, outcome):
    rows = ";".join("%x:%d:%d" % (key, tag & 0xF, head) for key, tag, head in case["rows"])
    return "\t".join((case["label"], str(len(case["rows"])), "%d/%d" % (case["count"], len(case["arena"])),
                      "%x" % case["target"], str(case["flag"]), rows or "-", format_outcome(outcome)))


def scale_line(case, outcome):
    fields = ",".join("%x" % case["record"][offset] for offset in SCALE_FIELDS)
    return "\t".join((case["label"], fields, format_outcome(outcome)))


def next_line(case, expected):
    return "\t".join((case["label"], str(len(case["rows"])), str(case["tree"][1]), str(len(case["tree"][3])),
                      str(len(expected))))


def tsv(header, rows):
    return "\n".join(["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]) + "\n"


def tally(classes, label):
    classes[label] = classes.get(label, 0) + 1


def generate(walks, nexts, scales, probe, sample):
    image = load_image()
    harness = Harness(image)
    machine = harness.machine
    digest = hashlib.sha256()
    mismatches = []
    classes = {}
    sample_rows = {"walk": [], "next": [], "scale": []}
    for index in range(walks):
        kind = "btree" if index % 2 else "deque"
        case = walk_case(index, kind)
        message = compare_walk(harness, case)
        if message:
            mismatches.append(message)
        outcome = spec_walk(case)
        tally(classes, kind + "-" + outcome_class(case, outcome))
        line = walk_line(case, outcome)
        digest.update(line.encode() + b"\n")
        if index % sample == 0:
            sample_rows["walk"].append(line)
    for index in range(nexts):
        case = next_case(index)
        message = compare_next(harness, case)
        if message:
            mismatches.append(message)
        expected = next_expected(case, harness.run_next(case["tree"], case["rows"])[1]) if case["rows"] else [None, None]
        line = next_line(case, expected)
        digest.update(line.encode() + b"\n")
        if index % sample == 0:
            sample_rows["next"].append(line)
    for index in range(scales):
        case = scale_case(index)
        message = compare_scale(harness, case)
        if message:
            mismatches.append(message)
        outcome = spec_scale(case["record"])
        tally(classes, "scale-" + ("panic" if "panic" in outcome else "scaled"))
        line = scale_line(case, outcome)
        digest.update(line.encode() + b"\n")
        if index % sample == 0:
            sample_rows["scale"].append(line)
    if mismatches:
        raise EvidenceError("%d cases differ, first: %s" % (len(mismatches), mismatches[0]))
    seen = set(machine.seen)
    pins, branches, offsets, sites = static_tables(image)
    locations = location_rows(image, harness)
    pool_walk = [walk_case(index, "btree" if index % 2 else "deque") for index in range(3000)]
    pool_next = [next_case(index) for index in range(300)]
    pool_scale = [scale_case(index) for index in range(300)]
    controls = run_variant_controls(harness, pool_walk, pool_next, pool_scale)
    controls += run_input_controls(image, harness, pool_walk, pool_next)
    walk_probe = [pool_walk[index] for index in range(0, 3000, max(1, 3000 // probe))][:probe]
    mutants = run_byte_mutants(image, seen, walk_probe, pool_next[:150], pool_scale[:150])
    coverage = []
    for name, start in FUNCTIONS:
        span = image.exact_fde(start)
        for row in decode_function(image, start):
            if row.va not in seen:
                coverage.append((name, "%#x" % row.va, row.op, operand_text(row.a), operand_text(row.b)))
    killed = [row for row in mutants if row[3] == "killed"]
    survived = [row for row in mutants if row[3] == "survived"]
    unreached = [row for row in mutants if row[3] == "unreached"]
    detected = sum(1 for row in controls if row[2]) + len(killed)
    measure = {"cases": walks + nexts + scales, "negative_controls": len(controls) + len(killed),
               "negative_detected": detected, "walk_cases": walks, "next_cases": nexts, "scale_cases": scales,
               "byte_mutants_killed": len(killed), "byte_mutants_survived": len(survived),
               "byte_mutants_unreached": len(unreached), "other_controls": len(controls),
               "case_table_sha256": digest.hexdigest()}
    return {
        "pins.tsv": tsv(("body", "start", "end", "bytes", "instructions", "sha256_prefix", "direct_call_sites"),
                        [(n, "%#x" % a, "%#x" % b, size, count, h, c) for n, a, b, size, count, h, c in pins]),
        "branches.tsv": tsv(("body", "va", "cc", "target"),
                            [(n, "%#x" % va, cc, "%#x" % (target & M64)) for n, va, cc, target in branches]),
        "field-offsets.tsv": tsv(("body", "displacement", "memory_operands"),
                                 [(n, "%#x" % d, c) for (n, d), c in sorted(offsets.items())]),
        "field-rules.tsv": tsv(("body", "field", "meaning"), FIELD_RULES),
        "locations.tsv": tsv(("name", "slot", "path", "line", "column"),
                             [(n, "%#x" % s, p, l, c) for n, s, p, l, c in locations]),
        "outcome-classes.tsv": tsv(("class", "cases"), sorted(classes.items())),
        "controls.tsv": tsv(("kind", "name", "detected", "by"), controls),
        "mutants.tsv": tsv(("body", "va", "kind", "result", "by"),
                           [(n, "%#x" % va, k, r, b) for n, va, k, r, b in mutants]),
        "coverage.tsv": tsv(("body", "va", "op", "a", "b"), coverage),
        "cases-walk-sample.tsv": tsv(("label", "levels", "count_vs_arena", "target", "flag", "levels_key_tag_head", "outcome"),
                                     [line.split("\t") for line in sample_rows["walk"]]),
        "cases-next-sample.tsv": tsv(("label", "levels", "height", "nodes", "yields"),
                                     [line.split("\t") for line in sample_rows["next"]]),
        "cases-scale-sample.tsv": tsv(("label", "fields_0x00_to_0x70", "outcome"),
                                      [line.split("\t") for line in sample_rows["scale"]]),
        "measure.json": json.dumps(measure, indent=1, sort_keys=True) + "\n",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--walks", type=int, default=10400)
    parser.add_argument("--nexts", type=int, default=1600)
    parser.add_argument("--scales", type=int, default=2000)
    parser.add_argument("--probe", type=int, default=250)
    parser.add_argument("--sample", type=int, default=3)
    args = parser.parse_args(argv)
    files = generate(args.walks, args.nexts, args.scales, args.probe, args.sample)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text, newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
