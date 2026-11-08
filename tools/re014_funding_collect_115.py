#!/usr/bin/env python3
"""Reconstruct how node #115 collects the per-asset funding premium: the sequential fold 0x24e5d00 and its two parallel bridge twins.

The funding premium body 0x44d9060 (merged as RE-014 funding premium) is reached through the .got slot 0x64e5f70. A byte scan of .text for
rip-relative references to that slot finds exactly three call sites, all inside collect loops: the 647-byte fold 0x24e5d00 and the two
1,446-byte parallel bridge bodies 0x5b34d90 and 0x5b39440. This tool runs the real bytes of all three in the evaluator of the merged
funding premium tool (premium body, B-tree walk, allocator, grow helper, join and thread registry are recording stubs) and compares every
run with a separately written model:

* fold: for every asset id of a slice, ids found in a u64 B-tree set are skipped; otherwise local = id % 10000 selects a 0x120 byte metadata
  row and a 0x60 byte oracle row (bounds panics with two Location records), the premium body is called, and a 24 byte record
  (id, none flag, f64 bits) is appended, growing the vector exactly when it is full.
* bridge: the split decision (halved length against the minimum, migrated flag, split budget, registry thread count), the underflow panic,
  the join closure fields, the merge of two linked lists of vector chunks, the empty case and the single node case with their
  deallocation calls.

No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/re014_funding_collect_115.py --out <dir>
"""

import argparse
import collections
import hashlib
import json
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import funding_premium115 as fp  # noqa: E402
from funding_premium115 import (  # noqa: E402
    EvidenceError, Halt, Panicked, HEAP_BASE, MASK, POISON, RAX, RBX, RCX, RDX, RSI, RDI, R8, R9, R12, R13, R14, R15, SHA256,
    STACK_TOP, decode_range, load_image,
)

FOLD = 0x24E5D00
BRIDGES = (0x5B34D90, 0x5B39440)
SLOT_PREMIUM = 0x64E5F70
SLOT_GROW = 0x64E4D28
SLOT_PANIC = 0x64DF620
SLOT_ALLOC = 0x64DF480
SLOT_ALLOC_FAIL = 0x64DF490
SLOT_FREE = 0x64DF4A0
SLOT_REGISTRY = 0x64E4E70
SLOT_SPLIT_PANIC = 0x64DF6B8
SPLIT_MESSAGE = 0x93EBAE
MARK = 0x7700000000

USED = 0x10000
SETOBJ = HEAP_BASE + 0x100
VECA = HEAP_BASE + 0x120
VECB = HEAP_BASE + 0x140
CTX = HEAP_BASE + 0x180
FOLDER = HEAP_BASE + 0x1C0
OUT = HEAP_BASE + 0x200
IDS = HEAP_BASE + 0x300
TLS = HEAP_BASE + 0x700
WORKER = HEAP_BASE + 0x720
REGISTRY = HEAP_BASE + 0x800
GLOBAL = HEAP_BASE + 0x780
ARENA = HEAP_BASE + 0x2000
ARG1 = 0x1234500000000001
ARG2 = 0x1234500000000002
ROW_A, ROW_B = 0x120, 0x60
NODE = 0xD0


def words(n, seed):
    state = seed & MASK[8]
    out = []
    for _ in range(n):
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        out.append(state)
    return out


def sentinel_word(k):
    return 0xCAFE000000000000 | k





# --- model (written from the instruction reading, no decoding) ---------------------------------------------------------------------------

def grown_cap(cap):
    return max(2 * cap, 4)


class Case:
    __slots__ = ("name", "ids", "members", "height", "chunks", "stale", "len_a", "len_b", "oracles", "premium", "cap", "len0",
                 "total", "mig", "splits", "minimum", "nthreads", "worker", "left", "right", "lens", "weird")

    def __init__(self, **kw):
        for key in self.__slots__:
            setattr(self, key, kw.get(key))


def premium_of(case, ident):
    """Deterministic fake premium answer for an id: (word0, tag, word2)."""
    a, b, c = words(3, (ident * 0x9E3779B97F4A7C15 ^ case.premium) & MASK[8])
    return b, (0 if a % 3 == 0 else 1 + b % 5), c


def model_fold(case, variant=None):
    """Predicted (outcome, log) of the sequential fold; `variant` names one deliberately wrong reading."""
    log, items = [], [(sentinel_word(i), i & 1, sentinel_word(100 + i)) for i in range(case.len0)]
    cap = case.cap
    for ident in case.ids:
        if (ident in case.members) != (variant == "skip_non_members"):
            continue
        local = ident % 10000 if variant != "mod_256" else ident % 256
        if local >= case.len_a:
            return ("panic", "A", local, case.len_a), log
        if local >= case.len_b:
            return ("panic", "B", local, case.len_b), log
        oracle = case.oracles[local]
        w0, tag, _ = premium_of(case, ident)
        log.append(("premium", ident, oracle, local))
        if len(items) == cap or (variant == "grow_early" and len(items) + 1 == cap):
            log.append(("grow", cap))
            cap = grown_cap(cap)
        zero_tag = tag == 0 if variant != "tag_one" else tag == 1
        if variant == "flag_inverted":
            items.append((ident, 0, oracle) if zero_tag else (ident, 1, w0))
        else:
            items.append((ident, 1, oracle) if zero_tag else (ident, 0, w0))
    return ("ok", cap, tuple(items)), log


def chain(label, caps):
    return [("node", label, i) for i in range(len(caps))]


def free_chain(label, caps):
    out = []
    for index, cap in enumerate(caps):
        if cap:
            out.append(("buf", label, index, 24 * cap))
        out.append(("node", label, index, 0x28))
    return out


def model_bridge(case, variant=None):
    """Predicted (outcome, log) of a bridge body."""
    n = len(case.ids)
    log = []
    half = case.total >> 1
    splits = case.splits
    split = False
    if half >= case.minimum or variant == "ignore_minimum":
        if case.mig:
            log.append(("tls",))
            if not case.worker:
                log.append(("global",))
            splits = max(splits >> 1, case.nthreads)
            split = True
        elif splits != 0:
            splits >>= 1
            split = True
    if split:
        if n < half:
            return ("panic", "split", n, half), log
        log.append(("join", half, splits, n - half))
        left, right = chain("L", case.left), chain("R", case.right)
        ll, rl = case.lens
        ltail = 0 if case.weird else (left[-1] if left else 0)
        if ltail == 0:
            outcome = ("list", right[0] if right else 0, right[-1] if right else 0, rl)
            return outcome, log + [("free",) + f for f in free_chain("L", case.left)]
        if not right:
            return ("list", left[0], ltail, ll), log
        link = ("link", ltail, right[0])
        return ("list", left[0], right[-1], ll + rl), log + [link]
    if n == 0:
        return ("list", 0, 0, 0), log
    outcome, leaf_log = model_fold(case, variant)
    log += leaf_log
    if outcome[0] == "panic":
        return outcome, log
    _, cap, items = outcome
    if not items:
        return ("list", 0, 0, 0), log
    return ("node", cap, items), log


# --- harness -------------------------------------------------------------------------------------------------------------------------

class Arena:
    def __init__(self):
        self.top = ARENA

    def alloc(self, size):
        at = self.top
        self.top = (self.top + size + 15) & ~15
        if self.top > HEAP_BASE + USED:
            raise Halt("arena exhausted")
        return at


def build_tree(memory, arena, shape, height, stale):
    keys, children = shape
    node = arena.alloc(NODE)
    memory.put_bytes(node, bytes(NODE * [0xC3]))
    for index, key in enumerate(keys):
        memory.write(node + 8 + 8 * index, 8, key)
    if stale is not None and len(keys) < 11:
        memory.write(node + 8 + 8 * len(keys), 8, stale)
    memory.write(node + 0x62, 2, len(keys))
    if children is not None:
        for index, child in enumerate(children):
            memory.write(node + 0x68 + 8 * index, 8, build_tree(memory, arena, child, height - 1, stale))
    return node


def panic_locations(image, start, end):
    """Panic Location pointers in address order: each `lea rdx,[rip+d]` directly followed by a call through the panic slot."""
    code = bytes(image.blob[image.offset(start):image.offset(start) + end - start])
    out, index = [], 0
    while True:
        index = code.find(b"\x48\x8d\x15", index)
        if index < 0 or index + 13 > len(code):
            return out
        if code[index + 7:index + 9] == b"\xff\x15":
            slot = start + index + 13 + struct.unpack_from("<i", code, index + 9)[0]
            if slot == SLOT_PANIC:
                out.append(start + index + 7 + struct.unpack_from("<i", code, index + 3)[0])
        index += 1


def direct_targets(image, start, end):
    return [row.target for row in decode_range(image, start, end) if row.op == "call" and row.target is not None]


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = fp.Machine(image, patches)
        self.case, self.log, self.arena = None, [], None
        self.labels, self.freed = {}, []
        self.locs = {}
        self.targets = {}
        statics = self.machine.memory.statics
        for slot, hook in ((SLOT_PREMIUM, self.on_premium), (SLOT_GROW, self.on_grow), (SLOT_PANIC, self.on_panic),
                           (SLOT_ALLOC, self.on_alloc), (SLOT_ALLOC_FAIL, self.on_alloc_fail), (SLOT_FREE, self.on_free),
                           (SLOT_REGISTRY, self.on_global), (SLOT_SPLIT_PANIC, self.on_split_panic)):
            statics[slot] = MARK + slot
            self.machine.slots[MARK + slot] = hook
        for entry in (FOLD,) + BRIDGES:
            start, end = image.exact_fde(entry)
            self.locs[entry] = {loc: name for loc, name in zip(panic_locations(image, start, end), ("A", "B"))}
            self.targets[entry] = direct_targets(image, start, end)[:2]

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_premium(self, machine):
        regs, mem = machine.regs, machine.memory
        ident = regs[RDX]
        local = ident % 10000
        self.expect(regs[RSI] == ARG1 and regs[R9] == ARG2, "premium owner and meta arguments")
        self.expect(regs[R8] == mem.read(VECA + 8, 8) + ROW_A * local, "metadata row")
        oracle = mem.read(mem.read(VECB + 8, 8) + ROW_B * local, 8)
        self.expect(regs[RCX] == oracle, "oracle word")
        w0, tag, w2 = premium_of(self.case, ident)
        self.log.append(("premium", ident, oracle, local))
        mem.write(regs[RDI], 8, w0)
        mem.write(regs[RDI] + 8, 8, tag)
        mem.write(regs[RDI] + 16, 8, w2)

    def on_grow(self, machine):
        regs, mem = machine.regs, machine.memory
        cap, ptr = mem.read(regs[RDI], 8), mem.read(regs[RDI] + 8, 8)
        self.log.append(("grow", cap))
        new_cap = grown_cap(cap)
        new_ptr = self.arena.alloc(24 * new_cap)
        if cap:
            mem.copy(new_ptr, ptr, 24 * cap)
        mem.write(regs[RDI], 8, new_cap)
        mem.write(regs[RDI] + 8, 8, new_ptr)

    def on_panic(self, machine):
        regs = machine.regs
        raise Panicked("%d %d %#x" % (regs[RDI], regs[RSI], regs[RDX]))

    def on_split_panic(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == SPLIT_MESSAGE and regs[RSI] == 0x13, "split panic message")
        raise Panicked("split 0 0x0")

    def on_alloc(self, machine):
        self.expect(machine.regs[RDI] == 0x28, "node size")
        machine.regs[RAX] = self.arena.alloc(0x28)

    def on_alloc_fail(self, machine):
        raise Panicked("alloc %d %d 0x0" % (machine.regs[RDI], machine.regs[RSI]))

    def on_free(self, machine):
        regs = machine.regs
        self.freed.append((regs[RDI], regs[RSI], regs[RDX] & MASK[4]))

    def on_global(self, machine):
        self.log.append(("global",))
        machine.regs[RAX] = GLOBAL

    def on_tls(self, machine):
        self.log.append(("tls",))
        machine.regs[RAX] = TLS

    def on_join(self, machine):
        regs, mem = machine.regs, machine.memory
        out, closure = regs[RDI], regs[RSI]
        case = self.case
        n, half = len(case.ids), case.total >> 1
        splits = mem.read(mem.read(closure + 0x10, 8), 8)
        self.expect(mem.read(mem.read(closure, 8), 8) == case.total, "closure total")
        self.expect(mem.read(mem.read(closure + 8, 8), 8) == half, "closure split point")
        self.expect(mem.read(closure + 0x18, 8) == IDS + 8 * half and mem.read(closure + 0x20, 8) == n - half, "right slice")
        self.expect(mem.read(closure + 0x28, 8) == CTX and mem.read(closure + 0x50, 8) == CTX, "context")
        self.expect(mem.read(closure + 0x40, 8) == IDS and mem.read(closure + 0x48, 8) == half, "left slice")
        self.log.append(("join", half, splits, n - half))
        left, right = self.nodes["L"], self.nodes["R"]
        ll, rl = case.lens
        ltail = 0 if case.weird else (left[-1] if left else 0)
        for index, value in enumerate((left[0] if left else 0, ltail, ll, right[0] if right else 0, right[-1] if right else 0, rl)):
            mem.write(out + 8 * index, 8, value)

    def make_chain(self, label, caps):
        mem, arena = self.machine.memory, self.arena
        nodes = [arena.alloc(0x28) for _ in caps]
        for index, (node, cap) in enumerate(zip(nodes, caps)):
            buf = arena.alloc(24 * max(cap, 1))
            mem.write(node, 8, cap)
            mem.write(node + 8, 8, buf)
            mem.write(node + 0x10, 8, 1 + index)
            mem.write(node + 0x18, 8, nodes[index + 1] if index + 1 < len(nodes) else 0)
            mem.write(node + 0x20, 8, nodes[index - 1] if index else 0)
            self.labels[node] = ("node", label, index)
            self.labels[buf] = ("buf", label, index)
        self.nodes[label] = nodes

    def prepare(self, case):
        m = self.machine
        mem = m.memory
        mem.reset(USED)
        m.xmm = [POISON | POISON << 64] * 16
        mem.put_bytes(HEAP_BASE, bytes((index * 29 + 5) & 0xFF for index in range(0x1000)))
        self.case, self.log, self.freed = case, [], []
        self.labels, self.nodes = {}, {"L": [], "R": []}
        self.arena = arena = Arena()
        if case.members:
            shape = fp.split_tree(sorted(case.members), case.height, list(case.chunks or ()))
            mem.write(SETOBJ, 8, build_tree(mem, arena, shape, case.height, case.stale))
            mem.write(SETOBJ + 8, 8, case.height)
        else:
            mem.write(SETOBJ, 8, 0)
            mem.write(SETOBJ + 8, 8, 0x77)
        rows_a = arena.alloc(ROW_A * max(1, case.len_a) + 16)
        rows_b = arena.alloc(ROW_B * max(1, case.len_b) + 16)
        mem.write(VECA + 8, 8, rows_a)
        mem.write(VECA + 0x10, 8, case.len_a)
        mem.write(VECB + 8, 8, rows_b)
        mem.write(VECB + 0x10, 8, case.len_b)
        for index in range(min(case.len_b, len(case.oracles))):
            mem.write(rows_b + ROW_B * index, 8, case.oracles[index])
        for field, value in ((0, SETOBJ), (8, VECA), (0x10, ARG1), (0x18, VECB), (0x20, ARG2)):
            mem.write(CTX + field, 8, value)
        for index, ident in enumerate(case.ids):
            mem.write(IDS + 8 * index, 8, ident)
        mem.write(TLS, 8, WORKER if case.worker else 0)
        mem.write(WORKER + 0x110, 8, REGISTRY)
        mem.write(GLOBAL, 8, REGISTRY)
        mem.write(REGISTRY + 0x208, 8, case.nthreads or 0)
        if case.left is not None:
            self.make_chain("L", case.left)
            self.make_chain("R", case.right)
        return bytes(mem.heap[:0x2000])

    def read_items(self, ptr, count):
        mem = self.machine.memory
        return tuple((mem.read(ptr + 24 * i, 8), mem.read(ptr + 24 * i + 8, 8), mem.read(ptr + 24 * i + 16, 8)) for i in range(count))

    def drive_fold(self, case):
        m, mem = self.machine, self.machine.memory
        self.prepare(case)
        buffer = self.arena.alloc(24 * max(1, case.cap) + 16)
        for index in range(case.len0):
            for part, value in enumerate((sentinel_word(index), index & 1, sentinel_word(100 + index))):
                mem.write(buffer + 24 * index + 8 * part, 8, value)
        for index, value in enumerate((case.cap, buffer, case.len0, CTX)):
            mem.write(FOLDER + 8 * index, 8, value)
        returned = m.run(FOLD, {RDI: OUT, RSI: FOLDER, RDX: IDS, RCX: IDS + 8 * len(case.ids)})
        self.expect(returned == OUT, "returned pointer")
        cap, ptr, length, ctx = (mem.read(OUT + 8 * index, 8) for index in range(4))
        self.expect(ctx == CTX and mem.read(FOLDER + 0x18, 8) == CTX, "context word")
        self.expect(length < 200 and ptr != 0, "length")
        return ("ok", cap, self.read_items(ptr, length))

    def drive_bridge(self, case, entry):
        m, mem = self.machine, self.machine.memory
        self.prepare(case)
        targets = self.targets[entry]
        m.calls = {targets[0]: self.on_tls, targets[1]: self.on_join}
        top = STACK_TOP - 0x100
        mem.write(top, 8, len(case.ids))
        mem.write(top + 8, 8, CTX)
        returned = m.run(entry, {RDI: OUT, RSI: case.total, RDX: case.mig, RCX: case.splits, R8: case.minimum, R9: IDS})
        self.expect(returned == OUT, "returned pointer")
        head, tail, length = (mem.read(OUT + 8 * index, 8) for index in range(3))
        if any(row[0] == "join" for row in self.log) or not head:
            def name(address):
                return self.labels.get(address, address) if address else 0
            return ("list", name(head), name(tail), length)
        self.expect(head == tail and length == 1, "single node list")
        self.expect(mem.read(head + 0x18, 8) == 0 and mem.read(head + 0x20, 8) == 0, "node links")
        return ("node", mem.read(head, 8), self.read_items(mem.read(head + 8, 8), mem.read(head + 0x10, 8)))

    def run(self, case, entry):
        self.machine.seen = set()
        try:
            outcome = self.drive_fold(case) if entry == FOLD else self.drive_bridge(case, entry)
        except Panicked as panic:
            parts = str(panic).split()
            index = parts[0]
            if index == "alloc":
                outcome = ("panic", "alloc", 0, 0)
            elif index == "split":
                outcome = ("panic", "split", len(self.case.ids), self.case.total >> 1)
            else:
                outcome = ("panic", self.locs[entry].get(int(parts[2], 16), "other"), int(index), int(parts[1]))
        except (Halt, EvidenceError, IndexError, KeyError, ValueError, OverflowError, struct.error) as problem:
            self.last_halt = str(problem)
            return ("halt", type(problem).__name__), []
        log = list(self.log)
        for address, size, align in self.freed:
            label = self.labels.get(address)
            log.append(("free",) + (label if label else ("vec",)) + (size,))
        if outcome[0] == "list":
            # links are observable in memory: the left tail must now point at the right head and back
            left, right = self.nodes["L"], self.nodes["R"]
            if left and right and any(row[0] == "join" for row in self.log) and not self.case.weird:
                mem = self.machine.memory
                if mem.read(left[-1] + 0x18, 8) == right[0] and mem.read(right[0] + 0x20, 8) == left[-1]:
                    log.append(("link", ("node", "L", len(left) - 1), ("node", "R", 0)))
        return outcome, log


def expected_log(rows, case):
    return list(rows)


# --- cases ---------------------------------------------------------------------------------------------------------------------------

def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11


def make_cases(count, seed=0xF00D5EED):
    stream = lcg(seed)

    def draw(n):
        return next(stream) % n

    for index in range(count):
        kind = ("fold", "bridge", "bridge")[index % 3]
        len_a = 1 + draw(9)
        len_b = len_a if draw(8) else 1 + draw(9)
        nids = draw(7) if kind == "fold" else draw(9)
        ids = []
        members = set()
        for _ in range(nids):
            local = draw(len_a + (2 if draw(14) == 0 else 0))
            ident = draw(40) * 10000 + local
            ids.append(ident)
            if draw(3) == 0:
                members.add(ident)
        if draw(5) == 0 and ids:
            members.add(ids[0] + 10000 * 50)
        for _ in range(draw(12) if members else 0):
            members.add(draw(60) * 10000 + draw(9))
        oracles = [next(stream) if draw(4) else (0x7FF8000000000000 | draw(5)) for _ in range(max(len_a, len_b, 10000 if False else 1))]
        height = 0 if len(members) <= 11 and draw(3) else 1 + draw(3)
        if len(members) > 11 and height == 0:
            height = 1
        case = Case(name="%s-%d" % (kind, index), ids=ids, members=members, height=height,
                    chunks=[2 + draw(4) for _ in range(3)], stale=ids[0] if ids and draw(3) == 0 and ids[0] not in members else None,
                    len_a=len_a, len_b=len_b, oracles=oracles, premium=next(stream), cap=0, len0=0,
                    total=0, mig=0, splits=0, minimum=0, nthreads=0, worker=0, left=None, right=None, lens=(0, 0), weird=False)
        if kind == "fold":
            case.cap = draw(7)
            case.len0 = draw(case.cap + 1)
        else:
            n = len(ids)
            case.total = n if draw(5) else draw(2 * n + 3)
            case.minimum = draw(6)
            case.mig = draw(2)
            case.splits = draw(4)
            case.nthreads = draw(5)
            case.worker = draw(2)
            case.left = [draw(3) * 2 for _ in range(draw(4))]
            case.right = [draw(3) * 2 for _ in range(draw(4))]
            case.lens = (draw(50), draw(50))
            case.weird = draw(9) == 0
        yield case


def fix_members(case):
    """A hash set holding ids must keep the lookups meaningful: nothing to adjust, kept for readability."""
    return case


# --- run and compare -----------------------------------------------------------------------------------------------------------------------

def compare(harness, case, entry, variant=None):
    got = harness.run(case, entry)
    if entry == FOLD:
        outcome, log = model_fold(case, variant)
    else:
        outcome, log = model_bridge(case, variant)
    return got, (outcome, expected_log(log, case))


VARIANTS = ("skip_non_members", "mod_256", "grow_early", "tag_one", "flag_inverted", "ignore_minimum")


def digest(value):
    return hashlib.sha256(repr(value).encode()).hexdigest()[:12]


def run_stream(harness, count, reached):
    stats = {"cases": 0, "mismatches": 0, "first": None, "kinds": collections.Counter()}
    caught = {name: 0 for name in VARIANTS}
    rows = []
    for index, case in enumerate(make_cases(count)):
        entries = (FOLD,) if case.name.startswith("fold") else BRIDGES
        for entry in entries:
            got, want = compare(harness, case, entry)
            reached[entry].update(harness.machine.seen)
            stats["cases"] += 1
            stats["kinds"][(entry, want[0][0] if want[0][0] != "list" else "list", len(case.ids) > 0)] += 1
            if got != want:
                stats["mismatches"] += 1
                stats["first"] = stats["first"] or (index, case.name, got, want)
            for name in VARIANTS:
                if (entry == FOLD or name in ("ignore_minimum", "skip_non_members", "mod_256", "grow_early", "tag_one", "flag_inverted")):
                    other = (model_fold(case, name) if entry == FOLD else model_bridge(case, name))
                    if (other[0], expected_log(other[1], case)) != got:
                        caught[name] += 1
            if index % 40 == 0:
                rows.append((index, case.name, "%#x" % entry, len(case.ids), want[0][0], digest(got)))
    return stats, caught, rows


def mutants_of(image, reached, entry):
    out = []
    start, end = image.exact_fde(entry)
    for row in decode_range(image, start, end):
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
            if operand and operand[0] == "m" and operand[1] is not None and 0x10 <= abs(operand[4]) < 0x200:
                disp = operand[4]
                packed = struct.pack("<i", disp) if abs(disp) >= 128 else struct.pack("<b", disp)
                spot = bytes(data).find(packed)
                if spot >= 0 and bytes(data).count(packed) == 1:
                    out.append((row.va, "displacement", row.va + spot, data[spot], data[spot] ^ 8))
    return out


def run_mutants(image, entry, mutants, cases):
    rows = []
    for va, kind, at, old, new in mutants:
        harness = Harness(image, {at: new})
        harness.machine.step_limit = 20000
        killed, first = False, ""
        for index, case in enumerate(cases):
            got, want = compare(harness, case, entry)
            if got != want:
                killed, first = True, str(index)
                break
        rows.append((entry, va, kind, at, old, new, killed, first))
    return rows


def structural_controls(image, harness, cases):
    """(name, detected, how): wrong readings of the bytes and corrupted inputs that must be refused."""
    out = []
    sample = [c for c in cases if c.name.startswith("fold") and len(c.ids) >= 2][:60]

    def refused(name, make, entry=FOLD, pool=None):
        pool = pool or sample
        hit = ""
        for case in pool:
            changed = make(case)
            if changed is None:
                continue
            got = harness.run(changed, entry)
            want = (model_fold if entry == FOLD else model_bridge)(case)
            if (got[0], got[1]) != (want[0], expected_log(want[1], case)):
                hit = case.name
                break
        out.append((name, bool(hit), hit or "not detected"))

    def clone(case, **kw):
        fields = {key: getattr(case, key) for key in Case.__slots__}
        fields.update(kw)
        return Case(**fields)

    refused("stale oracle word", lambda c: clone(c, oracles=[x ^ 1 for x in c.oracles]) if c.ids else None, pool=None)
    refused("model premium seed differs", lambda c: clone(c, premium=c.premium + 1))
    refused("one more member in the set", lambda c: clone(c, members=set(c.members) | {c.ids[0]}) if c.ids[0] not in c.members else None)
    refused("one member removed from the set", lambda c: clone(c, members=set(c.members) - {c.ids[0]}) if c.ids[0] in c.members else None)
    refused("metadata vector shortened by one", lambda c: clone(c, len_a=max(0, c.len_a - 1)))
    refused("oracle vector shortened by one", lambda c: clone(c, len_b=max(0, c.len_b - 1)))
    refused("capacity changed", lambda c: clone(c, cap=c.cap + 1))
    refused("length one above capacity claim", lambda c: clone(c, len0=c.len0 + 1) if c.len0 < c.cap else None)
    refused("id modulo 9999", lambda c: clone(c, ids=[x + (x // 10000) for x in c.ids]))
    refused("id slice truncated", lambda c: clone(c, ids=c.ids[:-1]))
    refused("set object emptied", lambda c: clone(c, members=set()) if c.members else None)
    bridge_pool = [c for c in cases if c.name.startswith("bridge") and len(c.ids) >= 2][:80]
    for entry in BRIDGES:
        refused("bridge %#x total changed" % entry, lambda c: clone(c, total=c.total + 4), entry, bridge_pool)
        refused("bridge %#x minimum changed" % entry, lambda c: clone(c, minimum=c.minimum + 1), entry, bridge_pool)
        refused("bridge %#x split budget changed" % entry, lambda c: clone(c, splits=c.splits + 2), entry, bridge_pool)
        refused("bridge %#x migrated flag flipped" % entry, lambda c: clone(c, mig=1 - c.mig), entry, bridge_pool)
        refused("bridge %#x thread count changed" % entry, lambda c: clone(c, nthreads=c.nthreads + 1) if c.mig else None, entry, bridge_pool)
    # bytes and addresses
    try:
        load_image(fp.BINARY, "0" * 64)
        out.append(("corrupted binary digest accepted", False, "accepted"))
    except EvidenceError:
        out.append(("corrupted binary digest refused", True, "EvidenceError"))
    for name, address in (("address inside a function body", FOLD + 1), ("address before .text", 0x1000), ("address past the file", 1 << 40)):
        try:
            image.exact_fde(address)
            out.append((name + " accepted as a function start", False, "accepted"))
        except EvidenceError:
            out.append((name + " refused as a function start", True, "EvidenceError"))
    flipped = Harness(image, {FOLD + 0xFB: image.blob[image.offset(FOLD + 0xFB)] ^ 0xFF})
    flipped.machine.step_limit = 20000
    got = flipped.run(sample[0], FOLD)
    want = model_fold(sample[0])
    out.append(("flipped byte of the 10000 immediate", (got[0], got[1]) != (want[0], expected_log(want[1], sample[0])), "model comparison"))
    return out


def normal_operand(operand):
    """Operand with absolute (rip-relative) addresses reduced to a marker so two copies at different addresses compare."""
    if operand and operand[0] == "m" and operand[1] is None and operand[2] is None:
        return ("m", "absolute")
    return operand


def twin_rows(image):
    """Instruction level comparison of the two bridge bodies: offsets whose decoded form differs, and why."""
    (a0, a1), (b0, b1) = (image.exact_fde(entry) for entry in BRIDGES)
    left, right = decode_range(image, a0, a1), decode_range(image, b0, b1)
    rows = [("length", "%d" % (a1 - a0), "%d" % (b1 - b0), "")]
    rows.append(("instructions", str(len(left)), str(len(right)), ""))
    for one, two in zip(left, right):
        offset = one.va - a0
        if offset != two.va - b0:
            rows.append(("misaligned", "%#x" % offset, "%#x" % (two.va - b0), one.op))
            break
        if (one.op, one.width, one.cc) != (two.op, two.width, two.cc):
            rows.append(("opcode", "%#x" % offset, "", "%s/%s" % (one.op, two.op)))
            continue
        a_ops = (normal_operand(one.a), normal_operand(one.b))
        b_ops = (normal_operand(two.a), normal_operand(two.b))
        if a_ops != b_ops:
            rows.append(("operand", "%#x" % offset, "", one.op))
        if one.target is not None and two.target is not None:
            inside = (a0 <= one.target < a1, b0 <= two.target < b1)
            if inside == (True, True) and one.target - a0 != two.target - b0:
                rows.append(("branch", "%#x" % offset, "", one.op))
            elif inside != (True, True) and one.target != two.target:
                rows.append(("external-target", "%#x" % offset, "%#x" % one.target, "%#x" % two.target))
    return rows


REGISTER_NAMES = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
TEN_THOUSAND = 10000


def function_code(image, entry):
    start, end = image.exact_fde(entry)
    at = image.offset(start)
    return start, bytes(image.blob[at:at + end - start])


def division_rows(image):
    """The `id % 10000` of every body: the movabs magic, the shift and the multiplier are read as byte patterns; the identity
    floor(x * m / 2^75) == floor(x / 10000) for every 64-bit x follows from 0 <= m * 10000 - 2^75 <= 2^11, which is checked here."""
    rows = []
    for entry in (FOLD,) + BRIDGES:
        start, code = function_code(image, entry)
        magics = [(m.start(), int.from_bytes(m.group(1), "little")) for m in re.finditer(rb"[\x48\x49][\xb8-\xbf](.{8})", code, re.S)
                  if int.from_bytes(m.group(1), "little") > 1 << 60]
        shifts = [m.start() for m in re.finditer(rb"\x48\xc1[\xe8-\xef]\x0b", code)]
        mults = [m.start() for m in re.finditer(rb"\x48\x69[\xc0-\xff]\x10\x27\x00\x00", code)]
        if len(magics) != 1 or len(shifts) != 1 or len(mults) != 1:
            raise EvidenceError("expected one magic, one shift and one multiplier in %#x" % entry)
        magic = magics[0][1]
        slack = magic * TEN_THOUSAND - (1 << 75)
        exact = 0 <= slack <= 1 << 11
        edges = [0, 1, 9999, 10000, 10001, MASK[8], MASK[8] - 1, 1 << 63, (MASK[8] // 10000) * 10000, (MASK[8] // 10000) * 10000 - 1]
        agree = all((x * magic >> 64) >> 11 == x // 10000 for x in edges)
        rows.append(("%#x" % entry, "%#x" % (start + magics[0][0]), "%#x" % magic, "%#x" % (start + shifts[0]),
                     "%#x" % (start + mults[0]), slack, int(exact), int(agree)))
    return rows


def field_rows(image):
    """Every (function, base register, displacement) of a memory operand with a base register, with its access count."""
    out = []
    for entry in (FOLD,) + BRIDGES:
        start, end = image.exact_fde(entry)
        counts = collections.Counter()
        for row in decode_range(image, start, end):
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is not None and operand[1] != 4:
                    counts[(operand[1], operand[4])] += 1
        out += [("%#x" % entry, REGISTER_NAMES[reg], "%#x" % (disp & MASK[8]) if disp >= 0 else "-%#x" % -disp, n)
                for (reg, disp), n in sorted(counts.items())]
    return out


def scan_call_sites(image):
    """Every rip-relative reference to a given .got slot in .text: (site, slot name, bytes)."""
    start, code = image.text_bytes()
    slots = {SLOT_PREMIUM: "premium"}
    out = []
    for index in range(len(code) - 6):
        if code[index] == 0xFF and code[index + 1] == 0x15:
            target = start + index + 6 + struct.unpack_from("<i", code, index + 2)[0]
            if target in slots:
                out.append((start + index, slots[target]))
    return out


def function_rows(image, reached):
    rows = []
    for entry in (FOLD,) + BRIDGES:
        start, end = image.exact_fde(entry)
        insns = decode_range(image, start, end)
        rows.append(("%#x" % entry, end - start, len(insns), len(reached[entry])))
    return rows


def analyse(count=7000, mutant_pool=160, image=None):
    image = image or load_image()
    harness = Harness(image)
    reached = {entry: set() for entry in (FOLD,) + BRIDGES}

    class Hits(dict):
        def __missing__(self, key):
            return self.setdefault(key, set())

    hits = collections.defaultdict(set)
    stats, caught, sample = run_stream(harness, count, hits)
    cases = list(make_cases(max(count, 600)))
    controls = structural_controls(image, harness, cases)
    mutants = []
    for entry in (FOLD,) + BRIDGES:
        pool = [c for c in cases if c.name.startswith("fold" if entry == FOLD else "bridge")][:mutant_pool]
        mutants += run_mutants(image, entry, mutants_of(image, hits[entry], entry), pool)
    return {"image": image, "stats": stats, "caught": caught, "sample": sample, "hits": hits, "controls": controls,
            "mutants": mutants, "sites": scan_call_sites(image), "harness": harness}


def render(result):
    image, stats, hits = result["image"], result["stats"], result["hits"]
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"

    harness = result["harness"]
    tsv("call-sites.tsv", ("site", "slot", "owner"),
        [("%#x" % site, name, "%#x" % image.fde(site)[0]) for site, name in result["sites"]])
    tsv("bridge-twins.tsv", ("difference", "offset_or_left", "right_or_target", "detail"), twin_rows(image))
    tsv("division-by-10000.tsv", ("function", "magic_at", "magic", "shift_at", "multiplier_at", "slack", "exact_for_all_u64", "edges_agree"),
        division_rows(image))
    tsv("field-offsets.tsv", ("function", "base_register", "displacement", "accesses"), field_rows(image))
    tsv("functions.tsv", ("function", "bytes", "instructions", "reached"), function_rows(image, hits))
    tsv("panic-locations.tsv", ("function", "which", "location"),
        [("%#x" % entry, name, "%#x" % loc) for entry in (FOLD,) + BRIDGES for loc, name in sorted(harness.locs[entry].items())])
    tsv("bridge-calls.tsv", ("function", "first_direct_call", "second_direct_call"),
        [("%#x" % entry, "%#x" % harness.targets[entry][0], "%#x" % harness.targets[entry][1]) for entry in BRIDGES])
    tsv("outcomes.tsv", ("function", "outcome", "non_empty_slice", "cases"),
        [("%#x" % e, o, int(n), c) for (e, o, n), c in sorted(stats["kinds"].items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2]))])
    tsv("cases-sample.tsv", ("index", "name", "function", "slice_length", "outcome", "digest"), result["sample"])
    tsv("variants.tsv", ("wrong_reading", "cases_refused"), sorted(result["caught"].items()))
    tsv("structural-controls.tsv", ("control", "detected", "how"), [(n, int(d), h) for n, d, h in result["controls"]])
    tsv("mutants.tsv", ("function", "address", "kind", "edited_byte_at", "old", "new", "killed", "first_case"),
        [("%#x" % e, "%#x" % va, kind, "%#x" % at, old, new, int(k), first) for e, va, kind, at, old, new, k, first in result["mutants"]])
    detected = sum(1 for n in result["caught"].values() if n) + sum(1 for _, d, _ in result["controls"] if d)
    total_controls = len(result["caught"]) + len(result["controls"])
    killed = sum(1 for row in result["mutants"] if row[6])
    evidence = {"binary_sha256": SHA256, "functions": ["%#x" % e for e in (FOLD,) + BRIDGES], "cases": stats["cases"],
                "mismatches": stats["mismatches"], "first_mismatch": stats["first"], "mutants": len(result["mutants"]),
                "mutants_killed": killed}
    files["evidence.json"] = json.dumps(evidence, indent=1, sort_keys=True, default=str) + "\n"
    files["measure.json"] = json.dumps({"cases": stats["cases"], "negative_controls": total_controls + killed,
                                        "negative_detected": detected + killed, "mismatches": stats["mismatches"],
                                        "mutants": len(result["mutants"]), "mutants_killed": killed, "mutants_survived": len(result["mutants"]) - killed}, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = analyse()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = render(result)
    for name, text in files.items():
        (out / name).write_text(text)
    print(files["measure.json"], end="")
    return 0 if result["stats"]["mismatches"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
