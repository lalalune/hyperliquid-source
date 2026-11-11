"""Reconstruct the node #115 hash signature tracker prior-lookup and watermark bodies (abci).

Four bodies of `l1/src/abci/hash_signature_tracker.rs` are covered: the prior-hash lookups
0x2BAFCE0 / 0x2BAFF80 (height -> entry through a ring or a map, then a 32-byte hash set or
deque test, then an element iterator handed to a collector) and the watermark / cutoff
bodies 0x27605D0 / 0x27604D0 (running maximum, seal marker, saturating 50000 cutoff, helper
descriptor release). Each body's real instruction bytes run in the shared evaluator of
tools/decimal_scaled_u64.py with every callee replaced by a logging stub; the result words,
the tracker writes and the ordered callee log are compared with `lookup` and `watermark`,
independently written Python reconstructions. Every conditional jump is flipped and must be
caught, and deliberately wrong reconstructions are negative controls. The target is read,
never executed. Every number in the output comes from ELF bytes or from these runs.
"""
import argparse
import copy
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as cpu  # noqa: E402  shared #115 evaluator (Image, decode, Machine)

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
U64 = (1 << 64) - 1
NONE_VEC = 1 << 63
COLLECTED = 0x7300_1234
DESC_PTR = 0x7400_0000
CUTOFF = 0xC350
MEMCMP = 0x5000_0000
MEMCMP_SLOT = 0x64DFB50

LOOKUPS = {
    0x2BAFCE0: {"search": 0x1D65B20, "ring": 0x24C9200, "probe": 0x24C6B60, "collect": 0x236E750},
    0x2BAFF80: {"search": 0x1D65B20, "ring": 0x24C9200, "probe": 0x24C6B60, "collect": 0x236FF70},
}
WATERMARKS = {
    0x27605D0: {"locate": 0x2DAF740, "helper": 0x28AC490},
    0x27604D0: {"locate": 0x2DAF740, "helper": 0x28ACED0},
}
BODIES = {**LOOKUPS, **WATERMARKS}

OUT, TRACKER, HASHP = (cpu.INPUT + i * 0x1000 for i in range(3))
RING = cpu.INPUT + 0x4000          # tracker ring buffer, 80-byte entries, +8 to the entry
MAPNODE = cpu.INPUT + 0x8000       # map leaf, 72-byte slots, +0x60 to the entry
TREE = cpu.INPUT + 0x10000         # hash-set nodes, 0x500 apart
DEQUE = cpu.INPUT + 0x20000        # entry deque buffer, 96-byte elements
OBJ = cpu.INPUT + 0x30000          # watermark: fourth argument
ENTRY_SP = cpu.STACK - 0x800
STEP_LIMIT = 6000
HASH = bytes(0x40 + i for i in range(32))
HEIGHT = 0x1234_5678_9ABC


class Fail(Exception):
    pass


def load_image():
    data = TARGET.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise Fail(f"target digest {digest} != {SHA256}")
    return cpu.Image(data)


# ---------------------------------------------------------------- static facts from bytes

def body_insns(image, start):
    lo, hi = image.fde_of(start)
    if lo != start:
        raise Fail(f"{start:#x} is not an FDE start")
    out, va = [], lo
    while va < hi:
        insn = image.fetch(va)
        out.append(insn)
        if insn.key == 0xCC:
            break
        va += insn.size
    return lo, hi, out


def slot_of(image, insn):
    if insn.modrm is None:
        return None
    modrm = image.data[insn.modrm]
    if modrm & 0xC7 != 0x05:
        return None
    return insn.va + insn.size + struct.unpack_from("<i", image.data, insn.modrm + 1)[0]


def call_rows(image, start):
    rows = []
    for insn in body_insns(image, start)[2]:
        if insn.key == 0xE8:
            rows.append((insn.va, "call", insn.target, ""))
        elif insn.key == 0xFF and (image.data[insn.modrm] >> 3) & 7 == 2:
            slot = slot_of(image, insn)
            if slot is not None:
                rows.append((insn.va, "slot_call", image.slots.get(slot, 0), f"slot={slot:#x}"))
    return rows


def rip_leas(image, start):
    """Targets of every rip-relative lea in byte order."""
    return [slot_of(image, i) for i in body_insns(image, start)[2]
            if i.key == 0x8D and slot_of(image, i) is not None]


def slot_calls(image, start):
    return [(i.va, slot_of(image, i)) for i in body_insns(image, start)[2]
            if i.key == 0xFF and (image.data[i.modrm] >> 3) & 7 == 2 and slot_of(image, i) is not None]


def trace_flag_address(image, start):
    for insn in body_insns(image, start)[2]:
        if insn.key == 0x8B and slot_of(image, insn) is not None:
            return slot_of(image, insn)
    raise Fail(f"no flag load in {start:#x}")


def jcc_sites(image, start):
    rows = []
    for insn in body_insns(image, start)[2]:
        if isinstance(insn.key, int) and 0x70 <= insn.key <= 0x7F:
            rows.append((insn.va, insn.off + insn.size - 2))
        elif isinstance(insn.key, tuple) and len(insn.key) == 2 and 0x80 <= insn.key[1] <= 0x8F:
            rows.append((insn.va, insn.off + insn.size - 5))
    return rows


def watermark_slots(image, start):
    """(dealloc slot target, trace slot target): the release call sits in the straight line,
    the trace call in the out-of-line block after it."""
    calls = slot_calls(image, start)
    if len(calls) != 2 or calls[0][0] > calls[1][0]:
        raise Fail(f"unexpected slot calls in {start:#x}")
    return image.slots[calls[0][1]], image.slots[calls[1][1]]


# ---------------------------------------------------------------- evaluator with stubs

class Machine(cpu.Machine):
    def __init__(self, image, case, roles):
        super().__init__(image)
        self.case, self.roles, self.log = case, roles, []
        self.by_target = {t: r for r, t in roles.items()}

    def step(self):
        insn = self.image.fetch(self.pc)
        here, data = self.pc, self.image.data
        key = insn.key
        self.seen.add(here)
        if key == 0x98 and insn.rex & 8:          # cdqe
            self.pc = here + insn.size
            v = self.get(cpu.RAX, 32)
            self.put(cpu.RAX, 64, None if v is None else (v - (1 << 32) if v >> 31 else v) & U64)
            return
        if key == 0xFF and (data[insn.modrm] >> 3) & 7 == 6:   # push r/m64
            self.pc = here + insn.size
            v = self.read(self.operand(insn), 64)
            sp = self.get(cpu.RSP, 64) - 8
            self.set_reg(cpu.RSP, sp)
            self.store(sp, 8, v)
            return
        if key == 0xFF and (data[insn.modrm] >> 3) & 7 == 2 and data[insn.modrm] >> 6 == 3:
            self.pc = here + insn.size                   # call reg
            target = self.get((data[insn.modrm] & 7) | ((insn.rex & 1) << 3), 64)
            if target is None:
                cpu.fail(f"call through unknown register at {here:#x}")
            self.call(target, here)
            return
        if key == 0xFF and (data[insn.modrm] >> 3) & 7 == 2 and slot_of(self.image, insn) == MEMCMP_SLOT:
            self.pc = here + insn.size                   # call [GLOB_DAT memcmp]
            self.call(MEMCMP, here)
            return
        super().step()

    def bytes_at(self, at, n):
        return [self.mem.get(at + i) for i in range(n)]

    def call(self, target, where):
        role = "memcmp" if target == MEMCMP else self.by_target.get(target)
        if role is None:
            raise cpu.Done(f"unexpected call {target:#x}", where)
        a = [self.get(r, 64) for r in (cpu.RDI, cpu.RSI, cpu.RDX, cpu.RCX, cpu.R8, cpu.R9)]
        ret = getattr(self, "stub_" + role)(a)
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        for reg, value in (ret or {}).items():
            self.set_reg(reg, value)
        self.flags = [None, None, None, None]
        self.pc = where + self.image.fetch(where).size

    # lookup callees
    def stub_memcmp(self, a):
        left, right = self.bytes_at(a[0], a[2]), self.bytes_at(a[1], a[2])
        if None in left or None in right:
            cpu.fail("memcmp of unknown bytes")
        self.log.append(("cmp", a[1]))
        for x, y in zip(left, right):
            if x != y:
                return {cpu.RAX: (x - y) & U64}
        return {cpu.RAX: 0}

    def stub_search(self, a):
        self.log.append(("search", a[1], a[2], self.load(a[3], 8)))
        found = self.case["found"]
        self.store(a[0], 4, 0 if found else 1)
        self.store(a[0] + 8, 8, MAPNODE)
        self.store(a[0] + 0x18, 8, self.case["sidx"])

    def stub_ring(self, a):
        self.log.append(("ring", a[0], self.load(a[1], 8)))
        return {cpu.RAX: self.case["rerr"], cpu.RDX: self.case["ridx"]}

    def stub_probe(self, a):
        self.log.append(("probe", a[0], bytes(self.bytes_at(a[1], 32))))
        return {cpu.RAX: self.case["probe"]}

    def stub_collect(self, a):
        words = tuple(self.load(a[1] + 8 * i, 8) for i in range(9))
        self.log.append(("collect", a[0], words))
        self.store(a[0], 8, COLLECTED)

    # watermark callees
    def stub_locate(self, a):
        self.log.append(("locate", a[0] - ENTRY_SP, a[1], a[2], a[3], a[4]))

    def stub_helper(self, a):
        sp = self.get(cpu.RSP, 64)
        self.log.append(("helper", a[0] - ENTRY_SP, a[1], a[2], a[3], a[4], self.load(sp, 8)))
        self.store(a[0], 8, self.case["count"])
        self.store(a[0] + 8, 8, DESC_PTR)

    def stub_dealloc(self, a):
        self.log.append(("dealloc", a[0], a[1], a[2]))

    def stub_trace(self, a):
        self.log.append(("trace", a[0], a[1], a[3], a[4]))


# ---------------------------------------------------------------- memory layouts

def cmp_sign(a, b):
    return (a > b) - (a < b)


def key_for(rel, j):
    """A 32-byte key that compares below / equal / above HASH, first differing byte j."""
    k = bytearray(HASH)
    if rel == "<":
        k[j] -= 1
    elif rel == ">":
        k[j] += 1
    return bytes(k)


def lay_tree(m, nodes):
    """nodes: list of {"keys": [bytes], "kids": [index]}; node k lives at TREE + k * 0x500."""
    for k, node in enumerate(nodes):
        base = TREE + k * 0x500
        m.store(base + 0x42A, 2, len(node["keys"]))
        for i, key in enumerate(node["keys"]):
            for j, b in enumerate(key):
                m.store(base + 0x2C0 + 32 * i + j, 1, b)
        for i, kid in enumerate(node["kids"]):
            m.store(base + 0x430 + 8 * i, 8, TREE + kid * 0x500)


def entry_address(case):
    if case["form"] == "map":
        return MAPNODE + case["sidx"] * 72 + 0x60
    return RING + (case["ridx"] + case["head"] - (case["cap"] if case["ridx"] + case["head"] >= case["cap"] else 0)) * 80 + 8


def lookup_setup(m, case):
    for reg in range(16):
        m.set_reg(reg, 0x0BAD_0000 + reg * 0x100)
    m.set_reg(cpu.RDI, OUT)
    m.set_reg(cpu.RSI, TRACKER)
    m.set_reg(cpu.RDX, HEIGHT)
    m.set_reg(cpu.RCX, HASHP)
    m.set_reg(cpu.RSP, ENTRY_SP)
    m.store(ENTRY_SP, 8, cpu.RETURN_MARK)
    m.store(MEMCMP_SLOT, 8, MEMCMP)
    m.store(OUT, 8, 0xEEEE_EEEE)
    for i, b in enumerate(HASH):
        m.store(HASHP + i, 1, b)
    if case["form"] == "map":
        m.store(TRACKER + 0x18, 8, NONE_VEC)
        m.store(TRACKER + 0x20, 8, MAPNODE if case["root"] else 0)
        m.store(TRACKER + 0x28, 8, case["trh"])
    else:
        m.store(TRACKER + 0x18, 8, case["cap"])
        m.store(TRACKER + 0x20, 8, RING)
        m.store(TRACKER + 0x28, 8, case["head"])
        m.store(TRACKER + 0x30, 8, case["len"])
    e = case["entry"]
    base = entry_address(case)
    m.store(base, 8, e["w0"])
    m.store(base + 8, 8, e["w8"])
    m.store(base + 0x10, 8, e["w10"])
    m.store(base + 0x18, 8, e["w18"])
    lay_tree(m, e.get("nodes", []))


def watermark_setup(m, case, flag_address):
    for reg in range(16):
        m.set_reg(reg, 0x0BAD_0000 + reg * 0x100)
    m.set_reg(cpu.RDI, TRACKER)
    m.set_reg(cpu.RSI, case["h"])
    m.set_reg(cpu.RDX, 0x5151_0000)
    m.set_reg(cpu.RCX, OBJ)
    m.set_reg(cpu.RSP, ENTRY_SP)
    m.store(ENTRY_SP, 8, cpu.RETURN_MARK)
    m.store(TRACKER + 0x80, 8, case["prev"])
    m.store(TRACKER + 0x90, 2, case["mark"])
    m.store(OBJ + 0x10, 8, case["h"] if case["equal"] else (case["h"] ^ 0x40) & U64)
    m.store(flag_address, 4, case["trace"])


def run_body(image, start, case, seen=None):
    roles = dict(BODIES[start])
    flag = None
    if start in LOOKUPS:
        pass
    else:
        roles["dealloc"], roles["trace"] = watermark_slots(image, start)
        flag = trace_flag_address(image, start)
    m = Machine(image, case, roles)
    if start in LOOKUPS:
        lookup_setup(m, case)
    else:
        watermark_setup(m, case, flag)
    try:
        m.pc = start
        while True:
            m.steps += 1
            if m.steps > STEP_LIMIT:
                return ("limit",)
            m.step()
    except cpu.Done as done:
        if done.how != "ret":
            return ("stop", done.how)
    except cpu.ToolError as err:
        return ("error", str(err))
    finally:
        if seen is not None:
            seen |= m.seen
    if start in LOOKUPS:
        return ("ret", m.load(OUT, 8), m.get(cpu.RAX, 64) == OUT, tuple(m.log))
    return ("ret", m.load(TRACKER + 0x80, 8), m.load(TRACKER + 0x90, 2), tuple(m.log))


# ---------------------------------------------------------------- the reconstructions

def search_set(nodes, root, depth, variant=None):
    """Hash-set descent: linear scan of each node's keys; equal hash ends the lookup.
    Returns (found, memcmp log rows)."""
    log, node = [], root
    while True:
        keys = nodes[node]["keys"]
        pos = len(keys)
        for i, key in enumerate(keys):
            log.append(("cmp", TREE + node * 0x500 + 0x2C0 + 32 * i))
            c = cmp_sign(HASH, key)
            if c == 0 and variant != "equal_continues":
                return True, log
            if c == 0 and variant == "equal_continues":
                pos = i
                break
            if c < 0:
                pos = i
                break
        if depth == 0:
            return False, log
        depth -= 1
        node = nodes[node]["kids"][pos]


def iterator_words(entry, variant=None):
    w0, w8, w10, w18 = entry["w0"], entry["w8"], entry["w10"], entry["w18"]
    if w0 == NONE_VEC:
        flag = 1 if w8 else 0
        count = w18 if w8 else 0
        return (flag, 0, w8, w10, flag, 0, w8, w10, count)
    cap, buf, head, length = w0, w8, w10, w18
    if length == 0:
        first = second = 0
        count = 0
        end = 0
    else:
        head -= cap if head >= cap else 0
        room = (cap - head) & U64
        if length > room:
            count, end = length - room, cap
        else:
            count, end = 0, head + length
        first = head
        second = count
    stride = 96
    return (2, buf + first * stride, buf + end * stride, buf, buf + second * stride, 0,
            buf + end * stride, buf, count)


def lookup(case, variant=None):
    """Independent reconstruction of the prior lookup. Returns what run_body returns."""
    log = []
    none = ("ret", NONE_VEC, True, ())

    def done(tag):
        return ("ret", NONE_VEC, True, tuple(log))

    if case["form"] == "map":
        if not case["root"] and variant != "map_skips_null_root":
            return done(None)
        log.append(("search", MAPNODE, case["trh"], HEIGHT))
        if not case["found"]:
            return done(None)
    else:
        log.append(("ring", TRACKER + 0x18, HEIGHT))
        if case["rerr"]:
            return done(None)
        if case["ridx"] >= case["len"] and variant != "ring_skips_bound":
            return done(None)
    entry = case["entry"]
    n = entry["w18"]
    if n == 0:
        return done(None)
    if n == 1 and variant != "single_skips_filter":
        if entry["w0"] == NONE_VEC:
            if entry["w8"]:
                found, rows = search_set(entry["nodes"], 0, entry["w10"], variant)
                log.extend(rows)
                if found:
                    return done(None)
        else:
            log.append(("probe", entry_address(case), HASH))
            if not case["probe"]:
                return done(None)
    words = iterator_words(entry, variant)
    log.append(("collect", OUT, words))
    return ("ret", COLLECTED, True, tuple(log))


def watermark(case, locate, trace_row, loc_helper, variant=None):
    """Independent reconstruction of the watermark / cutoff body."""
    h, prev = case["h"], case["prev"]
    log = []
    top = max(prev, h)
    if variant == "signed_max":
        s = lambda v: v - (1 << 64) if v >> 63 else v
        top = prev if s(prev) > s(h) else h
    if case["trace"]:
        log.append(trace_row)
    log.append(("locate", -0x40, TRACKER + 0x60, h, OBJ + 0x60, locate))
    mark = case["mark"]
    if case["equal"] if variant != "mark_always" else True:
        mark = 1
    cut = h - CUTOFF if h >= CUTOFF else 0
    if variant == "wrap_cutoff":
        cut = (h - CUTOFF) & U64
    if variant == "cutoff_off_by_one":
        cut = h - CUTOFF + 1 if h >= CUTOFF - 1 else 0
    if variant == "cutoff_from_max":
        cut = top - CUTOFF if top >= CUTOFF else 0
    helper, loc2 = loc_helper
    log.append(("helper", -0x40, TRACKER, cut, 0x5151_0000, 0, loc2))
    if case["count"] and variant != "no_release":
        log.append(("dealloc", DESC_PTR, case["count"] * 8 if variant != "bytes_not_words" else case["count"], 0))
    return ("ret", top, mark, tuple(log))


# ---------------------------------------------------------------- cases

def patterns():
    return {0: [()], 1: [("<",), ("=",), (">",)],
            2: [("<", "<"), ("<", ">"), ("<", "="), ("=", ">"), (">", ">")],
            3: [("<", "<", "<"), ("<", "<", ">"), ("<", "=", ">"), (">", ">", ">")]}


def set_entries():
    out = []
    pats = patterns()
    for n in (1, 2):
        out.append({"name": f"set/null/n{n}", "w0": NONE_VEC, "w8": 0, "w10": 0, "w18": n, "nodes": []})
    for nk, group in pats.items():
        for pat in group:
            for j in (0, 31):
                nodes = [{"keys": [key_for(r, j) for r in pat], "kids": []}]
                out.append({"name": f"set/leaf/{''.join(pat) or 'empty'}/{j}", "w0": NONE_VEC,
                            "w8": TREE, "w10": 0, "w18": 1, "nodes": nodes})
    leaf_pats = [(), ("<",), ("=",), (">",), ("<", ">")]
    for pat in ((), ("<",), ("=",), (">",), ("<", ">"), ("<", "=", ">"), (">", ">")):
        for lp in leaf_pats:
            kids = list(range(1, len(pat) + 2))
            nodes = [{"keys": [key_for(r, 5) for r in pat], "kids": kids}]
            for _ in kids:
                nodes.append({"keys": [key_for(r, 31) for r in lp], "kids": []})
            out.append({"name": f"set/inner/{''.join(pat) or 'empty'}/{''.join(lp) or 'empty'}",
                        "w0": NONE_VEC, "w8": TREE, "w10": 1, "w18": 1, "nodes": nodes})
    nodes = [{"keys": [key_for(">", 0)], "kids": [1, 2]}, {"keys": [key_for(">", 3)], "kids": [3, 4]},
             {"keys": [], "kids": []}, {"keys": [key_for("<", 9)], "kids": []}, {"keys": [], "kids": []}]
    out.append({"name": "set/depth2/walk", "w0": NONE_VEC, "w8": TREE, "w10": 2, "w18": 1, "nodes": nodes})
    for n in (2, 5):
        out.append({"name": f"set/leaf/n{n}", "w0": NONE_VEC, "w8": TREE, "w10": 0, "w18": n,
                    "nodes": [{"keys": [key_for("=", 0)], "kids": []}]})
    return out


def deque_entries():
    out = [{"name": "deque/empty", "w0": 4, "w8": DEQUE, "w10": 1, "w18": 0}]
    for cap in (4, 8):
        for head in (0, 1, 3, 4, 7, 9):
            for n in (1, 2, 3, 4, 8, 9):
                out.append({"name": f"deque/c{cap}h{head}n{n}", "w0": cap, "w8": DEQUE, "w10": head, "w18": n})
    return out


def entry_shapes():
    return [{"name": "zero/none", "w0": NONE_VEC, "w8": 0, "w10": 0, "w18": 0},
            {"name": "zero/deque", "w0": 4, "w8": DEQUE, "w10": 0, "w18": 0}] + set_entries() + deque_entries()


def tracker_shapes():
    out = []
    for cap in (3, 4):
        for head in (0, 2, 3):
            for length in (0, 1, 3):
                for ridx in (0, 1, 2, 3):
                    if length == 3 and ridx not in (0, 2):
                        continue
                    if length == 1 and ridx not in (0, 1):
                        continue
                    out.append({"form": "ring", "cap": cap, "head": head, "len": length, "ridx": ridx,
                                "rerr": 0, "root": 0, "found": 0, "sidx": 0, "trh": 0})
    out.append({"form": "ring", "cap": 4, "head": 1, "len": 3, "ridx": 1, "rerr": 1,
                "root": 0, "found": 0, "sidx": 0, "trh": 0})
    for root in (0, 1):
        for found in (0, 1):
            for sidx in (0, 2):
                out.append({"form": "map", "cap": 0, "head": 0, "len": 0, "ridx": 0, "rerr": 0,
                            "root": root, "found": found, "sidx": sidx, "trh": 3})
    return out


def lookup_cases():
    entries = entry_shapes()
    out = []
    for t in tracker_shapes():
        for e in entries:
            for probe in ((0, 1) if e["w18"] == 1 and e["w0"] != NONE_VEC else (1,)):
                c = dict(t)
                tsig = (t["form"], t["rerr"], t["ridx"] >= t["len"], t["root"], t["found"])
                c.update({"entry": e, "probe": probe, "kind": "lookup", "tsig": tsig,
                          "name": f"{t['form']}/{e['name']}"})
                out.append(c)
    return out


def watermark_cases():
    out = []
    values = (0, 1, 49_999, 50_000, 50_001, 1 << 40, 1 << 63, U64)
    prevs = (0, 5, 50_000, 1 << 63, U64)
    for h in values:
        for prev in prevs:
            for equal in (0, 1):
                for trace in (0, 1):
                    for count in (0, 3):
                        for mark in (0, 0x0201):
                            out.append({"kind": "watermark", "h": h, "prev": prev, "equal": equal,
                                        "trace": trace, "count": count, "mark": mark,
                                        "name": f"h{h:x}/p{prev:x}"})
    return out


def describe(case):
    if case["kind"] == "watermark":
        return "\t".join(["watermark", f"{case['h']:#x}", f"{case['prev']:#x}", str(case["equal"]),
                          str(case["trace"]), str(case["count"]), f"{case['mark']:#x}"])
    return "\t".join(["lookup", case["name"], str(case["probe"])])


def outcome(result):
    if result[0] != "ret":
        return result[0]
    roles = ",".join(row[0] for row in result[3])
    if isinstance(result[2], bool):
        return f"{'collected' if result[1] == COLLECTED else 'none'}/{roles}"
    return f"{result[1]:#x}/{result[2]:#x}/{roles}"


def reconstruct(image, start, case, variant=None):
    if start in LOOKUPS:
        return lookup(case, variant)
    leas = rip_leas(image, start)
    trace_row = ("trace", leas[3], 1, leas[4], leas[5])
    return watermark(case, leas[0], trace_row, (None, leas[1]), variant)


LOOKUP_VARIANTS = ("map_skips_null_root", "ring_skips_bound", "single_skips_filter", "equal_continues")
WATERMARK_VARIANTS = ("signed_max", "mark_always", "wrap_cutoff", "cutoff_off_by_one", "cutoff_from_max",
                      "no_release", "bytes_not_words")


def select_cases(all_cases, real):
    seen, picked = set(), []
    for i, c in enumerate(all_cases):
        k = (outcome(real[i]), c["tsig"] if c["kind"] == "lookup" else (c["h"] in (0, 1, 49_999, 50_000)), c["entry"]["name"] if c["kind"] == "lookup" else c["equal"])
        if k not in seen:
            seen.add(k)
            picked.append(i)
    return picked


def generate(out_dir):
    image = load_image()
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    groups = {"lookup": lookup_cases(), "watermark": watermark_cases()}
    summary = {"target_sha256": SHA256, "bodies": {}}
    total_cases = mismatches = 0
    reached, real_by_body, sample_lines = {}, {}, ["#\tbody\tkind\tcase\toutcome\tverdict"]
    for start in BODIES:
        kind = "lookup" if start in LOOKUPS else "watermark"
        all_cases = groups[kind]
        lo, hi, insns = body_insns(image, start)
        counts, digest, real, seen = {}, hashlib.sha256(), [], set()
        for i, case in enumerate(all_cases):
            got = run_body(image, start, case, seen)
            ok = got == reconstruct(image, start, case)
            mismatches += not ok
            total_cases += 1
            real.append(got)
            key = outcome(got)
            counts[key] = counts.get(key, 0) + 1
            digest.update(key.encode() + b"\n")
        picked = select_cases(all_cases, real)
        for i in picked[:150]:
            sample_lines.append(f"{i}\t{start:#x}\t" + describe(all_cases[i]) + "\t" + outcome(real[i]) + "\tmatch")
        real_by_body[start] = real
        reached[start] = seen
        summary["bodies"][f"{start:#x}"] = {
            "fde": [f"{lo:#x}", f"{hi:#x}"], "instructions": len(insns), "cases": len(all_cases),
            "direct_callees": {k: f"{v:#x}" for k, v in sorted(BODIES[start].items())},
            "outcomes": len(counts), "outcome_counts": dict(sorted(counts.items())),
            "result_digest": digest.hexdigest(),
            "instructions_reached": sum(1 for insn in insns if insn.va in seen)}
    summary["cases"] = total_cases
    summary["mismatches"] = mismatches
    summary["lookup_twins_agree"] = (summary["bodies"]["0x2bafce0"]["result_digest"]
                                     == summary["bodies"]["0x2baff80"]["result_digest"])
    summary["watermark_twins_agree"] = (summary["bodies"]["0x27605d0"]["result_digest"]
                                        == summary["bodies"]["0x27604d0"]["result_digest"])
    controls = detected = 0
    variant_rows = {}
    for start, names in ((0x2BAFCE0, LOOKUP_VARIANTS), (0x27605D0, WATERMARK_VARIANTS)):
        kind = "lookup" if start in LOOKUPS else "watermark"
        for name in names:
            total, first = 0, None
            for i, case in enumerate(groups[kind]):
                if reconstruct(image, start, case, name) != real_by_body[start][i]:
                    total += 1
                    first = i if first is None else first
            variant_rows[name] = {"caught_cases": total, "first_case": first}
            controls += 1
            detected += total > 0
    summary["negative_controls"] = variant_rows
    mut_lines = ["body\tjcc_va\tfile_offset_flipped\tverdict\tfirst_killing_case"]
    killed = survived = unreached = 0
    for start in BODIES:
        kind = "lookup" if start in LOOKUPS else "watermark"
        all_cases, real = groups[kind], real_by_body[start]
        sample = select_cases(all_cases, real)
        for va, op_off in jcc_sites(image, start):
            data = bytearray(image.data)
            data[op_off] ^= 1
            mutant = copy.copy(image)
            mutant.data = bytes(data)
            mutant.cache = {}
            killer = None
            for i in sample:
                if run_body(mutant, start, all_cases[i]) != real[i]:
                    killer = i
                    break
            verdict = "killed" if killer is not None else "unreached" if va not in reached[start] else "survived"
            mut_lines.append(f"{start:#x}\t{va:#x}\t{op_off:#x}\t{verdict}\t{'-' if killer is None else killer}")
            killed += verdict == "killed"
            survived += verdict == "survived"
            unreached += verdict == "unreached"
    summary["mutants"] = {"killed": killed, "survived": survived, "unreached": unreached}
    controls += killed + survived
    detected += killed
    call_lines = ["body\tsite\tkind\ttarget\tnote"]
    for start in BODIES:
        for va, kind, target, note in call_rows(image, start):
            call_lines.append(f"{start:#x}\t{va:#x}\t{kind}\t{target:#x}\t{note}")
    measure = {"cases": total_cases, "negative_controls": controls, "negative_detected": detected}
    files = {"cases.tsv": "\n".join(sample_lines) + "\n", "mutants.tsv": "\n".join(mut_lines) + "\n",
             "calls.tsv": "\n".join(call_lines) + "\n",
             "summary.json": json.dumps(summary, indent=1, sort_keys=True) + "\n",
             "measure.json": json.dumps(measure, indent=1, sort_keys=True) + "\n"}
    for name, text in files.items():
        (out_dir / name).write_text(text)
    summary["measure"] = measure
    return summary


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        s = generate(args.out)
    except Fail as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    print(json.dumps({"mismatches": s["mismatches"], "mutants": s["mutants"], "measure": s["measure"]}))
    good = (s["mismatches"] == 0 and s["mutants"]["survived"] == 0
            and s["measure"]["negative_controls"] == s["measure"]["negative_detected"])
    return 0 if good else 2


if __name__ == "__main__":
    sys.exit(main())
