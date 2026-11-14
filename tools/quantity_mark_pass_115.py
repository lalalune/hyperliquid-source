#!/usr/bin/env python3
"""Node #115 per-asset mark-quantity pass 0x2c4fe30: model, machine harness, controls and evidence.

The pass takes one perp dex entry (stride 0x510 in the exchange vector), walks its asset slots, resolves each slot's oracle index through
either an ordered map or a ring of 16-byte pairs, reads the index's mark integer from a hashed table, multiplies by the book scale, rounds
half away from zero, saturates to u64 (never below 1), divides by 10**(6 - size decimals), converts the f64 to a 96-bit decimal and
inserts it at the slot key in a local ordered map. The map goes to the sink 0x2c509b0.

`model` is an independent Python statement of that behaviour. `Harness` runs the original bytes in the shared x86-64 interpreter with
hooks for every callee outside the pass and compares event logs and results on every case. Byte patches of the pass and variants of the
model are the negative controls.

    python3 tools/quantity_mark_pass_115.py --out <dir>
"""

import argparse
import hashlib
import json
import math
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import quantity_pass_x86_115 as cpu  # noqa: E402
from decimal_from_f64_115 import spec_kernel  # noqa: E402

SHA256 = cpu.SHA256
ENTRY = 0x2C4FE30
SINK = 0x2C509B0
INSERT = 0x2DC25D0
GUARD = 0x44E0810
BTREE = 0x35BD660
RINGS = 0x45547E0
KERNEL = 0x5C43C60
DROP_TMP = 0x42320D0
DROP_ERR = 0x2C94F00
DRAIN = 0x2447830
SLOT_DEALLOC, SLOT_FIND, SLOT_ROUND = 0x64DF4A0, 0x64E78B0, 0x64E1890
SLOT_UNWRAP, SLOT_ASSERT, SLOT_ADD, SLOT_MUL, SLOT_INDEX = 0x64DF6A0, 0x64DF830, 0x64DF520, 0x64DF870, 0x64DF848
SLOTS = (SLOT_DEALLOC, SLOT_FIND, SLOT_ROUND, SLOT_UNWRAP, SLOT_ASSERT, SLOT_ADD, SLOT_MUL, SLOT_INDEX)
PANIC_NAMES = {SLOT_UNWRAP: "dex-index", SLOT_ASSERT: "oracle-id", SLOT_ADD: "key-add", SLOT_MUL: "key-mul", SLOT_INDEX: "decimals"}

MIN = 1 << 63
M64 = (1 << 64) - 1
STRIDE = 0x510
SELF = cpu.HEAP_BASE + 0x1000
DEXES = cpu.HEAP_BASE + 0x3000
ARG2 = cpu.HEAP_BASE + 0x6000
ELEMS = cpu.HEAP_BASE + 0x20000
RB = cpu.HEAP_BASE + 0x9000
NAMES = cpu.HEAP_BASE + 0xA000
RINGBUF = cpu.HEAP_BASE + 0xC000
NODE = cpu.HEAP_BASE + 0xE000
OUT = cpu.HEAP_BASE + 0xF000
USED = 0x10000
BIG_USED = 0x70000
OUT_UNTOUCHED = 0xA5A5
HYPE, PURR = b"HYPE", b"PURR"
TABLE = [10.0 ** n for n in range(7)]
SATURATE = float.fromhex("0x1.fffffffffffffp+63")  # 1.844674407370955e19, compared with strictly greater
LIMIT = 2.0 ** 64
BIAS = 2.0 ** 63


class Case:
    def __init__(self):
        self.seed = 0
        self.keys = (0, 0)
        self.scale = 1.0
        self.dexes = []
        self.index = 0
        self.arg2_id = 0
        self.elems = []
        self.marks = {}
        self.rb = (MIN, 0, 0)
        self.tail = bytes(21)
        self.real_kernel = False


def u64_cast(x):
    """The saturating f64 -> u64 sequence of the pass for x >= 0 or NaN-free input (see model)."""
    return M64 if x > SATURATE else int(x)


def round_away(x):
    if x != x or x in (math.inf, -math.inf):
        return x
    a = abs(x)
    f = math.floor(a)
    r = f + 1.0 if a - f >= 0.5 else float(f)
    return math.copysign(r, x)


def mark_count(mark, scale, mut):
    prod = float(mark) * scale
    r = round_away(prod)
    if "round_half_even" in mut:
        r = float(round(prod)) if prod == prod and abs(prod) != math.inf else prod
    if "round_floor" in mut and r == r and abs(r) != math.inf:
        r = float(math.floor(prod))
    x = r if r > 0.0 else 0.0
    if x == math.inf:
        x = 0.0
    elif x > LIMIT:
        x = LIMIT
    cast = u64_cast(x) if "no_saturate" not in mut else int(x) & M64
    floor_one = 2 if "floor_two" in mut else 1
    return prod, (cast if cast >= floor_one else floor_one) if "no_floor" not in mut else cast


def model(c, mut=()):
    """Return (events, outcome) the pass must produce for case c."""
    ev = []
    n = len(c.dexes)
    if c.index >= n:
        return ev, ("panic", "dex-index")
    d = c.dexes[c.index]
    ev.append(("guard",))
    ev.append(("guard",))
    code = None
    if d["f378"] == MIN or d["f408"] == MIN + 1:
        code = 0x19E
    elif d["flag58"] != 0 and "ignore_flag58" not in mut:
        code = 0x101
    if code is not None:
        if "swap_codes" in mut:
            code = 0x101 if code == 0x19E else 0x19E
        if c.rb[0] == MIN:
            ev.append(("drain",))
        elif c.rb[0] != 0 or "dealloc_always" in mut:
            ev.append(("dealloc", c.rb[1], c.rb[0] * 24))
        return ev, ("early", code)
    first = c.dexes[0]
    scale0 = (c.scale + -1.0) + 1.0 if "scale_plain" not in mut else c.scale
    inserted = 0
    for i in range(d["count"]):
        if d["id"] * 10000 > M64:
            return ev, ("panic", "key-mul")
        key = d["id"] * 10000 + i
        if key > M64:
            return ev, ("panic", "key-add")
        if d["src"][0] == "btree":
            ev.append(("btree", key))
            v = d["src"][1].get(key)
        else:
            ev.append(("ring", key))
            v = dict((k, val) for k, val in d["src"][3]).get(key)
        if v is None:
            continue
        ev.append(("find", v, c.keys))
        mark = c.marks.get(v, 0)
        if mark == 0:
            continue
        scale = scale0
        if first["id"] == 0 and v <= 0x270F and v < len(c.elems):
            nm, ln = c.elems[v][1], c.elems[v][2]
            if ln == 4 and (nm == HYPE or (nm == PURR and "purr_off" not in mut)):
                scale = 1.0
        prod, count = mark_count(mark, scale, mut)
        ev.append(("round", struct.unpack("<Q", struct.pack("<d", prod))[0]))
        if v // 10000 != first["id"] and "no_id_check" not in mut:
            return ev, ("panic", "oracle-id")
        local = v - (v // 10000) * 10000
        if local >= len(c.elems):
            return ev, ("panic", "oracle-id")
        dec = c.elems[local][0]
        if dec >= 7:
            return ev, ("panic", "decimals")
        div = TABLE[6 - dec] if "dec_off_by_one" not in mut else TABLE[min(6, 7 - dec)]
        q = float(count) / div
        bits = struct.unpack("<Q", struct.pack("<d", q))[0]
        if bits & ((1 << 63) - 1) >= 0x7FF0000000000000:
            ev.append(("drop_err",))
            continue
        expo, frac = (bits >> 52) & 0x7FF, bits & ((1 << 52) - 1)
        positive = 1 if bits >> 63 == 0 else 0
        if "sign_flip" in mut:
            positive ^= 1
        if expo:
            lo, mid, e2 = frac & 0xFFFFFFFF, (frac >> 32) | 0x100000, expo - 1075
        elif frac:
            lo, mid, e2 = frac & 0xFFFFFFFF, frac >> 32, -1074
        else:
            lo = None
        if not mut and not REACH.get("frozen"):
            REACH["zero" if lo is None else "denormal"] += 0 if expo else 1
        if lo is None:
            dec16 = struct.pack("<IIQ", (bits >> 63) << 31, 0, 0)
        else:
            ev.append(("kernel", lo, mid, e2 & 0xFFFFFFFF, positive, 1, 1))
            res = spec_kernel(lo, mid, 0, e2, positive, 1, 0 if "kernel_round_off" in mut else 1)
            if res is None:
                ev.append(("drop_err",))
                continue
            dec16 = struct.pack("<IIQ", *res)
        ev.append(("drop_tmp",))
        ev.append(("insert", key, dec16.hex()))
        inserted += 1
    head = c.tail
    ev.append(("sink", inserted, struct.pack("<QQQQ", *(list(c.rb) + [0])).hex(), (b"\x01" + head).hex(), c.index))
    return ev, ("sink",)


REACH = {"zero": 0, "denormal": 0}

FIELD_ROWS = ["\t".join(r) for r in (
    ("struct", "offset", "width", "use", "first instruction"),
    ("book (rsi)", "0x60", "8+4", "hasher key words passed to the mark table lookup", "0x2c4fece"),
    ("book (rsi)", "0x7a0", "f64", "book scale, formed as (s + -1.0) + 1.0", "0x2c4ffbf"),
    ("book (rsi)", "0x7c8", "8", "pointer to the dex entry vector", "0x2c4fe61"),
    ("book (rsi)", "0x7d0", "8", "dex entry count, bound for the index argument", "0x2c4fe44"),
    ("dex entry", "0x8", "8", "pointer to 32-byte asset metadata rows (first entry only)", "0x2c503b6"),
    ("dex entry", "0x10", "8", "asset slot count; for the first entry also the metadata row count", "0x2c4ffaa"),
    ("dex entry", "0x50", "8", "dex id; slot key is 10000 * id + slot", "0x2c500b6"),
    ("dex entry", "0x58", "8", "nonzero makes the pass return 0x101", "0x2c4ff0c"),
    ("dex entry", "0x148", "table", "oracle index to mark integer table (first entry only)", "0x2c4ffcd"),
    ("dex entry", "0x378", "8", "0x8000000000000000 makes the pass return 0x19e", "0x2c4fee7"),
    ("dex entry", "0x408", "8", "0x8000000000000001 makes the pass return 0x19e", "0x2c4feff"),
    ("dex entry", "0x428", "8", "ring capacity, or 0x8000000000000000 for the ordered-map form", "0x2c500f8"),
    ("dex entry", "0x430", "8", "ring buffer pointer, or ordered-map root", "0x2c50107"),
    ("dex entry", "0x438", "8", "ring head, or ordered-map height", "0x2c50113"),
    ("dex entry", "0x440", "8", "ring length", "0x2c50165"),
    ("metadata row", "0x8", "8", "name pointer (u32 compared with HYPE and PURR)", "0x2c503cd"),
    ("metadata row", "0x10", "8", "name length, must be 4", "0x2c503c1"),
    ("metadata row", "0x1d", "1", "size decimals, below 7", "0x2c502de"),
    ("sink call", "rcx", "32", "moved 32-byte argument r8 (drained or freed on the early exits)", "0x2c50507"),
    ("sink call", "r8", "22", "byte 1 then the first 21 bytes of the third argument", "0x2c50537"),
    ("sink call", "r9", "32", "local map {0, 8, 0, 0} grown by the insert callee; length at +0x18", "0x2c50566"),
    ("sink call", "stack", "8", "the dex entry pointer", "0x2c50566"),
)]


def callee_rows(image):
    rows = ["member\tsite\tkind\ttarget\tcount"]
    for name, va in (("root", ENTRY), ("sink", SINK), ("insert", INSERT)):
        start, end = image.exact_fde(va)
        seen = {}
        for row in cpu.decode_range(image, start, end):
            if row.op == "call":
                key = ("direct", row.target)
            elif row.op == "calli":
                key = ("slot", row.a[4])
            else:
                continue
            first, count = seen.get(key, (row.va, 0))
            seen[key] = (first, count + 1)
        for (kind, target), (first, count) in sorted(seen.items(), key=lambda kv: kv[1][0]):
            rows.append("%s\t%#x\t%s\t%#x\t%d" % (name, first, kind, target, count))
        rows.append("%s\tsize\tfde\t%#x\t%d" % (name, start, end - start))
    return rows


def pack_double(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


class Harness:
    def __init__(self, image, patches=None, real_kernel=False):
        self.image = image
        self.real_kernel = real_kernel
        machine = cpu.Machine(image, patches)
        self.machine = machine
        machine.step_limit = 3_000_000
        for target, hook in ((GUARD, self.on_guard), (BTREE, self.on_btree), (RINGS, self.on_ring), (DROP_TMP, self.on_drop_tmp),
                             (INSERT, self.on_insert), (DROP_ERR, self.on_drop_err), (DRAIN, self.on_drain), (SINK, self.on_sink)):
            machine.calls[target] = hook
        if real_kernel:
            machine.real = frozenset((KERNEL,))
        else:
            machine.calls[KERNEL] = self.on_kernel
        hooks = {SLOT_DEALLOC: self.on_dealloc, SLOT_FIND: self.on_find, SLOT_ROUND: self.on_round}
        for slot in (SLOT_UNWRAP, SLOT_ASSERT, SLOT_ADD, SLOT_MUL, SLOT_INDEX):
            hooks[slot] = self.panic_hook(PANIC_NAMES[slot])
        for slot, hook in hooks.items():
            machine.memory.statics[slot] = cpu.MARK_BASE + slot
            machine.slots[cpu.MARK_BASE + slot] = hook
        self.case, self.log = None, []
        self.inserted = 0
        self.node_index = 0

    def expect(self, ok, text):
        if not ok:
            raise cpu.Halt("stub check failed: " + text)

    def panic_hook(self, name):
        def hook(machine):
            raise cpu.Panicked(name)
        return hook

    def on_guard(self, machine):
        self.log.append(("guard",))

    def on_drop_tmp(self, machine):
        self.expect(machine.memory.read(machine.regs[cpu.RDI], 2) == 0xB0, "temporary tag")
        self.log.append(("drop_tmp",))

    def on_drop_err(self, machine):
        self.expect(machine.memory.read(machine.regs[cpu.RDI], 2) == 0xB0, "error tag")
        self.log.append(("drop_err",))

    def on_drain(self, machine):
        machine.memory.write(machine.regs[cpu.RDI], 8, 0)
        self.log.append(("drain",))

    def on_dealloc(self, machine):
        regs = machine.regs
        self.expect(regs[cpu.RDX] & cpu.MASK[4] == 0, "dealloc alignment word")
        self.log.append(("dealloc", regs[cpu.RDI], regs[cpu.RSI]))

    def dex_of(self, address):
        return self.case.dexes[(address - 0x428 - DEXES) // STRIDE]

    def on_btree(self, machine):
        regs, mem = machine.regs, machine.memory
        key = mem.read(regs[cpu.RCX], 8)
        self.log.append(("btree", key))
        found = None
        for d in self.case.dexes:
            if d["src"][0] == "btree" and d["src"][2] == regs[cpu.RSI] and regs[cpu.RDX] == d["src"][3]:
                found = d["src"][1].get(key)
        out = regs[cpu.RDI]
        if found is None:
            mem.write(out, 4, 1)
            return
        slot = self.node_index
        self.node_index += 1
        mem.write(out, 4, 0)
        mem.write(out + 8, 8, NODE)
        mem.write(out + 0x18, 8, slot)
        mem.write(NODE + 0x60 + slot * 8, 8, found)

    def on_ring(self, machine):
        regs, mem = machine.regs, machine.memory
        key = mem.read(regs[cpu.RSI], 8)
        self.log.append(("ring", key))
        d = self.dex_of(regs[cpu.RDI])
        self.expect(d["src"][0] == "ring", "ring owner")
        pairs = d["src"][3]
        hit = [n for n, (k, _) in enumerate(pairs) if k == key]
        if hit:
            regs[cpu.RAX], regs[cpu.RDX] = 0, hit[0]
        else:
            regs[cpu.RAX], regs[cpu.RDX] = 1, 0
        machine.keep_rdx = True

    def on_find(self, machine):
        regs, mem = machine.regs, machine.memory
        self.expect(regs[cpu.RDI] == DEXES + 0x148 and regs[cpu.RCX] == 0, "find table")
        got = (mem.read(regs[cpu.RDX], 8), mem.read(regs[cpu.RDX] + 8, 4))
        self.expect(got == (self.case.keys[0], self.case.keys[1]), "hasher keys")
        v = regs[cpu.RSI]
        self.log.append(("find", v, self.case.keys))
        regs[cpu.RAX] = self.case.marks.get(v, 0)

    def on_round(self, machine):
        bits = machine.xmm[0] & cpu.MASK[8]
        self.log.append(("round", bits))
        x = struct.unpack("<d", struct.pack("<Q", bits))[0]
        machine.xmm_result = pack_double(round_away(x))

    def on_kernel(self, machine):
        regs, mem = machine.regs, machine.memory
        lo, mid, hi = (mem.read(regs[cpu.RSI] + 4 * n, 4) for n in range(3))
        self.expect(hi == 0 and regs[cpu.R8] & 0xFF == 1 and regs[cpu.R9] & 0xFF == 1, "kernel flags")
        e2 = regs[cpu.RDX] & cpu.MASK[4]
        positive = regs[cpu.RCX] & 0xFF
        self.log.append(("kernel", lo, mid, e2, positive, 1, 1))
        signed = e2 - (1 << 32) if e2 >> 31 else e2
        res = spec_kernel(lo, mid, 0, signed, positive, 1, 1)
        out = regs[cpu.RDI]
        if res is None:
            mem.write(out, 4, 0)
        else:
            mem.write(out, 4, 1)
            mem.put_bytes(out + 4, struct.pack("<IIQ", *res))

    def on_insert(self, machine):
        regs, mem = machine.regs, machine.memory
        key = regs[cpu.RDX]
        value = mem.bytes_at(regs[cpu.RCX], 16)
        self.log.append(("insert", key, value.hex()))
        self.inserted += 1
        mem.write(regs[cpu.RSI] + 0x18, 8, self.inserted)

    def on_sink(self, machine):
        regs, mem = machine.regs, machine.memory
        self.expect(regs[cpu.RDX] == 0, "sink third argument")
        rb = mem.bytes_at(regs[cpu.RCX], 32)
        flagged = mem.bytes_at(regs[cpu.R8], 22)
        owner = mem.read(regs[cpu.RSP] + 8, 8)
        mapped = mem.bytes_at(regs[cpu.R9], 32)
        self.expect(struct.unpack("<QQQQ", mapped)[3] == self.inserted, "map length")
        self.log.append(("sink", self.inserted, rb.hex(), flagged.hex(), (owner - DEXES) // STRIDE))
        mem.write(OUT, 2, 0x5151)

    def load(self, c):
        m = self.machine.memory
        m.reset(BIG_USED if len(c.elems) > 64 else USED)
        self.case, self.log, self.inserted, self.node_index = c, [], 0, 0
        w = m.write
        w(SELF + 0x60, 8, c.keys[0])
        w(SELF + 0x68, 4, c.keys[1])
        w(SELF + 0x7A0, 8, pack_double(c.scale))
        w(SELF + 0x7C8, 8, DEXES)
        w(SELF + 0x7D0, 8, len(c.dexes))
        for n, d in enumerate(c.dexes):
            at = DEXES + n * STRIDE
            w(at + 0x10, 8, d["count"])
            w(at + 0x50, 8, d["id"])
            w(at + 0x58, 8, d["flag58"])
            w(at + 0x378, 8, d["f378"])
            w(at + 0x408, 8, d["f408"])
            src = d["src"]
            if src[0] == "btree":
                w(at + 0x428, 8, MIN)
                w(at + 0x430, 8, src[2])
                w(at + 0x438, 8, src[3])
            else:
                cap, head, pairs = src[1], src[2], src[3]
                buf = RINGBUF + n * 0x400
                w(at + 0x428, 8, cap)
                w(at + 0x430, 8, buf)
                w(at + 0x438, 8, head)
                w(at + 0x440, 8, len(pairs))
                for k, (key, val) in enumerate(pairs):
                    pos = (head + k) % cap
                    w(buf + pos * 16, 8, key)
                    w(buf + pos * 16 + 8, 8, val)
        m.put_bytes(ARG2, c.tail)
        w(DEXES + 8, 8, ELEMS)
        for n, (dec, name, ln) in enumerate(c.elems):
            at = ELEMS + n * 32
            w(at + 0x1D, 1, dec)
            w(at + 8, 8, NAMES + n % 64 * 8)
            w(at + 0x10, 8, ln)
            m.put_bytes(NAMES + n % 64 * 8, name)
        m.put_bytes(RB, struct.pack("<QQQQ", *(list(c.rb) + [0])))
        w(OUT, 2, OUT_UNTOUCHED)

    def run(self, c):
        self.load(c)
        mach = self.machine
        try:
            mach.run(ENTRY, {cpu.RDI: OUT, cpu.RSI: SELF, cpu.RDX: ARG2, cpu.RCX: c.index, cpu.R8: RB})
        except cpu.Panicked as stop:
            return self.log, ("panic", str(stop))
        out = mach.memory.read(OUT, 2)
        if out == 0x5151:
            return self.log, ("sink",)
        return self.log, ("early", out)


def gen_case(seed):
    rng = random.Random(seed * 7919 + 13)
    c = Case()
    c.seed = seed
    c.keys = (rng.getrandbits(64), rng.getrandbits(32))
    c.scale = rng.choice([1.0, 0.5, 2.0, 1e6, 123456.789, 3.7e-5, 1e12, 1e19, 1e-12, 0.0, -2.0, 1e300, math.inf, math.nan,
                          rng.uniform(0.001, 5000.0), 10.0 ** rng.randint(-8, 20), rng.uniform(0.9, 1.1)])
    c.arg2_id = rng.choice([0, 0, 0, 1, 2, 7])
    nel = rng.randint(0, 5)
    names = [HYPE, PURR, b"ETHX", b"BT", b"PURR"]
    c.elems = []
    for _ in range(nel):
        dec = rng.choice([0, 1, 2, 3, 4, 5, 6, 6, 6, 3, 7, 9])
        nm = rng.choice(names)
        ln = 4 if len(nm) == 4 and rng.random() < 0.9 else rng.choice([3, 5, 4])
        c.elems.append((dec, nm.ljust(4, b"x")[:4], ln))
    c.tail = bytes(rng.getrandbits(8) for _ in range(21))
    special = seed % 211 == 3 or seed % 223 == 9
    ndex = 2 if special else rng.choice([1, 1, 2, 3])
    c.dexes = []
    for n in range(ndex):
        did = c.arg2_id if n == 0 else rng.choice([0, 1, 2, 3, 40, 77])
        count = nel if n == 0 else rng.choice([0, 1, 2, 3, 3, 4, 5])
        clean = special and n == 1
        if clean:
            did, count = (1844674407370955, 1700) if seed % 211 == 3 else (1844674407370956, 2)
        keys = [did * 10000 + i for i in range(count)] if did * 10000 < (1 << 64) and count <= 8 else []
        pairs = []
        for k in keys:
            if rng.random() < 0.85:
                local = rng.randrange(max(1, nel + (1 if rng.random() < 0.1 else 0)))
                owner = c.arg2_id if rng.random() < 0.92 else rng.choice([0, 1, 5])
                v = owner * 10000 + local
                if rng.random() < 0.04:
                    v = rng.getrandbits(40)
                pairs.append((k, v))
        for p in pairs:
            if rng.random() < 0.8:
                mag = rng.choice([1, 10, 10 ** 3, 10 ** 6, 10 ** 9, 10 ** 12, 10 ** 15, 10 ** 18, 1 << 63, M64])
                c.marks[p[1]] = rng.randint(1, mag)
        if rng.random() < 0.5:
            src = ("btree", dict(pairs), 0x5000 + 16 * n, rng.randint(0, 3))
        else:
            cap = max(1, len(pairs) + rng.randint(0, 3))
            src = ("ring", cap, rng.randrange(cap), sorted(pairs))
        quiet = clean or rng.random() < 0.8
        c.dexes.append(dict(
            count=count, id=did, flag58=0 if quiet else rng.choice([1, 2, 1 << 40]),
            f378=rng.randrange(1 << 20) if clean or rng.random() > 0.08 else MIN,
            f408=rng.choice([0, 5, MIN, MIN + 2]) if clean or rng.random() > 0.08 else MIN + 1, src=src))
    if special:
        c.index = 1
    else:
        c.index = rng.randrange(len(c.dexes)) if rng.random() < 0.97 else len(c.dexes) + rng.randint(0, 2)
    if rng.random() < 0.5:
        c.rb = (MIN, rng.getrandbits(40), rng.randint(0, 6))
    else:
        c.rb = (rng.choice([0, 0, 3, 8]), rng.getrandbits(40) & ~7, rng.randint(0, 8))
    c.real_kernel = seed % 25 == 0
    if seed % 300 == 7:
        wide(c, rng)
    return c


def wide(c, rng):
    """A first dex with 10000 asset metadata rows so the name probe limit 0x270f is reachable (oracle index 9999)."""
    c.arg2_id = 0
    c.elems = [(rng.choice([2, 3, 4]), b"ETHX", 4) for _ in range(10000)]
    c.elems[9999] = (rng.choice([0, 3, 6]), rng.choice([HYPE, PURR]), 4)
    c.marks = {9999: rng.randint(1, 10 ** 15)}
    c.scale = rng.choice([2.0, 123.5, 0.25, 1e6])
    first = dict(count=10000, id=0, flag58=0, f378=3, f408=0, src=("btree", {}, 0x5000, 0))
    second = dict(count=1, id=5, flag58=0, f378=7, f408=0, src=("btree", {50000: 9999}, 0x5010, 0))
    c.dexes = [first, second]
    c.index = 1


def sig(log, out, skip_kernel=False):
    rows = [r for r in log if not (skip_kernel and r[0] == "kernel")]
    return hashlib.sha256(repr((rows, out)).encode()).hexdigest()[:16]


def outcome_name(out):
    return out[0] + (":" + str(out[1]) if len(out) > 1 else "")


# (address, byte offset, original byte, replacement byte, meaning)
PATCHES = (
    (0x2C4FE4B, 1, 0x83, 0x82, "dex index bound jae -> jb"),
    (0x2C4FF06, 0, 0x74, 0x75, "sentinel test on +0x408 inverted"),
    (0x2C4FF11, 0, 0x74, 0x75, "busy flag +0x58 test inverted"),
    (0x2C4FEF2, 0, 0x70, 0x71, "None niche test on +0x378 jo -> jno"),
    (0x2C500B1, 1, 0x10, 0x11, "slot key stride 10000 -> 10001"),
    (0x2C500BA, 1, 0x80, 0x81, "key multiply overflow jo -> jno"),
    (0x2C500D0, 1, 0x82, 0x83, "key add carry jb -> jae"),
    (0x2C500E5, 0, 0x74, 0x75, "map-niche skip inside loop inverted"),
    (0x2C50131, 1, 0x84, 0x85, "ordered-map miss test inverted"),
    (0x2C5016C, 1, 0x83, 0x82, "ring length bound jae -> jb"),
    (0x2C5017C, 0, 0x73, 0x72, "ring wrap test inverted"),
    (0x2C501C9, 1, 0x84, 0x85, "dex id zero test inverted"),
    (0x2C50246, 2, 0x5C, 0x58, "u64 cast bias subsd -> addsd"),
    (0x2C50298, 3, 0x01, 0x02, "cast floor 1 -> 2"),
    (0x2C5029C, 3, 0x00, 0x01, "cast floor adc 0 -> 1"),
    (0x2C502B0, 3, 0x0B, 0x0C, "division by 10000 shift 11 -> 12"),
    (0x2C502BC, 1, 0x85, 0x84, "oracle id mismatch test inverted"),
    (0x2C502D0, 1, 0x83, 0x82, "local asset bound jae -> jb"),
    (0x2C502DE, 5, 0x1D, 0x1C, "size decimals byte offset 0x1d -> 0x1c"),
    (0x2C502E4, 3, 0x07, 0x08, "decimals bound 7 -> 8"),
    (0x2C502EE, 1, 0x06, 0x05, "decimals base 6 -> 5"),
    (0x2C50316, 2, 0x03, 0x02, "power table stride 8 -> 4"),
    (0x2C50347, 1, 0x8D, 0x8C, "non-finite test jge -> jl"),
    (0x2C50395, 3, 0x0F, 0x0E, "name probe limit 0x270f -> 0x270e"),
    (0x2C5039C, 1, 0x87, 0x86, "name probe limit branch ja -> jbe"),
    (0x2C503C1, 5, 0x04, 0x05, "name length 4 -> 5"),
    (0x2C503C7, 1, 0x85, 0x84, "name length test inverted"),
    (0x2C50406, 0, 0x74, 0x75, "zero mantissa test inverted"),
    (0x2C50426, 1, 0x99, 0x98, "positive flag setns -> sets"),
    (0x2C50436, 2, 0x01, 0x00, "kernel is64 argument 1 -> 0"),
    (0x2C5043C, 2, 0x01, 0x00, "kernel rounding argument 1 -> 0"),
    (0x2C50458, 1, 0x85, 0x84, "kernel success tag test inverted"),
)

MUTANTS = ("round_half_even", "round_floor", "no_saturate", "floor_two", "no_floor", "ignore_flag58", "swap_codes", "scale_plain",
           "purr_off", "dealloc_always", "no_id_check", "dec_off_by_one", "sign_flip", "kernel_round_off")
# model variants the cases cannot separate, with the reason (checked against the machine, not assumed)
EQUIVALENT_NOTES = {
    0x2C50406: "the zero or denormal exponent branch is dead: the f64 is count / 10**k with count >= 1 and k <= 6, so it is >= 1e-6 and its "
               "exponent field is never 0; the corpus counts zero denormal reaches",
}


def make_patches(image, spec):
    patches = {}
    for va, at, old, new, _ in spec:
        offset = image.offset(va + at)
        if image.blob[offset] != old:
            raise cpu.EvidenceError("patch byte mismatch at %#x" % (va + at))
        patches[va + at] = new
    return patches


def run_case(harness, c):
    log, out = harness.run(c)
    return log, out


def compare(harness, c, mut=(), strict=True):
    """Return None if the machine run equals the model, else a short description of the first difference."""
    try:
        log, out = harness.run(c)
    except cpu.Halt as stop:
        return "halt: %s" % stop
    want_log, want_out = model(c, mut)
    if harness.real_kernel:
        log = [r for r in log if r[0] != "kernel"]
        want_log = [r for r in want_log if r[0] != "kernel"]
    if want_out[0] == "panic" and out[0] == "panic":
        n = len(want_log)
        if out != want_out or log[:n] != want_log:
            return "panic differs: %s vs %s" % (out, want_out)
        return None
    if log != want_log or out != want_out:
        return "differs: machine %s model %s" % (outcome_name(out), outcome_name(want_out))
    return None


def corpus(count):
    return [gen_case(seed) for seed in range(1, count + 1)]


def write_lines(path, lines):
    with open(path, "w", newline="\n") as handle:
        for line in lines:
            handle.write(line + "\n")


def static_rows(image):
    rows = [("address", "bytes", "meaning")]
    for va, width, meaning in ((0x458DC8, 8, "-1.0 added to the book scale"), (0x4592B0, 8, "+1.0 added back / scale 1.0 for HYPE and PURR"),
                               (0x459090, 8, "2**64 clamp"), (0x459360, 8, "2**63 cast bias"), (0x458D58, 8, "saturation threshold"),
                               (0x459F10, 4, "token name HYPE"), (0x45A1E8, 4, "token name PURR"),
                               (0x5ED748, 56, "powers of ten 10**0..10**6"), (0x4553C4, 12, "zero decimal tail")):
        off = image.offset(va)
        rows.append(("%#x" % va, bytes(image.blob[off:off + width]).hex(), meaning))
    return ["\t".join(r) for r in rows]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=10000)
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = cpu.load_image()
    fast, slow = Harness(image), Harness(image, real_kernel=True)
    cases = corpus(args.cases)
    lines, kinds, failures, steps = ["seed\tkernel\tevents\toutcome\tsignature"], {}, [], 0
    for c in cases:
        harness = slow if c.real_kernel else fast
        diff = compare(harness, c)
        log, got = harness.log, None
        if diff:
            failures.append((c.seed, diff))
        want_log, want_out = model(c)
        kinds[outcome_name(want_out)] = kinds.get(outcome_name(want_out), 0) + 1
        shown = [r for r in want_log if not (c.real_kernel and r[0] == "kernel")]
        if c.seed % 2:
            lines.append("%d\t%s\t%d\t%s\t%s" % (c.seed, "real" if c.real_kernel else "stub", len(want_log), outcome_name(want_out),
                                                 sig(want_log, want_out, c.real_kernel)))
        steps += harness.machine.steps - 0
        harness.machine.steps = 0
    if failures:
        raise SystemExit("model and machine differ: %r" % failures[:3])
    write_lines(out / "cases.tsv", lines)
    write_lines(out / "outcome-kinds.tsv", ["outcome\tcases"] + ["%s\t%d" % kv for kv in sorted(kinds.items())])
    write_lines(out / "constants.tsv", static_rows(image))
    # negative controls: byte patches run on the machine, model variants run against the machine's recorded logs
    controls = ["control\tkind\tdetail\tdetected\tfirst_difference"]
    equivalent = ["control\tmeaning\treason"]
    REACH["zero"] = REACH["denormal"] = 0
    for c in cases:
        model(c)
    if REACH["zero"] or REACH["denormal"]:
        raise SystemExit("the dead exponent branch was reached: %r" % REACH)
    reach = dict(REACH)
    REACH["frozen"] = 1
    detected = total = 0
    battery = cases[:1500]
    for va, at, old, new, meaning in PATCHES:
        patched = Harness(image, make_patches(image, [(va, at, old, new, meaning)]))
        hit = ""
        for c in battery:
            if c.real_kernel and not (0x2C50426 <= va <= 0x2C50458):
                continue
            h = patched if not c.real_kernel else Harness(image, patched.machine.patches, real_kernel=True)
            diff = compare(h, c)
            if diff:
                hit = "seed %d %s" % (c.seed, diff[:60])
                break
        total += 1
        detected += bool(hit)
        if not hit and va not in EQUIVALENT_NOTES:
            raise SystemExit("undetected patch without a recorded reason: %#x" % va)
        if not hit:
            equivalent.append("%#x+%d\t%s\t%s" % (va, at, meaning, EQUIVALENT_NOTES[va]))
        controls.append("%#x+%d\tpatch\t%s\t%d\t%s" % (va, at, meaning, bool(hit), hit))
    for name in MUTANTS:
        hit = ""
        for c in cases:
            h = slow if c.real_kernel else fast
            if compare(h, c, (name,)):
                hit = "seed %d" % c.seed
                break
        total += 1
        detected += bool(hit)
        controls.append("%s\tmodel\tvariant of the statement\t%d\t%s" % (name, bool(hit), hit))
    if detected + len(equivalent) - 1 != total:
        raise SystemExit("controls neither detected nor justified")
    write_lines(out / "controls.tsv", controls)
    write_lines(out / "equivalent-mutants.tsv", equivalent)
    write_lines(out / "callees.tsv", callee_rows(image))
    write_lines(out / "fields.tsv", FIELD_ROWS)
    measure = dict(cases=len(cases), sampled_rows=len(lines) - 1, negative_controls=total, negative_detected=detected, equivalent=len(equivalent) - 1,
                   real_kernel_cases=sum(1 for c in cases if c.real_kernel), outcomes=len(kinds),
                   dead_branch_reaches=reach["zero"] + reach["denormal"])
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    print(json.dumps(measure, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
