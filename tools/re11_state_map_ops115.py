#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM state-map probe family and the code-cache install 0x54793e0.

The EVM state layer keeps its per-block maps in hashbrown tables whose hasher is foldhash with a
per-map seed (map header word +0x20) and the global seed word read through GOT 0x64dfa78.  The
binary holds one machine-code copy of the probe per (key type, bucket size, build): 12 "entry"
bodies (look the key up; hit = occupied block, miss = vacant block with the hash and the key, after
a reserve call when no growth is left), 7 "get" bodies (return the value pointer or null), and one
"contains" body.  The tool evaluates the real bytes of all 20 bodies with the concrete evaluator of
tools/re11_access_list115.py and compares each case with one generic model (foldhash of a 20- or
32-byte key, SSE2 group probe, bucket geometry).  It then reconstructs the first user of the
32-byte/40-byte instance, 0x54793e0 (install the code object of an account): it evaluates the real
probe 0x4ef7e50 inside the real caller, models the empty-code shortcut, the cache hit, and the
miss path (load callback, hashbrown insertion with the exact control-byte rules, growth and item
counters, checked Arc increments, replacing the account's code pointer).  No external program is
run and the binary is never executed.  Negative controls show that wrong models and corrupted
code bytes are detected.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import fde_extents  # noqa: E402
import re11_access_list115 as al  # noqa: E402

BINARY, SHA256, M64 = al.BINARY, al.SHA256, al.M64
fail, Boundary, Stream, put, u = al.fail, al.Boundary, al.Stream, al.put, al.u
ToolError = al.ToolError
STACK_TOP, FS_BASE = al.STACK_TOP, al.FS_BASE

SEED_GOT = 0x64dfa78
ENTRY_FRAME = STACK_TOP - 0x4000  # rsp at function entry (the return-address slot)
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]  # rbx rbp r12 r13 r14 r15
SAVED_REGS = [3, 5, 12, 13, 14, 15]
CLOBBER = [0xc10b_0000_0000_0000 + 0x101 * n for n in range(16)]
SCRATCH_REGS = [0, 1, 2, 6, 7, 8, 9, 10, 11]

# (address, kind, key length, bucket stride, value offset inside the bucket, reserve GOT slot, role label)
FUNCS = [
    (0x3ed7040, "entry", 20, 0xa8, 0, 0x64e6d48, "account map entry, build A"),
    (0x4ef78b0, "entry", 20, 0xa8, 0, 0x64e6d48, "account map entry, build B"),
    (0x4ef7ce0, "entry", 20, 0xa0, 0, 0x64e6c88, "address-keyed map entry, 0xa0 buckets"),
    (0x3ed6ee0, "entry", 20, 0x40, 0, 0x64e7030, "address-keyed map entry, 0x40 buckets (1)"),
    (0x3ed71b0, "entry", 20, 0x40, 0, 0x64e6d78, "address-keyed map entry, 0x40 buckets (2)"),
    (0x4ef7b80, "entry", 20, 0x40, 0, 0x64e6d78, "address-keyed map entry, 0x40 buckets (3)"),
    (0x5be1e70, "entry", 20, 0x40, 0, 0x64e6d78, "address-keyed map entry, 0x40 buckets (4)"),
    (0x3ed6d80, "entry", 32, 0x68, 0, 0x64e7028, "32-byte-keyed map entry, 0x68 buckets"),
    (0x4ef7a20, "entry", 32, 0x40, 0, 0x64e6c90, "32-byte-keyed map entry, 0x40 buckets"),
    (0x4ef7e50, "entry", 32, 0x28, 0, 0x64e6c98, "code-hash map entry, 0x28 buckets"),
    (0x3ed7e80, "get", 20, 0xa8, 0x18, None, "account map get, build A"),
    (0x4ef9240, "get", 20, 0xa8, 0x18, None, "account map get, build B"),
    (0x5be2230, "get", 20, 0xa8, 0x18, None, "account map get, build C"),
    (0x3ed7d80, "get", 20, 0x40, 0x18, None, "address-keyed map get, 0x40 buckets (A)"),
    (0x4ef9140, "get", 20, 0x40, 0x18, None, "address-keyed map get, 0x40 buckets (B)"),
    (0x5be2460, "get", 20, 0x40, 0x18, None, "address-keyed map get, 0x40 buckets (C)"),
    (0x5be2350, "get", 32, 0x68, 0x20, None, "32-byte-keyed map get, 0x68 buckets"),
    (0x5bdef30, "contains", 20, 0x40, 0, None, "address set contains, 0x40 buckets"),
]
INSTALL = 0x54793e0
PROBE_CODE = 0x4ef7e50
HASH_LOADER_GOT, ARC_CELL_GOT, ARC_DROP_GOT, LAZY_INIT = 0x64e6458, 0x64e6c78, 0x64e4fa8, 0x5b084ff
ROD_HASH_LOW, ROD_HASH_HIGH, ROD_PSUB = 0x4537f0, 0x452020, 0x450790
CASES_ENTRY, CASES_GET, CASES_INSTALL = 700, 600, 2600

HDR_AT, TBL_AT, KEY_AT, OUT_AT = 0x7d00_0000_0000, 0x7d00_0010_0000, 0x7d00_0020_0000, 0x7d00_0030_0000
G_AT = 0x7d00_0040_0000
ACCT_AT, PP_AT, CTX_AT, HASHER_AT = 0x7d00_0100_0000, 0x7d00_0101_0000, 0x7d00_0102_0000, 0x7d00_0103_0000
ARCS_AT, HEAP_AT, OLDARC_AT, ALT_AT = 0x7d00_0104_0000, 0x7d00_0105_0000, 0x7d00_0106_0000, 0x7d00_0107_0000
EMPTY_ARC_AT = 0x7d00_0108_0000
RES_GROWTH = 9


# ---------------------------------------------------------------- evaluator
class Mach(al.Machine):
    """Adds the lock prefix, signed conditions with a real overflow flag, and executed-address tracking."""

    def __init__(self, image, override=None):
        self.seen = set()
        super().__init__(image, override)

    def reset(self):
        super().reset()
        self.of = None

    def fetch(self, va):
        form = self.cache.get(va)
        if form is None:
            code = bytearray(self.image.code(va, 16))
            for i in range(16):
                if va + i in self.override:
                    code[i] = self.override[va + i]
            form = decode_lock(bytes(code), va)
            self.cache[va] = form
        return form

    def flags_add(self, a, b, size):
        res = a + b
        self.cf = res >> size != 0
        res &= (1 << size) - 1
        hb = size - 1
        self.of = (a >> hb) == (b >> hb) and (res >> hb) != (a >> hb)
        self.zf, self.sf = res == 0, bool(res >> hb)
        return res

    def flags_sub(self, a, b, size):
        self.cf = a < b
        res = (a - b) & ((1 << size) - 1)
        hb = size - 1
        self.of = (a >> hb) != (b >> hb) and (res >> hb) != (a >> hb)
        self.zf, self.sf = res == 0, bool(res >> hb)
        return res

    def cond(self, code, va):
        if code < 10:
            return super().cond(code, va)
        if self.of is None:
            fail(f"overflow flag read without a defining instruction at {va:#x}")
        if code == 12:
            return self.sf != self.of
        if code == 13:
            return self.sf == self.of
        if code == 14:
            return self.zf or self.sf != self.of
        if code == 15:
            return not self.zf and self.sf == self.of
        fail(f"unsupported condition {code} at {va:#x}")

    def step(self, va):
        self.seen.add(va)
        return super().step(va)


def decode_lock(code, va):
    if code[0] == 0xf0:
        form = al.decode(bytes(code[1:]) + b"\0", va + 1)
        form["len"] += 1
        form["lock"] = True
        return form
    return al.decode(bytes(code), va)


def sweep(image, start, end):
    rows, va = [], start
    while va < end:
        form = decode_lock(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    if va != end:
        fail(f"linear decode overruns {end:#x}")
    return rows


# ---------------------------------------------------------------- reconstruction: hash and probe
def fold(a, b):
    p = (a & M64) * (b & M64)
    return (p & M64) ^ (p >> 64)


def w64(d, at):
    return int.from_bytes(d[at:at + 8], "little")


def hash_key(key, seed, g, mut=frozenset()):
    """foldhash of a 20-byte address or a 32-byte word with the per-map seed and the global word."""
    k0, k1 = w64(key, 0), w64(key, 8)
    if "swap_words" in mut:
        k0, k1 = k1, k0
    if "seed_ignored" in mut:
        seed = 0
    if len(key) == 20:
        k2 = int.from_bytes(key[16:20], "little")
        return fold(fold(k1 ^ g, k0 ^ seed) ^ k2, g)
    k2, k3 = w64(key, 16), w64(key, 24)
    return fold(fold(k1 ^ g, k0 ^ seed) ^ k2, (g ^ k3) if "k3_plain" not in mut else k3)


def set_ctrl(ctrl, mask, i, v, mut=frozenset()):
    ctrl[i] = v
    if "no_mirror" not in mut:
        ctrl[((i - 16) & mask) + 16] = v


def insert_slot(ctrl, mask, h, mut=frozenset()):
    pos, st = h & mask, 0
    for _ in range(4 * mask + 8):
        bits = [i for i in range(16) if ctrl[pos + i] & 0x80]
        if bits:
            idx = (pos + bits[0]) & mask
            if ctrl[idx] & 0x80 == 0 and "no_wrap_fix" not in mut:
                idx = [i for i in range(16) if ctrl[i] & 0x80][0]
            return idx
        st += 16 if "stride8" not in mut else 8
        pos = (pos + st) & mask
    return 0


def probe(ctrl, tbl, nb, keylen, stride, key, h, mut=frozenset()):
    """Group probe: bucket index of the key or None (an EMPTY byte ends the walk)."""
    h2 = h >> (57 if "h2_56" not in mut else 56)
    mask = nb - 1
    pos, st = h & mask, 0
    cmp_len = keylen if "cmp_short" not in mut else keylen - 1
    for _ in range(4 * mask + 8):
        grp = ctrl[pos:pos + 16]
        for b in range(16):
            if grp[b] == h2:
                idx = (pos + b) & mask
                at = nb * stride - (idx + 1) * stride
                if tbl[at:at + cmp_len] == key[:cmp_len]:
                    return idx
        if 0xff in grp:
            return None
        st += 16 if "stride8" not in mut else 8
        pos = (pos + st) & mask
    return None


def model_map(kind, keylen, stride, val, hdr, tbl, key, g, nb, mut=frozenset()):
    """(rax, header image, out block image, events) of one entry/get/contains call."""
    hdr, out, ev = bytearray(hdr), bytearray(b"\x33" * 0x40), []
    ctrl_at, seed = u(hdr, 0, 8), u(hdr, 0x20, 8)
    if kind != "entry" and u(hdr, 0x18, 8) == 0 and "no_items_check" not in mut:
        return 0, hdr, out, ev
    ctrl = tbl[nb * stride:]
    h = hash_key(key, seed, g, mut)
    idx = probe(ctrl, tbl, nb, keylen, stride, key, h, mut)
    if kind == "get":
        return (0 if idx is None else ctrl_at - idx * stride - stride + val), hdr, out, ev
    if kind == "contains":
        return int(idx is not None), hdr, out, ev
    if idx is not None:
        put(out, 0, 8, 0)
        put(out, 8, 8, ctrl_at - idx * stride)
        put(out, 0x10, 8, HDR_AT)
    else:
        if (u(hdr, 0x10, 8) == 0) != ("growth_inverted" in mut):
            ev.append(("reserve", 0, 1, 0x20, 1))
            put(hdr, 0x10, 8, RES_GROWTH)
        put(out, 0, 8, HDR_AT)
        put(out, 8, 8, h)
        out[0x10:0x10 + keylen] = key
    return OUT_AT, hdr, out, ev


# ---------------------------------------------------------------- case construction
def build_table(s, keylen, stride, nb, nitems, seed, g):
    mask = nb - 1
    ctrl = bytearray(b"\xff" * (nb + 16))
    buckets = bytearray(s.take(nb * stride))
    placed = []
    for _ in range(nitems):
        key = s.take(keylen)
        h = hash_key(key, seed, g)
        i = insert_slot(ctrl, mask, h)
        if ctrl[i] & 0x80 == 0:
            continue
        set_ctrl(ctrl, mask, i, h >> 57)
        at = nb * stride - (i + 1) * stride
        buckets[at:at + keylen] = key
        placed.append((i, key))
    return ctrl, buckets, placed


def long_table(s, keylen, stride, key, seed, g, mode):
    """A 64-bucket table with one empty slot, so the walk crosses several groups (probe offsets +16, +48, +32)."""
    nb, mask = 64, 63
    h = hash_key(key, seed, g)
    h2, p = h >> 57, h & mask
    ctrl = bytearray(b"\xff" * (nb + 16))
    buckets = bytearray(s.take(nb * stride))
    empty = (p + (32 if mode == "miss" else 34)) & mask
    hit = (p + (16 if mode == "g1" else 48)) & mask
    placed = []
    for i in range(nb):
        if i == empty:
            continue
        v = s.below(0x80)
        v = v ^ 1 if v == h2 else v
        at = nb * stride - (i + 1) * stride
        if i == hit and mode != "miss":
            v = h2
            buckets[at:at + keylen] = key
        set_ctrl(ctrl, mask, i, v)
        placed.append((i, bytes(buckets[at:at + keylen])))
    return ctrl, buckets, placed


KINDS = ["hit", "miss", "hit_dense", "miss_dense", "h2_collide", "tail_diff", "tombstone", "zero_items",
         "growth0_miss", "seed_edge", "hit_late", "tail_diff_dense", "long_hit", "long_hit_g1", "long_miss"]
EDGE_WORDS = [0, M64, 1, 1 << 63, 0x5555_5555_5555_5555]


def make_map_case(s, spec, n):
    addr, kind, keylen, stride, val, _got, _role = spec
    ck = KINDS[n % len(KINDS)]
    nb = s.pick([4, 8, 16, 32, 64, 4, 8])
    g = int.from_bytes(s.take(8), "little")
    seed = int.from_bytes(s.take(8), "little")
    if ck == "seed_edge":
        seed, g = s.pick(EDGE_WORDS), s.pick(EDGE_WORDS)
    if ck.startswith("long"):
        nb = 64
        key = s.take(keylen)
        ctrl, buckets, placed = long_table(s, keylen, stride, key, seed, g, {"long_hit": "g2", "long_hit_g1": "g1", "long_miss": "miss"}[ck])
        return dict(kind=ck, nb=nb, g=g, seed=seed, ctrl=bytes(ctrl), buckets=bytes(buckets), key=key, growth=s.pick([0, 5]),
                    items=len(placed), placed=len(placed))
    dense = ck.endswith("dense")
    nitems = nb - 1 if dense else s.below(nb)
    ctrl, buckets, placed = build_table(s, keylen, stride, nb, nitems, seed, g)
    mask = nb - 1
    if ck == "tombstone" and placed:
        for i, _k in placed:
            if s.below(3) == 0:
                set_ctrl(ctrl, mask, i, 0x80)
    key = s.take(keylen)
    if ck in ("hit", "hit_dense", "hit_late") and placed:
        key = (placed[-1] if ck == "hit_late" else s.pick(placed))[1]
    elif ck == "tombstone" and placed:
        key = s.pick(placed)[1]
    elif ck in ("tail_diff", "tail_diff_dense") and placed:
        base = bytearray(s.pick(placed)[1])
        j = n // len(KINDS)
        base[keylen - 1 - (j % 2) * s.below(keylen)] ^= 1 << s.below(8)
        key = bytes(base)
        h2 = hash_key(key, seed, g) >> 57
        grp = [i for i, _k in placed]
        slot = (hash_key(key, seed, g) & mask)
        for i, _k in placed:  # make every stored control byte collide with the query's top-7 bits
            if i == (slot + 0) & mask or s.below(2):
                set_ctrl(ctrl, mask, i, h2)
    elif ck == "h2_collide" and placed:
        h = hash_key(key, seed, g)
        for i, _k in placed:
            set_ctrl(ctrl, mask, i, h >> 57)
    growth = 0 if ck == "growth0_miss" else s.pick([0, 3, 5, 5, 7])
    items = len(placed) if ck != "zero_items" else 0
    if s.below(9) == 0 and ck != "zero_items":
        items = 0
    return dict(kind=ck, nb=nb, g=g, seed=seed, ctrl=bytes(ctrl), buckets=bytes(buckets), key=key, growth=growth,
                items=items, placed=len(placed))


def map_regions(c, spec):
    _a, _k, keylen, stride, _v, _g, _r = spec
    nb = c["nb"]
    hdr = bytearray(0x28)
    put(hdr, 0, 8, TBL_AT + nb * stride)
    put(hdr, 8, 8, nb - 1)
    put(hdr, 0x10, 8, c["growth"])
    put(hdr, 0x18, 8, c["items"])
    put(hdr, 0x20, 8, c["seed"])
    gp = bytearray(8)
    put(gp, 0, 8, c["g"])
    return [(HDR_AT, hdr), (TBL_AT, bytearray(c["buckets"] + c["ctrl"])), (KEY_AT, bytearray(c["key"].ljust(0x40, b"\xa7"))),
            (OUT_AT, bytearray(b"\x33" * 0x40)), (G_AT, gp)]


def rflags_ok(m):
    return all(m.regs[r] == v for r, v in zip(SAVED_REGS, SAVED)) and m.regs[4] == ENTRY_FRAME


def run_map(image, spec, c, override=None, shared=None):
    addr, kind, keylen, stride, val, got, _r = spec
    m = shared or Mach(image, override)
    m.reset()
    m.regs[4] = ENTRY_FRAME
    for r, v in zip(SAVED_REGS, SAVED):
        m.regs[r] = v
    bufs = {base: m.add_region(base, len(buf), bytes(buf)) for base, buf in map_regions(c, spec)}
    m.words[SEED_GOT] = G_AT
    ev = []

    def reserve(mc):
        ev.append(("reserve", mc.regs[7] - HDR_AT, mc.regs[6] & 0xffffffff, mc.regs[2] - HDR_AT, mc.regs[1] & 0xffffffff))
        mc.store(mc.regs[7] + 0x10, 8, RES_GROWTH)
        for r in SCRATCH_REGS:
            mc.regs[r] = CLOBBER[r]
    if got:
        m.stubs[image.word(got)] = reserve
    if kind == "entry":
        m.regs[7], m.regs[6], m.regs[2] = OUT_AT, HDR_AT, KEY_AT
    else:
        m.regs[7], m.regs[6] = HDR_AT, KEY_AT
    try:
        m.run(addr, 3000)
    except ToolError as e:
        return {"error": str(e)}
    rax = m.regs[0] if kind != "contains" else m.regs[0] & 0xff
    return {"steps": m.steps, "rax": rax, "hdr": bytes(bufs[HDR_AT]), "out": bytes(bufs[OUT_AT]), "tbl": bytes(bufs[TBL_AT]), "ev": ev,
            "saved": rflags_ok(m)}


def compare_map(spec, c, got, mut=frozenset()):
    addr, kind, keylen, stride, val, _g, _r = spec
    if "error" in got:
        return False
    rax, hdr, out, ev = model_map(kind, keylen, stride, val, map_regions(c, spec)[0][1], c["buckets"] + c["ctrl"],
                                  c["key"], c["g"], c["nb"], mut)
    return (got["rax"] == rax and got["hdr"] == bytes(hdr) and got["out"] == bytes(out) and got["ev"] == ev
            and got["tbl"] == c["buckets"] + c["ctrl"] and got["saved"])


def map_outcome(spec, c, got):
    kind = spec[1]
    if "error" in got:
        return "error"
    if kind == "entry":
        if u(got["out"], 0, 8) == 0 and got["rax"] == OUT_AT:
            return "occupied"
        return "vacant_reserve" if got["ev"] else "vacant"
    if kind == "contains":
        return "found" if got["rax"] else "absent"
    return "found" if got["rax"] else "null"


# ---------------------------------------------------------------- code install 0x54793e0
class Arcs:
    """Synthetic allocator for Arc cells created by the load callback."""

    def __init__(self):
        self.n = 0

    def alloc(self):
        at = HEAP_AT + 0x10 * self.n
        self.n += 1
        if self.n > 0x100:
            fail("synthetic heap exhausted")
        return at


def rod(image, va, n=16):
    return image.read(va, n)


def make_install_case(s, n, image):
    kinds = ["has_code", "empty_hash", "empty_hash_lazy", "empty_edge", "hit", "hit_edge", "miss", "miss_dense",
             "miss_edge", "near_empty_low", "near_empty_high", "miss_growth0", "miss_reentrant", "miss_drop", "hit_late",
             "miss_tomb", "long_hit", "long_miss", "tail_diff"]
    ck = kinds[n % len(kinds)]
    nb = s.pick([4, 8, 16, 32, 64])
    g = int.from_bytes(s.take(8), "little")
    seed = int.from_bytes(s.take(8), "little")
    empty_hash = rod(image, ROD_HASH_LOW) + rod(image, ROD_HASH_HIGH)
    qkey = s.take(32)
    if ck in ("long_hit", "long_miss"):
        nb = 64
        ctrl, buckets, placed = long_table(s, 32, 40, qkey, seed, g, "g2" if ck == "long_hit" else "miss")
    else:
        nitems = nb - 1 if ck == "miss_dense" else s.below(nb)
        ctrl, buckets, placed = build_table(s, 32, 40, nb, nitems, seed, g)
    mask = nb - 1
    if ck == "miss_tomb":
        for i, _k in placed:
            if s.below(2):
                set_ctrl(ctrl, mask, i, 0x80)
    arcs = bytearray()
    counts = [s.pick([1, 2, 3, 0x7fff_ffff_ffff_ffff, 0x100]) for _ in placed]
    if ck == "hit_edge":
        counts = [s.pick([0, M64, M64 - 1, 1 << 63, 0x7fff_ffff_ffff_ffff]) for _ in placed]
    for k, (i, _key) in enumerate(placed):  # value word of each bucket: pointer to its Arc cell
        at = nb * 40 - (i + 1) * 40 + 32
        put(buckets, at, 8, ARCS_AT + 0x10 * k)
        arcs += struct.pack("<QQ", counts[k], k)
    acct = bytearray(s.take(0x90))
    put(acct, 0x70, 8, 0)
    hash_ = qkey
    if ck == "tail_diff" and placed:
        b = bytearray(s.pick(placed)[1])
        b[31 - s.below(2) * s.below(32)] ^= 1 << s.below(8)
        hash_ = bytes(b)
        h2 = hash_key(hash_, seed, g) >> 57
        for i, _k in placed:
            set_ctrl(ctrl, mask, i, h2)
    if ck in ("empty_hash", "empty_hash_lazy", "empty_edge"):
        hash_ = empty_hash
    elif ck in ("near_empty_low", "near_empty_high"):
        b = bytearray(empty_hash)
        b[(n // len(kinds)) % 16 + (0 if ck == "near_empty_low" else 16)] ^= 1 << s.below(8)
        hash_ = bytes(b)
    elif ck in ("hit", "hit_edge", "hit_late") and placed:
        hash_ = (placed[-1] if ck == "hit_late" else s.pick(placed))[1]
    acct[0x48:0x68] = hash_
    if ck == "has_code":
        put(acct, 0x70, 8, OLDARC_AT)
    new_count = s.pick([1, 1, 1, 2, 3, 0x7fff_ffff_ffff_ffff])
    if ck == "miss_edge":
        new_count = s.pick([M64, M64 - 1, 0, 1 << 63])
    reentrant = ck in ("miss_reentrant", "miss_drop")
    old_count = 1 if ck == "miss_drop" else s.pick([2, 5, 1])
    empty_count = s.pick([1, 4, 0x7fff_ffff_ffff_ffff])
    if ck == "empty_edge":
        empty_count = s.pick([0, M64, M64 - 1, 1 << 63])
    return dict(kind=ck, nb=nb, g=g, seed=seed, ctrl=bytes(ctrl), buckets=bytes(buckets), arcs=bytes(arcs), acct=bytes(acct),
                growth=0 if ck == "miss_growth0" else s.pick([0, 2, 5, 7]), items=len(placed), new_count=new_count,
                reentrant=reentrant, old_count=old_count, empty_count=empty_count,
                lazy_state=1 if ck == "empty_hash_lazy" else s.pick([0, 0, 1, 2]), key=hash_)


def install_regions(c, cell_at):
    nb = c["nb"]
    ctx = bytearray(0xa0)
    put(ctx, 0x40, 8, TBL_AT + nb * 40)
    put(ctx, 0x48, 8, nb - 1)
    put(ctx, 0x50, 8, c["growth"])
    put(ctx, 0x58, 8, c["items"])
    put(ctx, 0x60, 8, c["seed"])
    put(ctx, 0x90, 8, HASHER_AT)
    pp = bytearray(8)
    put(pp, 0, 8, CTX_AT)
    gp = bytearray(8)
    put(gp, 0, 8, c["g"])
    cell = bytearray(0x10)
    put(cell, 0, 8, EMPTY_ARC_AT)
    put(cell, 8, 4, c["lazy_state"])
    empty_arc = bytearray(16)
    put(empty_arc, 0, 8, c["empty_count"])
    old = bytearray(16)
    put(old, 0, 8, c["old_count"])
    return [(ACCT_AT, bytearray(c["acct"])), (PP_AT, pp), (CTX_AT, ctx), (TBL_AT, bytearray(c["buckets"] + c["ctrl"])),
            (ARCS_AT, bytearray(c["arcs"].ljust(0x400, b"\0"))), (HEAP_AT, bytearray(0x1000)), (G_AT, gp),
            (HASHER_AT, bytearray(0x20)), (cell_at, cell), (EMPTY_ARC_AT, empty_arc), (OLDARC_AT, old)]


class InstallModel:
    """Pure model of 0x54793e0 over byte images; mirrors the contracts used by the evaluator stubs."""

    def __init__(self, c, image, mut=frozenset()):
        self.c, self.image, self.mut = c, image, mut
        self.mem = {base: bytearray(buf) for base, buf in install_regions(c, 0x7d00_0109_0000)}
        self.ev, self.arcs, self.status = [], Arcs(), "ok"
        self.empty_hash = rod(image, ROD_HASH_LOW) + rod(image, ROD_HASH_HIGH)

    def bump(self, base, off, size, delta):
        v = u(self.mem[base], off, size)
        put(self.mem[base], off, size, (v + delta) & ((1 << (8 * size)) - 1))

    def arc_inc(self, base, off):
        old = u(self.mem[base], off, 8)
        sold = old - (1 << 64) if old >> 63 else old
        put(self.mem[base], off, 8, (old + 1) & M64)
        if sold + 1 <= 0:
            self.status = "ud2"
            return False
        return True

    def run(self):
        c, acct, ctx = self.c, self.mem[ACCT_AT], self.mem[CTX_AT]
        if u(acct, 0x70, 8) != 0:
            return
        h = bytes(acct[0x48:0x68])
        cell = self.mem[0x7d00_0109_0000]
        if h == self.empty_hash and "no_empty_shortcut" not in self.mut:
            if u(cell, 8, 4) != 0:
                self.ev.append(("lazy",))
                put(cell, 8, 4, 0)
            if not self.arc_inc(EMPTY_ARC_AT, 0):
                return
            return self.install(EMPTY_ARC_AT)
        tbl = self.mem[TBL_AT]
        nb = c["nb"]
        ctrl_off = nb * 40
        hdr = bytes(ctx[0x40:0x68])
        seed = u(hdr, 0x20, 8)
        hh = hash_key(h, seed, c["g"], self.mut)
        idx = probe(tbl[ctrl_off:], tbl, nb, 32, 40, h, hh, self.mut)
        if idx is not None:
            slot_end = nb * 40 - idx * 40
            arc_at = u(tbl, slot_end - 8, 8)
            if not self.arc_inc(ARCS_AT, arc_at - ARCS_AT):
                return
            return self.install(arc_at)
        if u(ctx, 0x50, 8) == 0:
            self.ev.append(("reserve", 0x40, 1, 0x60, 1))
            put(ctx, 0x50, 8, RES_GROWTH)
        new = self.arcs.alloc()
        self.ev.append(("load", 0, h.hex()))
        put(self.mem[HEAP_AT], new - HEAP_AT, 8, c["new_count"])
        put(self.mem[HEAP_AT], new - HEAP_AT + 8, 8, 0)
        if c["reentrant"]:
            put(acct, 0x70, 8, OLDARC_AT)
        ctrl = tbl[ctrl_off:]
        slot = insert_slot(ctrl, nb - 1, hh, self.mut)
        old = ctrl[slot]
        set_ctrl(ctrl, nb - 1, slot, hh >> 57, self.mut)
        at = nb * 40 - (slot + 1) * 40
        tbl[at:at + 32] = h
        put(tbl, at + 32, 8, new)
        tbl[ctrl_off:] = ctrl
        put(ctx, 0x50, 8, (u(ctx, 0x50, 8) - (old & 1)) & M64)
        put(ctx, 0x58, 8, u(ctx, 0x58, 8) + 1)
        if not self.arc_inc(HEAP_AT, new - HEAP_AT):
            return
        return self.install(new)

    def install(self, arc):
        acct = self.mem[ACCT_AT]
        old = u(acct, 0x70, 8)
        if old:
            self.bump_at(old)
        put(acct, 0x70, 8, arc)

    def bump_at(self, ptr):
        base = OLDARC_AT
        v = (u(self.mem[base], 0, 8) - 1) & M64
        put(self.mem[base], 0, 8, v)
        if v == 0:
            self.ev.append(("drop", 0x70))


def run_install(image, c, override=None, shared=None):
    m = shared or Mach(image, override)
    m.reset()
    m.regs[4] = ENTRY_FRAME
    for r, v in zip(SAVED_REGS, SAVED):
        m.regs[r] = v
    cell_at = image.word(ARC_CELL_GOT)
    bufs = {base: m.add_region(base, len(buf), bytes(buf)) for base, buf in install_regions(c, cell_at)}
    m.words[SEED_GOT] = G_AT
    ev, arcs = [], Arcs()

    def clobber(mc):
        for r in SCRATCH_REGS:
            mc.regs[r] = CLOBBER[r]

    def reserve(mc):
        ev.append(("reserve", mc.regs[7] - CTX_AT, mc.regs[6] & 0xffffffff, mc.regs[2] - CTX_AT, mc.regs[1] & 0xffffffff))
        mc.store(mc.regs[7] + 0x10, 8, RES_GROWTH)
        clobber(mc)

    def loader(mc):
        new = arcs.alloc()
        ev.append(("load", mc.regs[7] - HASHER_AT,
                   b"".join(mc.load(mc.regs[6] + 8 * i, 8).to_bytes(8, "little") for i in range(4)).hex()))
        mc.store(new, 8, c["new_count"])
        mc.store(new + 8, 8, 0)
        if c["reentrant"]:
            mc.store(ACCT_AT + 0x70, 8, OLDARC_AT)
        clobber(mc)
        mc.regs[0] = new

    def lazy(mc):
        ev.append(("lazy",))
        mc.store(mc.regs[7] + 8, 4, 0)
        clobber(mc)

    def drop(mc):
        ev.append(("drop", mc.regs[7] - ACCT_AT))
        clobber(mc)
    m.stubs[image.word(0x64e6c98)] = reserve
    m.stubs[image.word(HASH_LOADER_GOT)] = loader
    m.stubs[image.word(ARC_DROP_GOT)] = drop
    m.stubs[LAZY_INIT] = lazy
    m.regs[7], m.regs[6] = ACCT_AT, PP_AT
    status = "ok"
    try:
        m.run(INSTALL, 3000)
    except ToolError as e:
        if "ud2" not in str(e):
            return {"error": str(e)}
        status = "ud2"
    return {"steps": m.steps, "status": status, "mem": {k: bytes(v) for k, v in bufs.items()}, "ev": ev, "saved": status == "ud2" or rflags_ok(m)}


def compare_install(image, c, got, mut=frozenset()):
    if "error" in got:
        return False
    mod = InstallModel(c, image, mut)
    mod.run()
    if mod.status != got["status"] or mod.ev != got["ev"] or not got["saved"]:
        return False
    cell_at = image.word(ARC_CELL_GOT)
    want = {k: bytes(v) for k, v in mod.mem.items()}
    want[cell_at] = want.pop(0x7d00_0109_0000)
    return want == got["mem"]


def install_outcome(c, got):
    if "error" in got:
        return "error"
    if got["status"] == "ud2":
        return "ud2"
    return {"has_code": "early_return"}.get(c["kind"], "installed_" + ("miss" if any(e[0] == "load" for e in got["ev"]) else "shared"))


# ---------------------------------------------------------------- evidence
def static_rows(image, spec_list):
    starts = [s[0] for s in spec_list]
    rows = al.fde_rows(image, set(starts))
    out = []
    for s in spec_list:
        lo, hi = rows[s[0]]
        out.append((s, lo, hi))
    return out


# ---------------------------------------------------------------- controls
MAP_MUT = {"entry": ["swap_words", "seed_ignored", "h2_56", "cmp_short", "stride8", "growth_inverted"],
           "get": ["swap_words", "seed_ignored", "h2_56", "cmp_short", "stride8", "no_items_check"],
           "contains": ["swap_words", "seed_ignored", "h2_56", "cmp_short", "stride8", "no_items_check"]}
INSTALL_MUT = ["swap_words", "seed_ignored", "h2_56", "cmp_short", "stride8", "no_empty_shortcut", "no_mirror",
               "no_wrap_fix", "k3_plain"]
IMM8 = {0x0f70, 0x0fc6, 0xc6, 0xa8, 0x0c, 0x1c, 0x3c, 0x24, 0x83, 0xc1, 0x80, 0x6b}
IMM32 = {0x69, 0x3d, 0x81, 0xc7, 0xf7}
CONTROL_CASES, INSTALL_CONTROL_CASES = 160, 200


def imm_size(form):
    if "imm" not in form:
        return 0
    op = form["op"]
    if 0xb0 <= op <= 0xb7 or op in IMM8:
        return 1
    if 0xb8 <= op <= 0xbf:
        return 8 if form["rex"] & 8 else 4
    return 4 if op in IMM32 else 0


def disp8_pos(form):
    """Offset inside the instruction bytes of a one-byte displacement, or None."""
    b, i = form["bytes"], 0
    while b[i] in (0x66, 0x2e, 0xf3, 0xf2, 0x64, 0xf0):
        i += 1
    if 0x40 <= b[i] <= 0x4f:
        i += 1
    i += 2 if b[i] == 0x0f else 1
    if "rm" not in form or form["rm"][0] != "m" or form["rm"][1] == "rip":
        return None
    if b[i] >> 6 != 1:
        return None
    return i + 1 + (1 if b[i] & 7 == 4 else 0)


def corruptions(image, lo, hi, seen):
    """Deterministic list of (va, kind, patched address, new byte) for executed instructions of one body."""
    out = []
    for va, form in sweep(image, lo, hi):
        if va not in seen:
            continue
        b, op = form["bytes"], form["op"]
        if 0x70 <= op <= 0x7f:
            out.append((va, "jcc_invert", va, b[0] ^ 1))
        elif 0x0f80 <= op <= 0x0f8f:
            out.append((va, "jcc_invert", va + 1, b[1] ^ 1))
        n = imm_size(form)
        if n:
            out.append((va, "imm_flip", va + form["len"] - n, b[form["len"] - n] ^ 1))
        d = disp8_pos(form)
        if d is not None:
            out.append((va, "disp_flip", va + d, b[d] ^ 8))
    return out


def detect_corruption_map(image, spec, patch, n_cases):
    s = Stream(f"cases-{spec[0]:x}")
    m = Mach(image, {patch[2]: patch[3]})
    for n in range(n_cases):
        c = make_map_case(s, spec, n)
        try:
            got = run_map(image, spec, c, shared=m)
        except (ToolError, Boundary, KeyError, IndexError, ValueError):
            return True
        if not compare_map(spec, c, got):
            return True
    return False


def detect_corruption_install(image, patch, n_cases):
    s = Stream("cases-install")
    m = Mach(image, {patch[2]: patch[3]})
    for n in range(n_cases):
        c = make_install_case(s, n, image)
        try:
            got = run_install(image, c, shared=m)
        except (ToolError, Boundary, KeyError, IndexError, ValueError):
            return True
        if not compare_install(image, c, got):
            return True
    return False


# ---------------------------------------------------------------- evidence
def tsv(rows):
    return "".join("\t".join(str(x) for x in r) + "\n" for r in rows)


def callee_rows(image, name, lo, hi):
    out = []
    for va, form in sweep(image, lo, hi):
        op = form["op"]
        if op == 0xe8 and not (lo <= form["target"] < hi):
            out.append((name, f"{va:#x}", "call", f"{form['target']:#x}", "direct"))
        elif op == 0xff and form["reg"] & 7 == 2 and form["rm"][0] == "m" and form["rm"][1] == "rip":
            slot = (va + form["len"] + form["rm"][4]) & M64
            kind = "import" if slot in image.imports else "relative"
            out.append((name, f"{va:#x}", "call", f"{slot:#x}", f"got-{kind}:{image.word(slot):#x}"))
    return out


CONTRACTS = {
    "reserve": "reserve-one-more-bucket callee: records an event, stores the growth-left word 9 at map+0x10, clobbers every caller-saved register",
    "loader": "code-object loader (hash -> new Arc cell): records the 32 hash bytes, returns a fresh cell holding a chosen strong count",
    "drop": "Arc slow drop: records the account-relative address, clobbers caller-saved registers",
    "lazy": "lazy initialiser of the empty-code cell: records an event, clears the state dword at cell+8",
}


def generate(out_dir):
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = BINARY.read_bytes()
    image = al.Image(data)  # fails unless the SHA-256 is node #115
    specs = list(FUNCS)
    rows = al.fde_rows(image, {s[0] for s in specs} | {INSTALL})
    sweeps = {a: sweep(image, *rows[a]) for a in sorted(rows)}

    cases, classes, summary = [], {}, {"functions": {}}
    n_cases = 0
    controls, survivors, executed = [], [], {}

    for spec in specs:
        addr, kind, keylen, stride, val, got_slot, role = spec
        m = Mach(image)
        s = Stream(f"cases-{addr:x}")
        total = CASES_ENTRY if kind == "entry" else CASES_GET
        bad, steps = 0, 0
        muts = MAP_MUT[kind] + (["k3_plain"] if keylen == 32 else [])
        caught = {}
        for n in range(total):
            c = make_map_case(s, spec, n)
            res = run_map(image, spec, c, shared=m)
            ok = compare_map(spec, c, res)
            bad += not ok
            for mu in muts:
                if mu not in caught and not compare_map(spec, c, res, frozenset([mu])):
                    caught[mu] = n
            oc = map_outcome(spec, c, res)
            classes[(kind, keylen, stride, oc)] = classes.get((kind, keylen, stride, oc), 0) + 1
            steps += res.get("steps", 0)
            h = hash_key(c["key"], c["seed"], c["g"])
            cases.append((f"{addr:#x}", n, c["kind"], c["nb"], c["items"], c["growth"], f"{h:016x}", oc,
                          ";".join(f"{e[0]}" for e in res.get("ev", [])) or "-", res.get("steps", 0), int(ok)))
        n_cases += total
        for mu in muts:
            if mu in caught:
                controls.append((f"{addr:#x}", "model_mutant", mu, "detected", caught[mu]))
            else:
                survivors.append((f"{addr:#x}", "model_mutant", mu, "-", "-"))
        executed[addr] = set(m.seen)
        summary["functions"][f"{addr:#x}"] = {"cases": total, "mismatches": bad, "steps": steps}

    # the code-cache install
    m = Mach(image)
    s = Stream("cases-install")
    bad, steps, caught = 0, 0, {}
    for n in range(CASES_INSTALL):
        c = make_install_case(s, n, image)
        res = run_install(image, c, shared=m)
        ok = compare_install(image, c, res)
        bad += not ok
        for mu in INSTALL_MUT:
            if mu not in caught and not compare_install(image, c, res, frozenset([mu])):
                caught[mu] = n
        oc = install_outcome(c, res)
        classes[("install", 32, 40, oc)] = classes.get(("install", 32, 40, oc), 0) + 1
        steps += res.get("steps", 0)
        cases.append((f"{INSTALL:#x}", n, c["kind"], c["nb"], c["items"], c["growth"], c["key"][:8].hex(), oc,
                      ";".join(e[0] for e in res.get("ev", [])) or "-", res.get("steps", 0), int(ok)))
    n_cases += CASES_INSTALL
    for mu in INSTALL_MUT:
        if mu in caught:
            controls.append((f"{INSTALL:#x}", "model_mutant", mu, "detected", caught[mu]))
        else:
            survivors.append((f"{INSTALL:#x}", "model_mutant", mu, "-", "-"))
    executed[INSTALL] = set(m.seen)
    summary["functions"][f"{INSTALL:#x}"] = {"cases": CASES_INSTALL, "mismatches": bad, "steps": steps}

    # corrupted code bytes: every executed jcc inverted, every executed immediate / short displacement flipped
    for spec in specs + [None]:
        addr = INSTALL if spec is None else spec[0]
        lo, hi = rows[addr]
        for va, kind_, at, new in corruptions(image, lo, hi, executed[addr]):
            patch = (va, kind_, at, new)
            if spec is None:
                hit = detect_corruption_install(image, patch, INSTALL_CONTROL_CASES)
            else:
                hit = detect_corruption_map(image, spec, patch, CONTROL_CASES)
            if hit:
                controls.append((f"{addr:#x}", "corrupted_code", f"{kind_}@{va:#x}", "detected", f"{at:#x}"))
            else:
                survivors.append((f"{addr:#x}", kind_, f"{va:#x}", f"{at:#x}", f"{new:#04x}"))

    # input controls
    flipped = bytearray(data)
    flipped[len(flipped) // 2] ^= 1
    try:
        al.Image(bytes(flipped))
        controls.append(("-", "input", "flipped_binary_byte", "MISSED", "-"))
    except ToolError:
        controls.append(("-", "input", "flipped_binary_byte", "detected", "-"))
    try:
        image.code(0x10, 16)
        controls.append(("-", "input", "code_read_outside_text", "MISSED", "-"))
    except ToolError:
        controls.append(("-", "input", "code_read_outside_text", "detected", "-"))
    for name, spec, other in (("entry20_vs_entry32_model", FUNCS[0], FUNCS[7]), ("entry_stride_a8_vs_40", FUNCS[0], FUNCS[9]),
                              ("get_value_offset", FUNCS[10], FUNCS[16])):
        s = Stream(f"cases-{spec[0]:x}")
        m = Mach(image)
        wrong = (spec[0], spec[1], other[2], other[3], other[4], spec[5], spec[6])
        miss = 0
        for n in range(40):
            c = make_map_case(s, spec, n)
            res = run_map(image, spec, c, shared=m)
            if not compare_map(wrong, c, res):
                miss = 1
                break
        controls.append(("-", "input", name, "detected" if miss else "MISSED", "-"))

    n_ctl = len(controls)
    n_det = sum(1 for r in controls if r[3] == "detected")
    n_bad = sum(v["mismatches"] for v in summary["functions"].values())

    # ---- files
    dec = [("function", "address", "bytes", "executed")]
    for a in sorted(sweeps):
        for va, f in sweeps[a]:
            dec.append((f"{a:#x}", f"{va:#x}", f["bytes"].hex(), int(va in executed.get(a, set()))))
    (out / "decoded-instructions.tsv").write_text(tsv(dec))

    fr = [("address", "end", "bytes", "kind", "key_len", "stride", "value_offset", "reserve_slot", "reserve_target", "instructions",
           "executed", "body_sha256", "role")]
    for spec in specs:
        a = spec[0]
        lo, hi = rows[a]
        fr.append((f"{a:#x}", f"{hi:#x}", hi - lo, spec[1], spec[2], f"{spec[3]:#x}", f"{spec[4]:#x}",
                   f"{spec[5]:#x}" if spec[5] else "-", f"{image.word(spec[5]):#x}" if spec[5] else "-", len(sweeps[a]),
                   sum(1 for v in executed[a] if lo <= v < hi), hashlib.sha256(image.code(lo, hi - lo)).hexdigest(), spec[6]))
    lo, hi = rows[INSTALL]
    fr.append((f"{INSTALL:#x}", f"{hi:#x}", hi - lo, "install", 32, "0x28", "0x20", "0x64e6c98", f"{image.word(0x64e6c98):#x}",
               len(sweeps[INSTALL]), sum(1 for v in executed[INSTALL] if lo <= v < hi), hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
               "code-object install into the account (code-hash cache)"))
    (out / "functions.tsv").write_text(tsv(fr))

    cs = [("function", "site", "kind", "target_or_slot", "resolution", "contract")]
    for a in sorted(sweeps):
        for r in callee_rows(image, f"{a:#x}", *rows[a]):
            contract = ("real body evaluated" if r[3] == f"{PROBE_CODE:#x}" else
                        CONTRACTS["lazy"] if r[3] == f"{LAZY_INIT:#x}" else
                        CONTRACTS["loader"] if r[3] == f"{HASH_LOADER_GOT:#x}" else
                        CONTRACTS["drop"] if r[3] == f"{ARC_DROP_GOT:#x}" else
                        "unwind resume in a landing pad; never reached" if r[3] == "0x63f0a50" else CONTRACTS["reserve"])
            cs.append(r + (contract,))
    (out / "callee-sites.tsv").write_text(tsv(cs))

    ch = [("function", "case", "kind", "buckets", "items", "growth_left", "hash_or_key", "outcome", "callee_events", "steps",
           "match")] + cases
    (out / "cases.tsv").write_text(tsv(ch))
    oc_rows = [("family", "key_len", "stride", "outcome", "cases")] + [
        (k[0], k[1], f"{k[2]:#x}", k[3], v) for k, v in sorted(classes.items())]
    (out / "outcome-classes.tsv").write_text(tsv(oc_rows))
    (out / "negative-controls.tsv").write_text(tsv([("function", "control", "name", "result", "first_case_or_address")] + controls))
    (out / "survivors.tsv").write_text(tsv([("function", "kind", "instruction", "patched_address", "new_byte")] + survivors))
    consts = {
        "input_sha256": SHA256,
        "seed_got_slot": f"{SEED_GOT:#x}", "seed_got_target": f"{image.word(SEED_GOT):#x}",
        "empty_code_hash_low_16_at_0x4537f0": rod(image, ROD_HASH_LOW).hex(),
        "empty_code_hash_high_16_at_0x452020": rod(image, ROD_HASH_HIGH).hex(),
        "psub_constant_at_0x450790": rod(image, ROD_PSUB).hex(),
        "empty_code_cell_got": f"{ARC_CELL_GOT:#x}", "empty_code_cell_target": f"{image.word(ARC_CELL_GOT):#x}",
        "hash_loader_got_target": f"{image.word(HASH_LOADER_GOT):#x}", "arc_drop_got_target": f"{image.word(ARC_DROP_GOT):#x}",
        "extents": {f"{a:#x}": [f"{rows[a][0]:#x}", f"{rows[a][1]:#x}"] for a in sorted(rows)},
        "mutants": {"map": MAP_MUT, "install": INSTALL_MUT},
        "control_cases": {"map": CONTROL_CASES, "install": INSTALL_CONTROL_CASES},
    }
    (out / "constants.json").write_text(json.dumps(consts, indent=1, sort_keys=True) + "\n")
    summary.update({"cases": n_cases, "mismatches": n_bad, "negative_controls": n_ctl, "negative_detected": n_det,
                    "survivors": len(survivors),
                    "evaluated_instructions": sum(v["steps"] for v in summary["functions"].values())})
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": n_cases, "negative_controls": n_ctl, "negative_detected": n_det,
                                                  "mismatches": n_bad}, indent=1, sort_keys=True) + "\n")
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name not in ("MANIFEST.sha256", "README.md"))
    if (out / "README.md").exists():
        names.append("README.md")
    (out / "MANIFEST.sha256").write_text("".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names))
    print(f"cases {n_cases} mismatches {n_bad} controls {n_det}/{n_ctl} survivors {len(survivors)}")
    if n_bad or n_det != n_ctl:
        raise SystemExit(1)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    generate(args.out)


if __name__ == "__main__":
    main()
