#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM lazy code-object preparation bodies 0x54793e0 and 0x433c700.

Both bodies run on an EVM account record (rdi) with a host context (rsi -> pointer to the host).
They fill the cached code-object slot at account +0x70 once: a non-zero slot returns at once.
Otherwise the 32-byte code hash at account +0x48 is compared (two pcmpeqb against the 16-byte
constants at 0x4537f0 / 0x452020, the Keccak-256 of empty input) and the empty hash takes the shared
default path: the lazily initialised static behind GOT slot 0x64e6c78 (state dword +8, init 0x5b084ff
when non-zero), whose Arc strong count is incremented with `lock inc` (a result <= 0 without signed
overflow hits ud2).  Any other hash goes to a code map.  The hot body 0x54793e0 asks the map entry
function 0x4ef7e50 (host +0x40, evaluated as real machine code: hash, group probe, key compare, reserve call): an occupied entry clones the bucket Arc, a vacant one calls the loader
behind GOT slot 0x64e6458 with (host +0x90, hash), inserts a 40-byte bucket (32-byte key, Arc) at the
hashbrown insert slot (triangular 16-byte group probe, h2 = hash >> 57 in both control bytes, growth
left -= old control & 1, items += 1) and clones the new Arc.  The ordinary twin 0x433c700 calls the
tagged lookup 0x3d48830 on host +0x928: tag 5 with a non-zero Arc moves that Arc in without a count
change, tags below 2 (32-bit compare) fall to the default path, tag 2 calls the vtable drop of a
boxed error, tags above 2 deallocate (0x635de30) when the pointer is non-zero.  Both end by storing
the Arc at +0x70, first releasing a previous slot value with `lock dec` (drop-slow 0x5bde820 at zero).
The tool reads relocations, FDE extents and code bytes from the ELF file, evaluates the real machine
code with the concrete x86-64 evaluator of re11_transient_storage115 (extended for lock, signed
jcc), stubs the callees and compares every case with one pure-Python reconstruction.  The binary is
never executed.  Negative controls show wrong models and corrupted code are detected.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_transient_storage115 as base  # noqa: E402

ToolError, Image, Stream, fail = base.ToolError, base.Image, base.Stream, base.fail
BINARY, SHA256, M64 = base.BINARY, base.SHA256, base.M64

HOT, TWIN = 0x54793e0, 0x433c700
FUNCS = (HOT, TWIN, 0x4ef7e50)
ENTRY_A, MAKE_A, DROP_SLOW, LAZY_INIT = 0x4ef7e50, 0x43c8ec0, 0x5bde820, 0x5b084ff
SEED_GOT, SEED_AT, RESERVE_GOT, RESERVE = 0x64dfa78, 0x64ffe90, 0x64e6c98, 0x5be4680
LOOKUP_B, DEALLOC, LAZY_INIT_B = 0x3d48830, 0x635de30, 0x435059c
VDROP = 0x7c00_0000_f000
GOT_MAKE, GOT_LAZY, GOT_DROP, GOT_DEALLOC = 0x64e6458, 0x64e6c78, 0x64e4fa8, 0x64df4a0
LAZY_AT = 0x64fdfc0
EMPTY_HASH = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
CONST_LO, CONST_HI, CONST_STEP = 0x4537f0, 0x452020, 0x450790

ACC, CTXP, CTX, ARCS = 0x7d10_0000_0000, 0x7d10_0001_0000, 0x7d10_0002_0000, 0x7d10_0003_0000
BKT, TBLM, VT = 0x7d10_0004_0000, 0x7d10_0006_0000, 0x7d10_0007_0000
H_MAP_A, H_LOAD_A, H_MAP_B = 0x40, 0x90, 0x928
TBLH = CTX + H_MAP_A  # the code map header lives inside the host record
A_HASH, A_SLOT = 0x48, 0x70
DEFAULT, BUCKET_ARC, NEW, OLD = 0, 1, 2, 3
BUCKET = 40
SAVED = {r: 0x1357_0000_0000_0001 * (r + 1) & M64 for r in range(16)}
STK_RET = base.STACK_TOP - 0x100


# ---------------------------------------------------------------- decoder / evaluator extensions
_decode = base.decode


def decode(code, va):
    """base decoder plus the LOCK prefix (the lock byte is part of the instruction)."""
    if code[0] == 0xf0:
        form = _decode(code[1:], va + 1)
        form["len"] += 1
        form["bytes"] = bytes(code[:form["len"]])
        form["lock"] = True
        return form
    return _decode(code, va)


base.decode = decode


class Machine(base.TraceMachine):
    def cond(self, code, va):
        if code in (0xc, 0xd, 0xe, 0xf):
            of = getattr(self, "of", None)
            if of is None:
                fail(f"overflow flag read without a defining op at {va:#x}")
            lt = self.sf != of
            return {0xc: lt, 0xd: not lt, 0xe: self.zf or lt, 0xf: not (self.zf or lt)}[code]
        return super().cond(code, va)


# ---------------------------------------------------------------- reconstruction
def inc_traps(old):
    """`lock inc` then `jle ud2`: taken when the result is zero or negative without signed overflow."""
    new = (old + 1) & M64
    return new == 0 or (new >> 63 == 1 and old != 0x7fff_ffff_ffff_ffff)


def probe(ctrl, mask, hsh, mut):
    """hashbrown find_insert_slot over a control array that carries the 16-byte mirrored tail."""
    pos, stride = hsh & mask, 0
    while True:
        bits = [i for i in range(16) if ctrl[pos + i] & 0x80]
        if bits:
            idx = (pos + bits[0]) & mask
            break
        stride += 16
        pos = (pos + (16 if "probe_linear" in mut else stride)) & mask
    if ctrl[idx] & 0x80 == 0 and "jns_skip" not in mut:
        idx = next(i for i in range(16) if ctrl[i] & 0x80)
    return idx


def key_hash(key, secret, seed):
    """Folded two-multiply hash of the 32-byte code hash used by the code map entry function 0x4ef7e50."""
    k = [int.from_bytes(key[8 * i:8 * i + 8], "little") for i in range(4)]
    m = (k[1] ^ seed) * (k[0] ^ secret)
    x = ((m & M64) ^ (m >> 64)) ^ k[2]
    r = x * (seed ^ k[3])
    return (r & M64) ^ (r >> 64)


def set_ctrl(ctrl, mask, idx, v):
    ctrl[idx] = v
    ctrl[((idx - 16) & mask) + 16] = v


def entry_find(t, key, seed, mut=frozenset()):
    """Entry lookup: h2 byte matches in 16-byte groups with a full key compare, stop at a group with an EMPTY byte."""
    cap = t["cap"]
    mask = cap - 1
    h = key_hash(key, t["secret"], seed)
    h2 = h >> 57
    pos, stride = h & mask, 0
    while True:
        grp = t["ctrl"][pos:pos + 16]
        for i in range(16):
            if grp[i] == h2:
                idx = (pos + i) & mask
                p = cap * BUCKET - BUCKET * (idx + 1)
                if t["buckets"][p:p + 32] == key or "entry_match_loose" in mut:
                    return idx, h
        if 0xff in grp or ("entry_stop_deleted" in mut and 0x80 in grp):
            return None, h
        stride += 16
        pos = (pos + stride) & mask


def model_state(c):
    t = c.get("table")
    return {"acc70": c["acc70"], "counts": list(c["counts"]), "lazy": c["lazy_state"], "log": [],
            "table": None if t is None else {"cap": t["cap"], "ctrl": bytearray(t["ctrl"]),
                                              "buckets": bytearray(t["buckets"]), "growth": t["growth"],
                                              "items": t["items"], "secret": t["secret"]}}


def release_old(s, c, mut):
    """Store tail shared by both bodies: drop a previous slot value, then publish the Arc."""
    if s["acc70"]:
        slot = c["slot_of"][s["acc70"]]
        s["counts"][slot] = (s["counts"][slot] - 1) & M64
        if s["counts"][slot] == 0 and "no_drop_call" not in mut:
            s["log"].append(("drop", A_SLOT))


def default_path(s, c, mut):
    if s["lazy"] != 0:
        s["log"].append(("init",))
        s["lazy"] = 0
        if c["reent"] == "init":
            s["acc70"] = c["reent_ptr"]
    if "skip_default_inc" not in mut:
        old = s["counts"][DEFAULT]
        s["counts"][DEFAULT] = (old + 1) & M64
        if inc_traps(old) or ("overflow_traps" in mut and old == 0x7fff_ffff_ffff_ffff):
            return "ud2", None
    return None, DEFAULT


def model(c, mut=frozenset()):
    s = model_state(c)
    if s["acc70"] != 0:
        return finish(s, "ok")
    hsh = c["hash"]
    empty = hsh == EMPTY_HASH
    if "empty_low_only" in mut:
        empty = hsh[:16] == EMPTY_HASH[:16]
    addr = None
    if not empty:
        res = model_hot_lookup(s, c, mut) if c["func"] == HOT else model_twin_lookup(s, c, mut)
        if res == "ud2":
            return finish(s, "ud2")
        addr = res
    if addr is None:
        out, slot = default_path(s, c, mut)
        if out:
            return finish(s, out)
        addr = c["arc_addr"][slot]
    release_old(s, c, mut)
    s["acc70"] = addr
    return finish(s, "ok")


def model_hot_lookup(s, c, mut):
    t = s["table"]
    idx, h = entry_find(t, c["hash"], c["seed"], mut)
    cap = t["cap"]
    if idx is not None:
        arc = struct.unpack_from("<Q", t["buckets"], cap * BUCKET - BUCKET * (idx + 1) + 32)[0]
        slot = c["slot_of"][arc]
        old = s["counts"][slot]
        s["counts"][slot] = (old + 1) & M64
        return "ud2" if inc_traps(old) else arc
    if t["growth"] == 0:
        s["log"].append(("reserve", 0, 1, 0x20, 1))
        t["growth"] = 2
        if c["reent"] == "reserve":
            s["acc70"] = c["reent_ptr"]
    s["log"].append(("make", c["v90"], hsh_hex(c["hash"])))
    if c["reent"] == "make":
        s["acc70"] = c["reent_ptr"]
    mask = cap - 1
    idx = probe(t["ctrl"], mask, h, mut)
    h2 = (h >> (56 if "h2_shift_56" in mut else 57)) & 0xff
    oldctrl = t["ctrl"][idx]
    set_ctrl(t["ctrl"], mask, idx, h2)
    t["growth"] = (t["growth"] - ((oldctrl & 1) if "growth_always" not in mut else 1)) & M64
    t["items"] = (t["items"] + 1) & M64
    pos = cap * BUCKET - (BUCKET - 8 if "bucket_32" in mut else BUCKET) * (idx + 1)
    t["buckets"][pos:pos + 32] = c["hash"]
    t["buckets"][pos + 32:pos + 40] = struct.pack("<Q", c["arc_addr"][NEW])
    old = s["counts"][NEW]
    s["counts"][NEW] = (old + 1) & M64
    return "ud2" if inc_traps(old) else c["arc_addr"][NEW]


def model_twin_lookup(s, c, mut):
    """None = fall to the default path, an int = the Arc address to publish."""
    s["log"].append(("lookupB", H_MAP_B, hsh_hex(c["hash"])))
    if c["reent"] == "lookup":
        s["acc70"] = c["reent_ptr"]
    tag, p1, p2 = c["tag"], c["p1"], c["p2"]
    low = tag & 0xffffffff
    if tag == 5:
        if p1 == 0:
            return None
        if "tag5_inc" in mut:
            slot = c["slot_of"][p1]
            old = s["counts"][slot]
            s["counts"][slot] = (old + 1) & M64
        return p1
    if (tag if "tag_cmp_64" in mut else low) < 2:
        return None
    if low == 2:
        s["log"].append(("vdrop", p1 - VT))
        return None
    if p1 == 0:
        return None
    s["log"].append(("dealloc", p2, p1, 0))
    return None


def hsh_hex(h):
    return h.hex()


def finish(s, outcome):
    t = s["table"]
    tab = None if t is None else (bytes(t["ctrl"]), bytes(t["buckets"]), t["growth"], t["items"])
    return (outcome, s["acc70"], tuple(s["counts"]), s["lazy"], tab, tuple(s["log"]), True if outcome == "ok" else None)


# ---------------------------------------------------------------- fixture + evaluation
def table_layout(cap):
    return (cap * BUCKET + 15) & ~15


def build_table(s, c, cap, occupied, decoys, tombs, growth_mode, blocked=False):
    """A code map in which every resident key sits where hashbrown would have put it for the case's secret and seed."""
    mask = cap - 1
    secret, seed = c["secret"], c["seed"]
    ctrl = bytearray(b"\xff" * (cap + 16))
    buckets = bytearray(s.take(cap * BUCKET))
    key = c["hash"]
    hk = key_hash(key, secret, seed)

    def put(idx, k, h2, arc):
        set_ctrl(ctrl, mask, idx, h2)
        pos = cap * BUCKET - BUCKET * (idx + 1)
        buckets[pos:pos + 32] = k
        buckets[pos + 32:pos + 40] = struct.pack("<Q", ARCS + 0x40 * arc)

    room = cap - 1
    items = 0
    if blocked:
        for i in range(16):
            put((hk + i) & mask, s.take(32), s.below(0x7f) | (1 if hk >> 57 == 0x7f else 0), 4 + s.below(4))
        room -= 16
        items = 16
    n_dec = min(decoys, max(room, 0))
    for _ in range(n_dec):  # same h2 and probe path as the key, different key bytes
        w = bytearray(key)
        w[s.below(32)] ^= 1 << s.below(8)
        put(probe(ctrl, mask, hk, frozenset()), bytes(w), hk >> 57, 4 + s.below(4))
    room -= n_dec
    items += n_dec
    if occupied and room > 0:
        put(probe(ctrl, mask, hk, frozenset()), key, hk >> 57, BUCKET_ARC)
        room -= 1
        items += 1
    dense = s.below(2)
    for _ in range(max(room - s.below(4), 0) if dense else s.below(room + 1)):
        k = s.take(32)
        put(probe(ctrl, mask, key_hash(k, secret, seed), frozenset()), k, key_hash(k, secret, seed) >> 57, 4 + s.below(4))
        items += 1
    dead = 0
    for _ in range(tombs):
        full = [i for i in range(cap) if ctrl[i] < 0x80 and ctrl[i] != hk >> 57]
        if full:
            set_ctrl(ctrl, mask, full[s.below(len(full))], 0x80)
            dead += 1
    items -= dead
    tombs = dead
    capacity = cap * 7 // 8 if cap >= 8 else cap - 1
    growth = {"exact": max(capacity - items - tombs, 0), "zero": 0, "one": 1}[growth_mode]
    return {"cap": cap, "ctrl": bytes(ctrl), "buckets": bytes(buckets), "growth": growth, "items": items,
            "secret": secret}


COUNTS = [1, 2, 7, 0x7fff_ffff_ffff_fffe, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, M64 - 1, M64, 0]
LAZY_STATES = [0, 0, 1, 2, 0xffff_ffff]


def make_case(s, func, kind):
    c = {"func": func, "kind": kind, "acc70": 0, "hash": s.take(32), "entry": None, "reent": None, "reent_ptr": 0,
         "lazy_state": s.pick(LAZY_STATES), "counts": [s.pick(COUNTS) if s.below(4) == 0 else 1 + s.below(9)
                                                        for _ in range(8)],
         "table": None, "v90": s.below(1 << 63), "ctx_fill": s.take(8),
         "secret": s.below(1 << 64), "seed": s.below(1 << 64)}
    c["arc_addr"] = {k: ARCS + 0x40 * k for k in range(8)}
    c["slot_of"] = {ARCS + 0x40 * k: k for k in range(8)}
    if s.below(3) == 0:
        c["counts"][DEFAULT] = s.pick(COUNTS)
    if kind == "preset":
        c["acc70"] = ARCS + 0x40 * s.below(8)
        if s.below(2):
            c["hash"] = EMPTY_HASH
    elif kind == "default":
        c["hash"] = EMPTY_HASH
    elif kind == "halfhash":
        w = bytearray(EMPTY_HASH)
        w[s.below(16) + (16 if s.below(2) else 0)] ^= 1 << s.below(8)
        c["hash"] = bytes(w)
    if c["acc70"] == 0 and s.below(3) == 0:
        c["reent"] = s.pick(["init", "make", "reserve"] if func == HOT else ["init", "lookup"])
        c["reent_ptr"] = ARCS + 0x40 * OLD
        c["counts"][OLD] = s.pick([1, 1, 2, 3, 0, M64, 0x8000_0000_0000_0000])
    if func == HOT:
        c["entry"] = "occupied" if s.below(2) == 0 else "vacant"
        cap = s.pick([4, 8, 16, 16, 32, 64])
        c["table"] = build_table(s, c, cap, c["entry"] == "occupied", s.pick([0, 0, 1, 2]), s.pick([0, 0, 1, 3, 6]),
                                 s.pick(["exact", "exact", "zero", "one"]), cap >= 32 and s.below(3) == 0)
        if c["entry"] == "vacant" and s.below(2):  # make the insert slot start after the only spare slot of a small table
            pass
    else:
        c["tag"] = s.pick([0, 1, 2, 3, 4, 5, 5, 5, 6, 7, 0x1_0000_0000, 0x1_0000_0002, 0x1_0000_0005,
                           0x2_0000_0003, 0xffff_ffff_ffff_ffff, 0x1_0000_0000 | s.below(8)])
        c["p1"] = ARCS + 0x40 * s.below(8) if c["tag"] == 5 else VT
        if s.below(4) == 0 and c["tag"] & 0xffffffff != 2:
            c["p1"] = 0
        c["p2"] = s.below(1 << 64)
    return c


def case_stream():
    s = Stream("re11-code-object-prep-115")
    plan = [(HOT, "preset", 160), (HOT, "default", 1200), (HOT, "halfhash", 400), (HOT, "lookup", 4200),
            (TWIN, "preset", 160), (TWIN, "default", 900), (TWIN, "halfhash", 400), (TWIN, "lookup", 4400)]
    for func, kind, n in plan:
        for _ in range(n):
            c = make_case(s, func, kind)
            if func == TWIN and c["hash"] != EMPTY_HASH and c["acc70"] == 0 and "tag" in c:
                if c["tag"] == 5 and c["p1"]:
                    c["given_slot"] = c["p1"]
            yield c


def build_machine(image, override=None):
    m = Machine(image, override)
    return m


def install(m, c):
    m.reset()
    m.case = c
    acc = m.add_region(ACC, 0x100)
    acc[A_HASH:A_HASH + 32] = c["hash"]
    struct.pack_into("<Q", acc, A_SLOT, c["acc70"])
    m.acc = acc
    m.add_region(CTXP, 0x10, struct.pack("<Q", CTX))
    ctx = m.add_region(CTX, 0x1000)
    ctx[:8] = c["ctx_fill"]
    struct.pack_into("<Q", ctx, H_LOAD_A, c["v90"])
    m.arcs = m.add_region(ARCS, 0x400)
    for k in range(8):
        struct.pack_into("<Q", m.arcs, 0x40 * k, c["counts"][k])
    lazy = m.add_region(LAZY_AT, 0x40)
    struct.pack_into("<Q", lazy, 0, ARCS + 0x40 * DEFAULT)
    struct.pack_into("<I", lazy, 8, c["lazy_state"])
    m.lazy = lazy
    m.add_region(BKT, 0x40, b"\0" * 0x20 + struct.pack("<Q", ARCS + 0x40 * BUCKET_ARC))
    m.add_region(VT, 0x40, struct.pack("<QQ", VT + 0x10, VDROP) + struct.pack("<Q", VDROP))
    seed = m.add_region(SEED_AT, 0x10)
    struct.pack_into("<Q", seed, 0, c["seed"])
    m.tbl = None
    t = c["table"]
    if t is not None:
        cap = t["cap"]
        lay = table_layout(cap)
        ctrl_at = TBLM + lay
        m.tbl = (ctx, m.add_region(TBLM, lay + cap + 16 + 16), TBLM, ctrl_at)
        hdr, mem = m.tbl[0], m.tbl[1]
        struct.pack_into("<QQQQQ", hdr, H_MAP_A, ctrl_at, cap - 1, t["growth"], t["items"], t["secret"])
        mem[lay:lay + cap + 16] = t["ctrl"]
        mem[lay - cap * BUCKET:lay] = t["buckets"]
    m.log = []
    m.stubs = {RESERVE: stub_reserve, MAKE_A: stub_make, DROP_SLOW: stub_drop, LAZY_INIT: stub_init,
               LOOKUP_B: stub_lookup_b, LAZY_INIT_B: stub_init, DEALLOC: stub_dealloc, VDROP: stub_vdrop}


def key_at(m, at):
    return b"".join(m.load(at + 8 * i, 8).to_bytes(8, "little") for i in range(4)).hex()


def reenter(m, when):
    c = m.case
    if c["reent"] == when:
        m.store(ACC + A_SLOT, 8, c["reent_ptr"])


def stub_reserve(m):
    m.log.append(("reserve", m.regs[7] - TBLH, m.regs[6] & 0xffffffff, m.regs[2] - TBLH, m.regs[1] & 0xffffffff))
    m.store(TBLH + 0x10, 8, 2)
    reenter(m, "reserve")


def stub_make(m):
    m.log.append(("make", m.regs[7], key_at(m, m.regs[6])))
    reenter(m, "make")
    m.regs[0] = ARCS + 0x40 * NEW


def stub_drop(m):
    m.log.append(("drop", m.regs[7] - ACC))


def stub_init(m):
    m.log.append(("init",))
    m.store(LAZY_AT + 8, 4, 0)
    reenter(m, "init")


def stub_lookup_b(m):
    c, out = m.case, m.regs[7]
    m.log.append(("lookupB", m.regs[6] - CTX, key_at(m, m.regs[2])))
    reenter(m, "lookup")
    m.store(out, 8, c["tag"])
    m.store(out + 8, 8, c["p1"])
    m.store(out + 0x10, 8, c["p2"])


def stub_dealloc(m):
    m.log.append(("dealloc", m.regs[7], m.regs[6], m.regs[2] & 0xffffffff))


def stub_vdrop(m):
    m.log.append(("vdrop", m.regs[7] - VT))


def snapshot(m, outcome):
    c = m.case
    acc70 = struct.unpack_from("<Q", m.acc, A_SLOT)[0]
    counts = tuple(struct.unpack_from("<Q", m.arcs, 0x40 * k)[0] for k in range(8))
    lazy = struct.unpack_from("<I", m.lazy, 8)[0]
    tab = None
    if m.tbl:
        hdr, mem, base_at, ctrl_at = m.tbl
        cap = c["table"]["cap"]
        lay = table_layout(cap)
        tab = (bytes(mem[lay:lay + cap + 16]), bytes(mem[lay - cap * BUCKET:lay]),
               struct.unpack_from("<Q", hdr, H_MAP_A + 0x10)[0], struct.unpack_from("<Q", hdr, H_MAP_A + 0x18)[0])
    saved = all(m.regs[r] == SAVED[r] for r in (3, 5, 12, 13, 14, 15)) and m.regs[4] == STK_RET
    return (outcome, acc70, counts, lazy, tab, tuple(m.log), saved if outcome == "ok" else None)


def run_case(m, c):
    install(m, c)
    m.regs[7], m.regs[6] = ACC, CTXP
    for r in (3, 5, 12, 13, 14, 15):
        m.regs[r] = SAVED[r]
    try:
        m.run(c["func"])
        outcome = "ok"
    except ToolError as exc:
        if "ud2" not in str(exc):
            return ("error:" + str(exc),)
        outcome = "ud2"
    return snapshot(m, outcome)


def evaluate(image, override=None, mut=frozenset(), stop_on_first=False, machine=None, cases=None, step=1):
    m = machine or build_machine(image, override)
    bad = n = 0
    for i, c in enumerate(cases if cases is not None else case_stream()):
        if i % step:
            continue
        want = model(c, mut)
        try:
            got = run_case(m, c)
        except ToolError as exc:
            got = ("error:" + str(exc),)
        n += 1
        if want != got:
            bad += 1
            if stop_on_first:
                break
    return n, bad, m


def static_evidence(image):
    _, fdes = base.fde_extents.eh_frame_records(image.data, image.secs)
    rows = {f["start"]: f["end"] for f in fdes if f["start"] in FUNCS}
    for f in FUNCS:
        if f not in rows:
            fail(f"no FDE starts at {f:#x}")
    decoded, funcs, calls = {}, {}, {}
    for f in FUNCS:
        lo, hi = f, rows[f]
        decoded[f] = []
        va = lo
        while va < hi:
            form = decode(image.code(va, 16), va)
            decoded[f].append((va, form))
            va += form["len"]
        if va != hi:
            fail(f"linear decode overruns {hi:#x}")
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                            "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": len(decoded[f])}
        calls[f"{f:#x}"] = {f"{va:#x}": (f"{fm['target']:#x}" if "target" in fm else f"[{fm['bytes'].hex()}]")
                            for va, fm in decoded[f] if fm["op"] == 0xe8 or (fm["op"] == 0xff and fm["reg"] & 7 == 2)}
    got = {s: f"{image.word(s):#x}" for s in (GOT_MAKE, GOT_LAZY, GOT_DROP, GOT_DEALLOC)}
    want = {GOT_MAKE: MAKE_A, GOT_LAZY: LAZY_AT, GOT_DROP: DROP_SLOW, GOT_DEALLOC: DEALLOC}
    for s, v in want.items():
        if image.word(s) != v:
            fail(f"GOT slot {s:#x} changed")
    consts = {f"{a:#x}": image.read(a, 16).hex() for a in (CONST_LO, CONST_HI, CONST_STEP)}
    if image.read(CONST_LO, 16) + image.read(CONST_HI, 16) != EMPTY_HASH:
        fail("empty-hash constants changed")
    return {"binary_sha256": SHA256, "functions": funcs, "direct_calls": calls,
            "got_slots": {f"{k:#x}": v for k, v in sorted(got.items())}, "constants": consts,
            "empty_code_hash": EMPTY_HASH.hex(),
            "offsets": {"account_code_hash": A_HASH, "account_code_slot": A_SLOT, "hot_map": H_MAP_A,
                        "hot_loader_arg": H_LOAD_A, "twin_map": H_MAP_B, "bucket_bytes": BUCKET}}, decoded


MODEL_MUTANTS = ["empty_low_only", "entry_match_loose", "entry_stop_deleted", "skip_default_inc", "overflow_traps", "no_drop_call", "h2_shift_56",
                 "growth_always", "bucket_32", "probe_linear", "jns_skip", "tag_cmp_64", "tag5_inc"]
JCC = set(range(0x70, 0x80)) | set(range(0x0f80, 0x0f90))


def jcc_mutants(decoded):
    out = []
    for f, rows in sorted(decoded.items()):
        for va, fm in rows:
            if fm["op"] in JCC:
                pos = va + (1 if fm["op"] > 0xff else 0)
                out.append((f, va, pos, fm["bytes"][pos - va] ^ 1))
    return out


def controls(image, decoded, cases):
    rows = []
    for name in MODEL_MUTANTS:
        n, bad, _ = evaluate(image, mut=frozenset([name]), stop_on_first=True, cases=cases)
        rows.append(("model", name, int(bad > 0)))
    dead = []
    for f, va, pos, byte in jcc_mutants(decoded):
        n, bad, _ = evaluate(image, override={pos: byte}, stop_on_first=True, cases=cases)
        if bad:
            rows.append(("code", f"{f:#x} jcc at {va:#x} inverted", 1))
        else:
            dead.append((f, va))
    corrupt = bytearray(image.data)
    corrupt[image.text["offset"] + 7] ^= 1
    try:
        Image(bytes(corrupt))
        rows.append(("input", "one flipped .text byte", 0))
    except ToolError:
        rows.append(("input", "one flipped .text byte", 1))
    try:
        image.code(image.text["address"] + image.text["size"] + 0x100, 4)
        rows.append(("input", "address past .text", 0))
    except ToolError:
        rows.append(("input", "address past .text", 1))
    return rows, dead


def digest(obj):
    return hashlib.sha256(repr(obj).encode()).hexdigest()[:10]


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    consts, decoded = static_evidence(image)
    m = build_machine(image)
    lines = ["case\tbody\tkind\tinput\toutcome\tacc70\tlog\tdigest\tmatch"]
    bad = n = 0
    classes = {}
    sample = []
    for i, c in enumerate(case_stream()):
        want = model(c)
        try:
            got = run_case(m, c)
        except ToolError as exc:
            got = ("error:" + str(exc),)
        ok = want == got
        bad += not ok
        n += 1
        if i % 3 == 0:
            sample.append(c)
        oc = got[0]
        if c["func"] == HOT:
            what = c["entry"] if c["hash"] != EMPTY_HASH else "empty-hash"
        else:
            what = "empty-hash" if c["hash"] == EMPTY_HASH else f"tag={c['tag']:#x}"
        if c["acc70"]:
            what = "slot-set"
        key = f"{c['func']:#x}/{c['kind']}/{what}/{oc}"
        classes[key] = classes.get(key, 0) + 1
        inp = (f"hash={c['hash'][:4].hex()},lazy={c['lazy_state']:#x},reent={c['reent']},"
               f"cnt={','.join(f'{x:#x}' for x in c['counts'][:4])}")
        if c.get("table"):
            inp += (f",cap={c['table']['cap']},items={c['table']['items']},growth={c['table']['growth']},"
                    f"secret={c['secret']:#x}")
        if c["func"] == TWIN:
            inp += f",p1={c['p1']:#x}"
        lg = "|".join(e[0] for e in want[5]) if len(want) > 5 else "-"
        lines.append(f"{i}\t{c['func']:#x}\t{c['kind']}\t{inp}\t{oc}\t{(got[1] if len(got) > 1 else 0):#x}\t{lg}\t{digest(got)}\t{'yes' if ok else 'NO'}")
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "outcome-classes.tsv").write_text("class\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    seen = m.seen
    rows = ["function\taddress\tlength\tbytes\topcode\texecuted"]
    covered = {}
    for f, insns in sorted(decoded.items()):
        hit = sum(1 for va, _ in insns if va in seen)
        covered[f"{f:#x}"] = [hit, len(insns)]
        for va, fm in insns:
            rows.append(f"{f:#x}\t{va:#x}\t{fm['len']}\t{fm['bytes'].hex()}\t{fm['op']:#x}\t{int(va in seen)}")
    (out / "decoded-instructions.tsv").write_text("\n".join(rows) + "\n")
    ctl, dead = controls(image, decoded, sample)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "undetected-code-mutants.tsv").write_text(
        "function\tjcc_address\n" + "".join(f"{f:#x}\t{va:#x}\n" for f, va in dead))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    det = sum(r[2] for r in ctl)
    summary = {"binary_sha256": SHA256, "cases": n, "mismatches": bad, "covered_instructions": covered,
               "negative_controls": {"total": len(ctl), "detected": det}, "undetected_jcc_mutants": len(dead)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": n, "negative_controls": len(ctl), "negative_detected": det},
                                                 indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    bad = summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
