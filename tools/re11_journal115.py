#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM journal checkpoint revert 0x29710e0 and the account-slot journal write 0x29712c0 (three copies of the revert, one write body).

The EVM journaled state (the `evm` host object, one per execution) keeps a log vector (+0x8 pointer, +0x10 length, 0x50-byte
entries), a journal vector (+0x18 capacity, +0x20 pointer, +0x28 length, 0x58-byte entries whose first byte is the entry tag),
a minimum-length watermark at +0x40, the call depth at +0x118 and the spec byte at +0x126.  The revert body takes a
checkpoint (log length, journal length, watermark) and (1) saturating-decrements the depth, (2) when the checkpoint log
length does not exceed the current one, drops every log above it (a heap free of capacity*32 bytes when the capacity is
non-zero, then the owned-bytes drop through vtable slot +0x20) and cuts the log vector, (3) lowers the watermark to the
checkpoint value when that is not larger, (4) when the checkpoint journal length is below the current one, cuts the journal
to it and replays the removed entries newest first through the applier behind a GOT slot, passing (entry copy, state maps at
+0xc8 and +0xf0, spec >= 3), stopping early at the first entry whose tag is 0xc.  The write body looks up a 20-byte key in
the hashbrown map at +0xc8 (0xa8-byte buckets, mask +0xd0, items +0xe0, secret +0xe8, process seed behind a GOT slot),
panics through the panic helper when the map is empty or the key is absent, journals a tag-2 entry (first touch of the
bucket, flag bit 4) and a tag-0xb entry (growing the journal vector through a GOT helper when full), replaces the 32-byte
value and the owned reference word, and frees the old reference through the slow-path helper when its count reaches zero.
The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real machine code with the
concrete x86-64 evaluator of tools/re11_transient_storage115.py (no external programs, the binary is never executed) and
compares every case with one pure-Python reconstruction.  Negative controls show that wrong reconstructions and corrupted
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
import re11_transient_storage115 as T  # noqa: E402
from re11_transient_storage115 import (Boundary, Image, Stream, ToolError, TraceMachine, addr_hash, decode, fail,  # noqa: E402
                                       fde_rows, put, sweep_padded, u)

BINARY, SHA256, M64 = T.BINARY, T.SHA256, T.M64

REVERT = (0x29710e0, 0x4322f30, 0x5463410)
WRITE = (0x29712c0,)
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
SAVED_REGS = (3, 12, 13, 14, 15, 5)

JS_AT, JS_SIZE = 0x7d10_0000_0000, 0x200
LOG_AT, JN_AT, CK_AT, VT_AT = 0x7d10_0100_0000, 0x7d10_0200_0000, 0x7d10_0300_0000, 0x7d10_0400_0000
KEY_AT, VAL_AT, TAB_AT, SEED_AT = 0x7d10_0500_0000, 0x7d10_0600_0000, 0x7d10_0700_0000, 0x7d10_0800_0000
FAKE = 0x7c10_0000_0000  # synthetic stub targets, one per boundary
STUB_APPLY, STUB_DEALLOC, STUB_DROP, STUB_GROW, STUB_SLOW, STUB_PANIC = (FAKE + 16 * i for i in range(1, 7))
J_LOGS, J_NLOGS, J_JCAP, J_JPTR, J_JLEN, J_WATER, J_DEPTH, J_SPEC = 0x08, 0x10, 0x18, 0x20, 0x28, 0x40, 0x118, 0x126
J_MAP, J_MASK, J_ITEMS, J_SECRET = 0xc8, 0xd0, 0xe0, 0xe8
J_MAP2 = 0xf0
ENTRY, LOGENT, BUCKET = 0x58, 0x50, 0xa8
JS_FILL = 0xa7
STACK_FILL = 0x5c
GROW_STEP = 16
# call-site offsets inside the revert body (identical in all three copies; only the two GOT displacements differ)
REV_SITES = {"applier_load": 0xb5, "dealloc_load": 0x14b}
WR_SITES = {"seed_load": 0x2c, "grow_a": 0x13b, "grow_b": 0x178, "slow_call": 0x1cd, "panic_lea": 0x1e6, "panic_call": 0x1ed}
LOCK_AT = 0x1c4  # `lock` prefix of the reference decrement inside the write body: replaced by a nop (single thread)


# ---------------------------------------------------------------- static decode of the call-site roles
def rip_slot(image, base, off, opc_len):
    """Slot VA referenced by the rip-relative instruction at base+off whose displacement follows opc_len bytes."""
    code = image.code(base + off, opc_len + 4)
    disp = struct.unpack_from("<i", code, opc_len)[0]
    return (base + off + opc_len + 4 + disp) & M64


def revert_slots(image, base):
    a = image.code(base + REV_SITES["applier_load"], 3)
    d = image.code(base + REV_SITES["dealloc_load"], 3)
    if a != bytes.fromhex("488b1d") or d != bytes.fromhex("4c8b2d"):
        fail(f"revert call-site opcodes changed at {base:#x}")
    return rip_slot(image, base, REV_SITES["applier_load"], 3), rip_slot(image, base, REV_SITES["dealloc_load"], 3)


def write_slots(image, base):
    code = image.code
    if code(base + WR_SITES["seed_load"], 3) != bytes.fromhex("488b05"):
        fail(f"write seed load changed at {base:#x}")
    for k in ("grow_a", "grow_b", "slow_call", "panic_call"):
        if code(base + WR_SITES[k], 2) != bytes.fromhex("ff15"):
            fail(f"write call site {k} changed at {base:#x}")
    if code(base + WR_SITES["panic_lea"], 3) != bytes.fromhex("488d3d"):
        fail(f"write panic lea changed at {base:#x}")
    s = {"seed": rip_slot(image, base, WR_SITES["seed_load"], 3),
         "grow_a": rip_slot(image, base, WR_SITES["grow_a"], 2), "grow_b": rip_slot(image, base, WR_SITES["grow_b"], 2),
         "slow": rip_slot(image, base, WR_SITES["slow_call"], 2), "panic": rip_slot(image, base, WR_SITES["panic_call"], 2),
         "msg": rip_slot(image, base, WR_SITES["panic_lea"], 3)}
    if s["grow_a"] != s["grow_b"]:
        fail("the two journal grow sites use different slots")
    return s


# ---------------------------------------------------------------- reconstruction: revert
def log_view(c):
    return [(l["cap"], l["ptr"], l["data"], l["len"]) for l in c["logs"]]


def model_revert(c, mut=frozenset()):
    """Return (events, final js dict).  Events are in call order."""
    ev = []
    depth = c["depth"]
    if "depth_wrap" in mut:
        depth = (depth - 1) & M64
    elif "depth_keep" in mut:
        pass
    elif "depth_floor1" in mut:
        depth = depth - 1 if depth > 1 else depth
    else:
        depth = 0 if depth == 0 else depth - 1
    nlogs, jlen, water = c["nlogs"], c["jlen"], c["water"]
    ck_log, ck_j, ck_w = c["ck"]
    cmp_ok = ck_log <= nlogs
    if cmp_ok:
        for i in range(ck_log, nlogs):
            cap, ptr, data, ln = log_view(c)[i]
            if "skip_dealloc" not in mut and cap != 0:
                ev.append(("dealloc", ptr, (cap << (4 if "dealloc_cap16" in mut else 5)) & M64, 0))
            ev.append(("drop", i, data, ln))
        if "drop_first" in mut:
            ev.sort(key=lambda e: e[0] != "drop")
        if "log_len_keep" not in mut:
            nlogs = ck_log
    if "water_max" in mut:
        lower = ck_w >= water
    elif "water_always" in mut:
        lower = True
    else:
        lower = ck_w <= water
    if lower:
        water = ck_w
    spec = 1 if c["spec"] >= (4 if "spec_ge4" in mut else 3) else 0
    if "spec_ge2" in mut:
        spec = 1 if c["spec"] >= 2 else 0
    j_do = ck_j < jlen
    if j_do:
        old = jlen
        if "journal_len_keep" not in mut:
            jlen = ck_j
        idxs = range(old - 1, ck_j - 1, -1)
        if "journal_forward" in mut:
            idxs = range(ck_j, old)
        if "journal_extra" in mut:
            idxs = range(old - 1, ck_j - 2, -1) if ck_j > 0 else idxs
        for i in idxs:
            tag = c["journal"][i][0]
            if tag == 0xc and "sentinel_ignore" not in mut:
                if "sentinel_skip" in mut:
                    continue
                if "sentinel_after" in mut:
                    ev.append(("apply", tag, c["journal"][i][1:].hex(), J_MAP, J_MAP2, spec))
                break
            if "args_swapped" in mut:
                ev.append(("apply", tag, c["journal"][i][1:].hex(), J_MAP2, J_MAP, spec))
            else:
                ev.append(("apply", tag, c["journal"][i][1:].hex(), J_MAP, J_MAP2, spec))
    return ev, {"nlogs": nlogs, "jlen": jlen, "water": water, "depth": depth}


def build_revert(c):
    js = bytearray([JS_FILL]) * JS_SIZE
    put(js, J_LOGS, 8, LOG_AT)
    put(js, J_NLOGS, 8, c["nlogs"])
    put(js, J_JCAP, 8, c["jcap"])
    put(js, J_JPTR, 8, JN_AT)
    put(js, J_JLEN, 8, c["jlen"])
    put(js, J_WATER, 8, c["water"])
    put(js, J_DEPTH, 8, c["depth"])
    js[J_SPEC] = c["spec"]
    logs = bytearray()
    for l in c["logs"]:
        e = bytearray(l["fill"])
        put(e, 0, 8, l["cap"])
        put(e, 8, 8, l["ptr"])
        put(e, 0x18, 8, VT_AT)
        put(e, 0x20, 8, l["data"])
        put(e, 0x28, 8, l["len"])
        logs += e
    jn = b"".join(c["journal"])
    ck = bytearray(0x18)
    for i, v in enumerate(c["ck"]):
        put(ck, 8 * i, 8, v)
    vt = bytearray([0x6d]) * 0x40
    put(vt, 0x20, 8, STUB_DROP)
    return js, bytes(logs) or b"\0", jn or b"\0", bytes(ck), bytes(vt)


def run_revert(m, c, base, slots):
    m.reset()
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    js, logs, jn, ck, vt = build_revert(c)
    jsb = m.add_region(JS_AT, JS_SIZE, bytes(js))
    m.add_region(LOG_AT, len(logs), logs)
    m.add_region(JN_AT, max(len(jn), 8), jn)
    m.add_region(CK_AT, 0x18, ck)
    m.add_region(VT_AT, 0x40, vt)
    ev = []
    clobber = (0, 1, 2, 6, 7, 8, 9, 10, 11)

    def apply(mc):
        ent = bytes(mc.load(mc.regs[7] + i, 1) for i in range(ENTRY))
        ev.append(("apply", ent[0], ent[1:].hex(), mc.regs[6] - JS_AT, mc.regs[2] - JS_AT, mc.regs[1] & 0xff))
        for r in clobber:
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1

    def dealloc(mc):
        ev.append(("dealloc", mc.regs[7], mc.regs[6], mc.regs[2] & 0xffffffff))
        for r in clobber:
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1

    def drop(mc):
        i = (mc.regs[7] - 0x30 - LOG_AT) // LOGENT
        ev.append(("drop", i, mc.regs[6], mc.regs[2]))
        for r in clobber:
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1

    m.words[slots[0]], m.words[slots[1]] = STUB_APPLY, STUB_DEALLOC
    m.stubs = {STUB_APPLY: apply, STUB_DEALLOC: dealloc, STUB_DROP: drop}
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = JS_AT, CK_AT
    return ev, jsb


def check_revert(m, c, ev, jsb, want_ev, want_js):
    ok = ev == want_ev
    now = {lo: bytes(buf) for lo, hi, buf in m.regions if lo != T.STACK_TOP - 0x10000}
    expect = bytearray(build_revert(c)[0])
    put(expect, J_NLOGS, 8, want_js["nlogs"])
    put(expect, J_JLEN, 8, want_js["jlen"])
    put(expect, J_WATER, 8, want_js["water"])
    put(expect, J_DEPTH, 8, want_js["depth"])
    ok = ok and now[JS_AT] == bytes(expect)
    js, logs, jn, ck, vt = build_revert(c)
    ok = ok and now[LOG_AT] == logs and now[CK_AT] == ck and now[VT_AT] == vt and now[JN_AT][:len(jn)] == jn
    ok = ok and [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == T.STACK_TOP - 0x100
    return ok


# ---------------------------------------------------------------- cases: revert
TAGS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0xd, 0x80, 0xff]
CAPS = [0, 0, 0, 1, 2, 7, 1 << 59, 1 << 63, M64]


def rev_case(s, idx):
    nlogs = s.below(5)
    jlen = s.below(7)
    kind = s.below(8)
    ck_log = s.pick([0, nlogs, nlogs, max(nlogs - 1, 0), nlogs + 1, nlogs + 3, s.below(nlogs + 2)])
    ck_j = s.pick([0, jlen, jlen, max(jlen - 1, 0), jlen + 1, jlen + 5, s.below(jlen + 2)])
    water = s.pick([0, 5, M64, s.below(1 << 20), 1 << 63])
    ck_w = s.pick([water, water, water + 1 & M64, max(water - 1, 0), 0, M64, s.below(1 << 20)])
    journal = []
    sentinel = s.below(jlen) if jlen and kind < 3 else -1
    for i in range(jlen):
        e = bytearray(s.take(ENTRY))
        e[0] = 0xc if i == sentinel else s.pick(TAGS)
        if e[0] == 0xc and i != sentinel:
            e[0] = 3
        journal.append(bytes(e))
    logs = []
    for i in range(nlogs):
        logs.append({"cap": s.pick(CAPS), "ptr": int.from_bytes(s.take(8), "little") & 0xffff_ffff_fff0,
                     "data": int.from_bytes(s.take(8), "little"), "len": int.from_bytes(s.take(8), "little") & 0xffffff,
                     "fill": s.take(LOGENT)})
    return {"fn": "revert", "idx": idx, "nlogs": nlogs, "jlen": jlen, "jcap": jlen + s.below(3),
            "ck": (ck_log, ck_j, ck_w), "water": water, "depth": s.pick([0, 1, 2, 3, 9, 1 << 63, M64, s.below(100)]),
            "spec": s.pick([0, 1, 2, 3, 4, 0x0b, 0xe, 0xff, s.below(256)]), "logs": logs, "journal": journal}


REV_CASES = 3600


def eval_revert(image, base, cases, override=None, mut=frozenset(), machine=None, stop=False):
    m = machine or TraceMachine(image, override)
    slots = revert_slots(image, base)
    bad = 0
    out = []
    for c in cases:
        want_ev, want_js = model_revert(c, mut)
        ev, jsb = run_revert(m, c, base, slots)
        try:
            m.run(base, limit=50000)
            ok = check_revert(m, c, ev, jsb, want_ev, want_js)
            got = ("ret", len(ev))
        except (Boundary, ToolError) as exc:
            ok, got = False, ("error", str(exc))
        bad += not ok
        out.append((c, want_ev, want_js, ev, ok))
        if stop and not ok:
            break
    return out, bad, m


# ---------------------------------------------------------------- reconstruction: slot journal write
def layout(nb, entries, tombs, decoys):
    """hashbrown layout with 0xa8-byte buckets.

    entries [(key, hash, raw bucket bytes)], tombs [slot], decoys [(slot, h2, raw bucket bytes)].  Inserts take the first
    free byte of the first probe group that has one (triangular probing).  Bucket i ends at ctrl - i*0xa8; the
    sixteen bytes after the control bytes repeat the first sixteen.  Returns (memory, ctrl offset, {key: slot})."""
    mask = nb - 1
    mem = bytearray(nb * BUCKET + nb + 16)
    ctrl_off = nb * BUCKET
    ctrl = [0xff] * nb
    for i in tombs:
        ctrl[i] = 0x80
    taken = set(tombs)
    for i, h2, raw in decoys:
        ctrl[i] = h2
        taken.add(i)
        at = ctrl_off - (i + 1) * BUCKET
        mem[at:at + BUCKET] = raw
    slots = {}
    for key, h, raw in entries:
        pos, stride = h & mask, 0
        while True:
            free = [(pos + k) & mask for k in range(16) if ((pos + k) & mask) not in taken]
            if free:
                slot = free[0]
                break
            stride += 16
            pos = (pos + stride) & mask
        taken.add(slot)
        slots[key] = slot
        ctrl[slot] = h >> 57
        at = ctrl_off - (slot + 1) * BUCKET
        mem[at:at + BUCKET] = raw
    if 0xff not in ctrl:
        fail("table has no EMPTY slot")
    for i in range(nb):
        mem[ctrl_off + i] = ctrl[i]
    for i in range(16):
        mem[ctrl_off + nb + i] = ctrl[i % nb]
    return mem, ctrl_off, slots


def bucket_at(mem, coff, i):
    return mem[coff - (i + 1) * BUCKET:coff - i * BUCKET]


def probe(mem, coff, nb, h, key, mut=frozenset()):
    """Model of the group probe: slot index holding `key`, or None when a group with an EMPTY byte has no match."""
    mask = nb - 1
    h2 = (h >> 57) if "h2_shift56" not in mut else (h >> 56) & 0xff
    pos, stride = h & mask, 0
    for _ in range(nb + 2):
        grp = mem[coff + pos:coff + pos + 16]
        for b in range(16):
            if grp[b] != h2:
                continue
            idx = (pos + b) & mask
            bk = bucket_at(mem, coff, idx)
            if bk[:20] == key or ("tail_ignored" in mut and bk[:16] == key[:16]):
                return idx
        if 0xff in grp or "single_group" in mut:
            return None
        stride += 16
        pos = (pos + stride) & mask
    fail("probe did not terminate")


def model_write(c, mem, coff, mut=frozenset()):
    """Pure model.  Returns (kind, events, predicted memories) with kind 'ret' or 'panic'."""
    if c["items"] == 0 and "ignore_items" not in mut:
        return "panic", [], None
    h = addr_hash(c["key"], c["secret"] if "no_secret" not in mut else 0, c["seed"], mut)
    idx = probe(mem, coff, c["nb"], h, c["key"], mut)
    if idx is None:
        return "panic", [], None
    ev = []
    tab = bytearray(mem)
    jn = bytearray(c["jn"])
    jlen, jcap = c["jlen"], c["jcap"]
    end = coff - idx * BUCKET
    flags = tab[end - 4]

    def push(tag):
        nonlocal jlen
        e = jlen * ENTRY
        jn[e] = tag
        jn[e + 1:e + 17] = c["key"][:16]
        jn[e + 0x11:e + 0x15] = c["key"][16:20]
        jlen += 1

    if (flags & 4) == 0 or "touch_always" in mut:
        if jcap == jlen:
            ev.append(("grow", J_JCAP, jcap, jlen))
            jcap += GROW_STEP
        push(2)
        tab[end - 4] = flags | 4
    if jcap == jlen:
        ev.append(("grow", J_JCAP, jcap, jlen))
        jcap += GROW_STEP
    push(0xb if "tag_a" not in mut else 0xa)
    tab[end - 0x48:end - 0x28] = c["val"] if "value_off" not in mut else bytes(32)
    old = int.from_bytes(tab[end - 0x20:end - 0x18], "little")
    count = c["count"]
    if old != 0:
        count = (count - 1) & M64
        if count == 0 and "slow_never" not in mut:
            ev.append(("slow", coff - idx * BUCKET - 0x20))
    tab[end - 0x20:end - 0x18] = (c["newref"] if "keep_ref" not in mut else old).to_bytes(8, "little")
    return "ret", ev, {"tab": bytes(tab), "jn": bytes(jn), "jlen": jlen, "jcap": jcap, "count": count, "idx": idx}


MODES = ["hit", "hit", "hit-set", "absent", "decoy-hit", "decoy-absent", "tomb-hit", "full-group", "empty-items", "hit-set"]


def rand_raw(s):
    return bytearray(s.take(BUCKET))


def write_case(s, idx):
    mode = s.pick(MODES)
    nb = s.pick([16, 32, 32, 64])
    if mode == "full-group" and nb == 16:
        nb = 32
    secret = int.from_bytes(s.take(8), "little")
    seed = int.from_bytes(s.take(8), "little")
    key = s.take(20)
    h = addr_hash(key, secret, seed)
    mask = nb - 1
    pos = h & mask
    entries, decoys, tombs = [], [], []
    limit = 5 if nb == 16 else 12
    for _ in range(s.below(limit)):
        k = s.take(20)
        entries.append((k, addr_hash(k, secret, seed), bytes(rand_raw(s))))
    present = mode in ("hit", "hit-set", "decoy-hit", "tomb-hit", "full-group", "empty-items")
    raw = rand_raw(s)
    raw[:20] = key
    flags_set = mode in ("hit-set",) or (mode != "hit" and s.below(4) == 0)
    fl = int.from_bytes(raw[0xa4:0xa8], "little")
    fl = (fl | 4) if flags_set else (fl & ~4)
    raw[0xa4:0xa8] = (fl & 0xffffffff).to_bytes(4, "little")
    old_ref = s.pick([0, CNT_AT, CNT_AT, CNT_AT])
    count = s.pick([1, 1, 2, 0, 5, M64])
    raw[0x88:0x90] = old_ref.to_bytes(8, "little")
    if mode in ("decoy-hit", "decoy-absent"):
        for k in range(1 + s.below(4)):
            d = bytearray(key)
            d[s.below(20)] ^= 1 << s.below(8)
            draw = rand_raw(s)
            draw[:20] = d
            slot = (pos + s.below(16)) & mask
            if slot not in [x[0] for x in decoys]:
                decoys.append((slot, h >> 57, bytes(draw)))
    if mode == "tomb-hit":
        tombs = sorted({(pos + k) & mask for k in range(s.below(6))})
    if mode == "full-group":
        span = 16 if nb >= 32 else 12
        for k in range(span):
            slot = (pos + k) & mask
            draw = rand_raw(s)
            d = bytearray(key)
            d[s.below(20)] ^= 0x40
            draw[:20] = d
            decoys.append((slot, (h >> 57) if k % 3 == 0 else s.below(128), bytes(draw)))
    if present:
        entries.append((key, h, bytes(raw)))
    n_present = len(entries) + len(decoys)
    jcap = s.below(4) + (1 if mode != "hit" else 0)
    jlen = s.pick([jcap, jcap, max(jcap - 1, 0), jcap + 1, s.below(jcap + 1)])
    return {"fn": "write", "idx": idx, "mode": mode, "nb": nb, "secret": secret, "seed": seed, "key": key,
            "entries": entries, "decoys": decoys, "tombs": tombs, "items": 0 if mode == "empty-items" else n_present + 1,
            "jlen": jlen, "jcap": jcap, "newref": int.from_bytes(s.take(8), "little"), "count": count,
            "val": s.take(32)}


WRITE_CASES = 3600
CNT_AT = 0x7d10_0900_0000


def case_memories(c):
    mem, coff, slots = layout(c["nb"], c["entries"], c["tombs"], c["decoys"])
    c["jn"] = c.get("jn") or b"".join(bytes([0x4b + (i & 7)]) * ENTRY for i in range(c["jcap"] + c["jlen"] + 2 * GROW_STEP + 4))
    return mem, coff


def run_write(m, c, base, slots, mem, coff):
    m.reset()
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    js = bytearray([JS_FILL]) * JS_SIZE
    put(js, J_MAP, 8, TAB_AT + coff)
    put(js, J_MASK, 8, c["nb"] - 1)
    put(js, J_ITEMS, 8, c["items"])
    put(js, J_SECRET, 8, c["secret"])
    put(js, J_JCAP, 8, c["jcap"])
    put(js, J_JPTR, 8, JN_AT)
    put(js, J_JLEN, 8, c["jlen"])
    m.add_region(JS_AT, JS_SIZE, bytes(js))
    m.add_region(TAB_AT, len(mem), bytes(mem))
    m.add_region(JN_AT, len(c["jn"]), c["jn"])
    m.add_region(CNT_AT, 8, c["count"].to_bytes(8, "little"))
    m.add_region(KEY_AT, 0x20, c["key"] + bytes(12))
    m.add_region(VAL_AT, 0x20, c["val"])
    m.add_region(SEED_AT, 8, c["seed"].to_bytes(8, "little"))
    ev = []
    clobber = (0, 1, 2, 6, 7, 8, 9, 10, 11)

    def grow(mc):
        jsb = next(buf for lo, hi, buf in mc.regions if lo == JS_AT)
        cap = int.from_bytes(jsb[J_JCAP:J_JCAP + 8], "little")
        ln = int.from_bytes(jsb[J_JLEN:J_JLEN + 8], "little")
        ev.append(("grow", mc.regs[7] - JS_AT + J_JCAP - 0x18, cap, ln))
        put(jsb, J_JCAP, 8, cap + GROW_STEP)
        for r in clobber:
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1

    def slow(mc):
        ev.append(("slow", mc.regs[7] - TAB_AT))
        for r in clobber:
            mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1

    m.words[slots["seed"]] = SEED_AT
    m.words[slots["grow_a"]] = STUB_GROW
    m.words[slots["slow"]] = STUB_SLOW
    m.words[slots["panic"]] = STUB_PANIC
    m.stubs = {STUB_GROW: grow, STUB_SLOW: slow, STUB_PANIC: "panic"}
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = JS_AT, KEY_AT, c["newref"], VAL_AT
    return ev


def eval_write(image, base, cases, override=None, mut=frozenset(), machine=None, stop=False):
    ov = {base + LOCK_AT: 0x90}
    ov.update(override or {})
    m = machine or TraceMachine(image, ov)
    slots = write_slots(image, base)
    bad = 0
    out = []
    for c in cases:
        mem, coff = case_memories(c)
        kind, want_ev, pred = model_write(c, mem, coff, mut)
        ev = run_write(m, c, base, slots, mem, coff)
        try:
            m.run(base, limit=50000)
            got_kind = "ret"
        except Boundary as b:
            got_kind = "panic" if b.kind == "panic" and b.regs[7] == slots["msg"] else "?" + str(b.kind)
        except ToolError as exc:
            got_kind = "error:" + str(exc)
        ok = kind == got_kind and ev == want_ev
        if ok and kind == "ret":
            now = {lo: bytes(buf) for lo, hi, buf in m.regions}
            jsx = bytearray([JS_FILL]) * JS_SIZE
            put(jsx, J_MAP, 8, TAB_AT + coff)
            put(jsx, J_MASK, 8, c["nb"] - 1)
            put(jsx, J_ITEMS, 8, c["items"])
            put(jsx, J_SECRET, 8, c["secret"])
            put(jsx, J_JCAP, 8, pred["jcap"])
            put(jsx, J_JPTR, 8, JN_AT)
            put(jsx, J_JLEN, 8, pred["jlen"])
            ok = (now[JS_AT] == bytes(jsx) and now[TAB_AT] == pred["tab"] and now[JN_AT] == pred["jn"]
                  and now[CNT_AT] == pred["count"].to_bytes(8, "little") and now[KEY_AT] == c["key"] + bytes(12)
                  and now[VAL_AT] == c["val"] and [m.regs[k] for k in SAVED_REGS] == SAVED
                  and m.regs[4] == T.STACK_TOP - 0x100)
        bad += not ok
        out.append((c, kind, want_ev, ev, ok, pred))
        if stop and not ok:
            break
    return out, bad, m


# ---------------------------------------------------------------- static evidence
def sweep_locked(image, lo, hi):
    """Linear decode of an FDE extent; a lone 0xf0 prefix is its own row (the evaluator runs it as a nop), 0xcc is padding."""
    rows, va = [], lo
    while va < hi:
        first = image.code(va, 1)[0]
        if first in (0xcc, 0xf0):
            rows.append((va, None if first == 0xcc else {"op": 0xf0, "len": 1, "bytes": b"\xf0"}))
            va += 1
            continue
        form = decode(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


def static_evidence(image):
    starts = list(REVERT) + list(WRITE)
    rows = fde_rows(image, starts)
    decoded, funcs = {}, {}
    for f in starts:
        lo, hi = rows[f]
        hi = min(hi, lo + (0x1e0 if f in REVERT else 0x230))  # the body ends at the next function; padding follows
        decoded[f] = sweep_locked(image, lo, hi)
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                            "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None)}
    base = image.code(REVERT[0], 0x1a0)
    diffs = {}
    for f in REVERT[1:]:
        other = image.code(f, 0x1a0)
        offs = [i for i in range(0x1a0) if other[i] != base[i]]
        if offs != [0xb8, 0xb9, 0xba, 0xbb, 0x14e, 0x14f, 0x150, 0x151]:
            fail(f"revert copy {f:#x} differs outside the two GOT displacements: {offs}")
        diffs[f"{f:#x}"] = [f"{i:#x}" for i in offs]
    slots = {}
    for f in REVERT:
        a, d = revert_slots(image, f)
        slots[f"{f:#x}"] = {"applier": f"{a:#x}", "dealloc": f"{d:#x}",
                            "applier_reloc": "RELATIVE" if a in image.relative and a not in image.imports else "GLOB_DAT",
                            "dealloc_reloc": "RELATIVE" if d in image.relative and d not in image.imports else "GLOB_DAT"}
    w = {k: f"{v:#x}" for k, v in write_slots(image, WRITE[0]).items()}
    if image.code(WRITE[0] + LOCK_AT, 1) != b"\xf0":
        fail("lock prefix of the reference decrement moved")
    checks = {}
    for va, hx, what in CHECKED:
        want = bytes.fromhex(hx)
        if image.code(va, len(want)) != want:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want.hex(), "meaning": what}
    out = {"binary_sha256": SHA256, "functions": funcs, "revert_copy_byte_differences_vs_0x29710e0": diffs,
           "revert_got_slots": slots, "write_got_slots": w, "checked_bytes": checks,
           "journal_state_offsets": {"logs_ptr": "0x8", "logs_len": "0x10", "journal_cap": "0x18", "journal_ptr": "0x20",
                                     "journal_len": "0x28", "watermark": "0x40", "state_map_a": "0xc8",
                                     "state_map_mask": "0xd0", "state_map_items": "0xe0", "state_map_secret": "0xe8",
                                     "state_map_b": "0xf0", "depth": "0x118", "spec": "0x126"},
           "entry_bytes": {"journal": ENTRY, "log": LOGENT, "bucket": BUCKET}}
    return out, decoded


CHECKED = [
    (0x29710f7, "0fb68726010000", "spec byte +0x126 loaded"),
    (0x2971109, "4883f8014883d0ff", "depth saturating decrement: cmp 1; adc -1"),
    (0x2971122, "0f86ed000000", "jbe: checkpoint log length <= current length -> truncate branch"),
    (0x29711a5, "3c0c745a", "journal entry tag 0xc stops the replay"),
    (0x29711ab, "807c2407030f93c1", "applier flag = spec >= 3"),
    (0x29711f7, "ffd3", "call applier through the GOT slot loaded into rbx"),
    (0x2971201, "759d", "loop back while entries remain"),
    (0x2971270, "48c1e605", "log vector element freed with capacity << 5 bytes"),
    (0x29712d2, "4883bfe000000000", "write: map item count at +0xe0 compared with zero"),
    (0x29713e7, "41f645fc04", "write: bucket flag bit 4 (first touch) at end-4"),
    (0x297140d, "c6040802", "write: journal tag 2 stored"),
    (0x2971446, "c604080b", "write: journal tag 0xb stored"),
    (0x2971484, "f048ff0875", "write: lock decq of the old reference count"),
]


# ---------------------------------------------------------------- run, classify, controls
def rev_class(c, ev, wjs):
    trunc = "logs-cut" if c["ck"][0] <= c["nlogs"] else "logs-kept"
    applies = sum(1 for e in ev if e[0] == "apply")
    if c["ck"][1] >= c["jlen"]:
        j = "journal-kept"
    elif any(e[0] == "apply" for e in ev) and applies == c["jlen"] - c["ck"][1]:
        j = "journal-replayed"
    else:
        j = "journal-stopped-at-sentinel"
    return f"revert/{trunc}/{j}/{'water-lowered' if wjs['water'] != c['water'] else 'water-kept'}"


def write_class(c, kind, ev, pred):
    if kind == "panic":
        return "write/panic-" + ("empty-map" if c["items"] == 0 else "absent")
    first = "first-touch" if not (bucket_at(*case_memories(c), pred["idx"])[0xa4] & 4) else "already-touched"
    return f"write/ret/{first}/grow{sum(1 for e in ev if e[0] == 'grow')}/{'slow-free' if any(e[0] == 'slow' for e in ev) else 'no-free'}"


def cases_for(kind, copy, n, first=0):
    s = Stream(f"{kind}-{copy:#x}")
    gen = rev_case if kind == "rev" else write_case
    for i in range(first):
        gen(s, i)
    return [gen(s, i) for i in range(first, first + n)]


def chunked(kind, copy, n, step=200):
    for first in range(0, n, step):
        yield cases_for(kind, copy, min(step, n - first), first)


def stream_copy(kind, copy):
    """All cases of one body generated lazily in chunks (cases are not kept)."""
    s = Stream(f"{kind}-{copy:#x}")
    gen = rev_case if kind == "rev" else write_case
    total = REV_CASES if kind == "rev" else WRITE_CASES
    for i in range(total):
        yield gen(s, i)


def pool(kind, copy, n=300):
    return list(__import__("itertools").islice(stream_copy(kind, copy), n))


def mutated_pass(image, kind, copy, n, override=None, mut=frozenset()):
    cases = pool(kind, copy, n)
    if kind == "rev":
        _, bad, _ = eval_revert(image, copy, cases, override, mut, stop=True)
    else:
        _, bad, _ = eval_write(image, copy, cases, override, mut, stop=True)
    return bad > 0


REV_MUTANTS = ["depth_wrap", "depth_keep", "depth_floor1", "skip_dealloc", "dealloc_cap16", "drop_first", "log_len_keep",
               "water_max", "water_always", "spec_ge4", "spec_ge2", "journal_len_keep", "journal_forward",
               "journal_extra", "sentinel_ignore", "sentinel_skip", "sentinel_after", "args_swapped"]
WR_MUTANTS = ["h2_shift56", "tail_ignored", "single_group", "ignore_items", "no_secret", "touch_always", "tag_a",
              "value_off", "slow_never", "keep_ref"]


def jcc_flip_sites(image, base, lo, hi):
    sites, va = [], lo
    while va < hi:
        if image.code(va, 1)[0] in (0xf0, 0xcc):
            va += 1
            continue
        f = decode(image.code(va, 16), va)
        if 0x70 <= f["op"] <= 0x7f:
            sites.append(va)
        elif 0x0f80 <= f["op"] <= 0x0f8f:
            sites.append(va + 1)
        va += f["len"]
    return sites


def controls(image):
    rows, undetected = [], []
    for name in REV_MUTANTS:
        rows.append(("model", f"revert {name}", int(mutated_pass(image, "rev", REVERT[0], 400, mut=frozenset([name])))))
    for name in WR_MUTANTS:
        rows.append(("model", f"write {name}", int(mutated_pass(image, "wr", WRITE[0], 600, mut=frozenset([name])))))
    fde = fde_rows(image, list(REVERT) + list(WRITE))
    for copy in REVERT:
        lo, hi = fde[copy]
        sites = jcc_flip_sites(image, copy, lo, lo + 0x19b)
        for va in sites[: (None if copy == REVERT[0] else 5)]:
            byte = image.code(va, 1)[0] ^ 1
            det = mutated_pass(image, "rev", copy, 400, override={va: byte})
            if det:
                rows.append(("code", f"revert {va:#x}: condition byte ^1", 1))
            else:
                undetected.append(f"revert {va:#x}")
    lo, hi = fde[WRITE[0]]
    for va in jcc_flip_sites(image, WRITE[0], lo, lo + 0x1ed):
        byte = image.code(va, 1)[0] ^ 1
        det = mutated_pass(image, "wr", WRITE[0], 600, override={va: byte})
        if det:
            rows.append(("code", f"write {va:#x}: condition byte ^1", 1))
        else:
            undetected.append(f"write {va:#x}")
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
    return rows, undetected


# ---------------------------------------------------------------- output
def wtag(x):
    return T.wtag(x)


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    consts, decoded = static_evidence(image)
    total = bad = 0
    classes = {}
    rev_lines = ["case\tcopy\tlogs\tjournal\tjournal_cap\tcheckpoint\twatermark\tdepth\tspec\toutcome\tevents\tfinal\tmatch"]
    wr_lines = ["case\tmode\tbuckets\titems\tjournal\tjournal_cap\toutcome\tevents\tfinal\tmatch"]
    seen = {}
    for copy in REVERT:
        m = TraceMachine(image)
        n = 0
        for first in range(0, REV_CASES, 200):
            chunk = cases_for("rev", copy, min(200, REV_CASES - first), first)
            res, b, _ = eval_revert(image, copy, chunk, machine=m)
            bad += b
            for c, want_ev, wjs, ev, ok in res:
                total += 1
                oc = rev_class(c, ev, wjs)
                classes[oc] = classes.get(oc, 0) + 1
                if c["idx"] % 2 == 0:
                    kinds = {}
                    for e in ev:
                        kinds[e[0]] = kinds.get(e[0], 0) + 1
                    rev_lines.append("\t".join(map(str, [
                        c["idx"], f"{copy:#x}", c["nlogs"], c["jlen"], c["jcap"],
                        f"{c['ck'][0]}/{c['ck'][1]}", f"{wtag(c['ck'][2])}vs{wtag(c['water'])}", wtag(c["depth"]),
                        f"{c['spec']:#x}", oc, ",".join(f"{k}={v}" for k, v in sorted(kinds.items())) or "-",
                        f"logs={wjs['nlogs']},jlen={wjs['jlen']},depth={wtag(wjs['depth'])}", "yes" if ok else "NO"])))
        seen[copy] = m.seen
    wmach = TraceMachine(image, {WRITE[0] + LOCK_AT: 0x90})
    for first in range(0, WRITE_CASES, 200):
        chunk = cases_for("wr", WRITE[0], min(200, WRITE_CASES - first), first)
        res, b, _ = eval_write(image, WRITE[0], chunk, machine=wmach)
        bad += b
        for c, kind, want_ev, ev, ok, pred in res:
            total += 1
            oc = write_class(c, kind, ev, pred)
            classes[oc] = classes.get(oc, 0) + 1
            if c["idx"] % 2 == 0:
                evs = ",".join(f"{e[0]}" + (f"@{e[2]}/{e[3]}" if e[0] == "grow" else "") for e in ev) or "-"
                fin = "-" if pred is None else f"slot={pred['idx']},jlen={pred['jlen']},cap={pred['jcap']},count={wtag(pred['count'])}"
                wr_lines.append("\t".join(map(str, [c["idx"], c["mode"], c["nb"], c["items"], c["jlen"], c["jcap"], oc, evs,
                                                    fin, "yes" if ok else "NO"])))
    seen[WRITE[0]] = wmach.seen
    (out / "cases-revert.tsv").write_text("\n".join(rev_lines) + "\n")
    (out / "cases-write.tsv").write_text("\n".join(wr_lines) + "\n")
    (out / "outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    lines = ["function\taddress\tlength\tbytes\topcode\texecuted"]
    covered = {}
    for start, insns in sorted(decoded.items()):
        hit = tot = 0
        for va, f in insns:
            if f is None:
                lines.append(f"{start:#x}\t{va:#x}\t1\tcc\tpadding\t0")
                continue
            run = va in seen.get(start, ())
            hit += run
            tot += 1
            lines.append(f"{start:#x}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t{int(run)}")
        covered[f"{start:#x}"] = [hit, tot]
    (out / "decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl, undetected = controls(image)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl)
        + "".join(f"undetected-not-counted\t{u_}\t0\n" for u_ in undetected))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    detected = sum(r[2] for r in ctl)
    summary = {"binary_sha256": SHA256, "cases": total, "mismatches": bad, "covered_instructions": covered,
               "outcome_classes": classes, "negative_controls": {"total": len(ctl), "detected": detected},
               "undetected_equivalent_flips": len(undetected)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": total, "negative_controls": len(ctl),
                                                  "negative_detected": detected}, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
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
