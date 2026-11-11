#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM alt_bn128 precompile glue: add 0x5c15e20, mul 0x5c16080, pairing 0x5c162b0 and six gas wrappers.

The three run bodies are the revm-style glue around a lazily initialised crypto provider: every body first
compares a fixed gas cost against the caller's gas limit (cost above limit -> the out-of-gas status 0x8000000000000001),
then right-pads or reads the input in place and hands fixed-size slices to one vtable method of the provider behind the
GOT static 0x64fe3d8 (slot +0x30 add, +0x38 mul, +0x40 pairing).  add pads to 128 bytes (inputs up to 0x7f are copied into a
zeroed stack buffer, longer ones are read in place), mul pads to 96 bytes and passes a 32-byte scalar, and the pairing body
computes n = len / 192 with the reciprocal multiply 0xaaaa...ab >> 7, the cost n * per_pair + base with overflow panics,
rejects lengths that are not multiples of 192 with status 0x800000000000000a, and builds one 32-byte
(ptr, 64, ptr, 128) slice descriptor per pair in a heap vector.  A successful add or mul result is boxed in a fresh 64-byte
allocation; the Bytes-like output picks one of two vtables by the allocation's low bit.  The six wrappers
(add 150 / 500 at 0x5c09750 / 0x5c097f0, mul 6000 / 40000 at 0x5c15ba0 / 0x5c15c40, pairing 34000 + 45000 / 80000 + 100000 per
pair at 0x5c15ce0 / 0x5c15d80) call the bodies through the GOT slots 0x64eaec8 / 0x64eaec0 / 0x64eaed0 and widen the 0x28-byte
result into a 0x58-byte frame.  The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the
real machine code with the concrete x86-64 evaluator of tools/re11_transient_storage115.py (no external programs, the binary
is never executed; allocator, memcpy, panics and the provider methods are stubbed by call target and their arguments are
recorded) and compares every case with one pure-Python reconstruction.  Negative controls show that wrong
reconstructions and corrupted code bytes are detected.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_transient_storage115 as ev  # noqa: E402

BINARY = ev.BINARY
SHA256 = ev.SHA256
M64 = ev.M64
ToolError, Boundary, Image, TraceMachine, Stream = ev.ToolError, ev.Boundary, ev.Image, ev.TraceMachine, ev.Stream
fail = ev.fail

# ---------------------------------------------------------------- target addresses (observed)
ADD_RUN, MUL_RUN, PAIR_RUN = 0x5c15e20, 0x5c16080, 0x5c162b0
SLOT_MUL, SLOT_ADD, SLOT_PAIR = 0x64eaec0, 0x64eaec8, 0x64eaed0  # RELATIVE words -> the run bodies
STATIC_VA = 0x64fe3d8  # lazy provider object: +0 data, +8 vtable, +0x10 once-state
STATIC_GOT = 0x64ec358  # RELATIVE word -> STATIC_VA
ONCE_INIT = 0x5bee2d3
ALLOC, ALLOC_ERR, DEALLOC, VEC_GROW = 0x6355830, 0x141e264, 0x635de30, 0x5c1f200
SLOT_ALLOC, SLOT_ALLOC_ERR, SLOT_DEALLOC, SLOT_GROW = 0x64df480, 0x64df498, 0x64df4a0, 0x64ec3b8
PANIC_MUL, PANIC_ADD, PANIC_SLICE = 0x1681dc0, 0x1681da0, 0x16817e0
SLOT_MEMCPY = 0x64df508
OOG = 0x8000000000000001
BAD_LEN = OOG + 9
OK_MARK = 0x8000000000000024
V_ODD, V_EVEN = 0x64040c0, 0x64040e8  # Bytes vtables chosen by the allocation's low bit (words at 0x64df8c8 / 0x64df8c0)
BOOL_TRUE, BOOL_FALSE = 0x4576a0, 0x457f80
STATIC_A, STATIC_B = 0x64c0190, 0x64c0420

# (name, entry, family, fixed cost, per-pair, base)
TARGETS = [
    ("add-run", ADD_RUN, "add", None, None, None),
    ("mul-run", MUL_RUN, "mul", None, None, None),
    ("pair-run", PAIR_RUN, "pair", None, None, None),
    ("add-wrap-150", 0x5c09750, "add", 150, None, None),
    ("add-wrap-500", 0x5c097f0, "add", 500, None, None),
    ("mul-wrap-6000", 0x5c15ba0, "mul", 6000, None, None),
    ("mul-wrap-40000", 0x5c15c40, "mul", 40000, None, None),
    ("pair-wrap-34000", 0x5c15ce0, "pair", None, 34000, 45000),
    ("pair-wrap-80000", 0x5c15d80, "pair", None, 80000, 100000),
]
ENTRIES = {t[0]: t for t in TARGETS}
FUNC_STARTS = tuple(t[1] for t in TARGETS)
ROLES = {
    "add-run": "bn254 add body: gas check, pad to 128, provider vtable +0x30, box 64-byte result",
    "mul-run": "bn254 mul body: gas check, pad to 96, provider vtable +0x38, box 64-byte result",
    "pair-run": "bn254 pairing body: n*per+base cost, len%192, slice vector, provider vtable +0x40",
    "add-wrap-150": "add gas 150 wrapper -> body via GOT 0x64eaec8, widen to 0x58 frame",
    "add-wrap-500": "add gas 500 wrapper -> body via GOT 0x64eaec8, widen to 0x58 frame",
    "mul-wrap-6000": "mul gas 6000 wrapper -> body via GOT 0x64eaec0, widen to 0x58 frame",
    "mul-wrap-40000": "mul gas 40000 wrapper -> body via GOT 0x64eaec0, widen to 0x58 frame",
    "pair-wrap-34000": "pairing 34000/pair + 45000 wrapper -> body via GOT 0x64eaed0",
    "pair-wrap-80000": "pairing 80000/pair + 100000 wrapper -> body via GOT 0x64eaed0",
}

# ---------------------------------------------------------------- harness layout
OUT_AT = 0x7d00_0000_0000
IN_AT = 0x7d00_0100_0000
VT_AT = 0x7d00_0200_0000
ALLOC_BASE = 0x7d00_0300_0000
ALLOC_STRIDE = 0x1_0000
DATA_PTR = 0x7d00_0400_0000
FN_ADD, FN_MUL, FN_PAIR = 0x7d10_0000_0001, 0x7d10_0000_0002, 0x7d10_0000_0003
STACK_FILL = 0x5a
OUT_FILL = 0xee
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
SAVED_REGS = (3, 5, 12, 13, 14, 15)
PAD = {"add": 0x80, "mul": 0x60}
SLICE2 = {"add": 0x40, "mul": 0x20}
VT_SLOT = {"add": 0x30, "mul": 0x38, "pair": 0x40}


# ---------------------------------------------------------------- pure reconstruction
def stale(n):
    return bytes([STACK_FILL]) * n


def model_run(c, mut=frozenset(), under_wrapper=False):
    """Reconstruct the body at the entry: returns (out bytes, events, panic).  c carries the decoded arguments."""
    fam = c["family"]
    fill = STACK_FILL if under_wrapper else OUT_FILL
    out = bytearray([fill]) * 0x28
    ev_log = []
    data, ln = c["input"], len(c["input"])
    cost, limit = c["cost"], c["limit"]
    if fam == "pair":
        n = ln // 192
        if "pair_no_floor" in mut:
            n = (ln + 191) // 192
        prod = n * c["per"]
        if prod > M64:
            ev_log.append(("noreturn", "mul-overflow"))
            return bytes(out), ev_log, "mul-overflow"
        cost = prod + c["base"]
        if cost > M64:
            ev_log.append(("noreturn", "add-overflow"))
            return bytes(out), ev_log, "add-overflow"
    over = cost >= limit if "limit_ge" in mut else cost > limit
    if over:
        out[0:8] = (0).to_bytes(8, "little")
        out[8:16] = OOG.to_bytes(8, "little")
        return bytes(out), ev_log, None
    once = c["once"]
    if fam == "pair":
        if ln != 192 * n:
            out[0:8] = (0).to_bytes(8, "little")
            out[8:16] = (BAD_LEN if "bad_len_code" not in mut else BAD_LEN + 1).to_bytes(8, "little")
            return bytes(out), ev_log, None
        pairs = []
        for i in range(n):
            pairs.append((192 * i, 64, 192 * i + 64, 128))
        if n and c["alloc_fail"]:
            ev_log.append(("alloc", 32 * n))
            ev_log.append(("noreturn", "alloc-error", 8, 32 * n))
            return bytes(out), ev_log, "alloc-error"
        if n:
            ev_log.append(("alloc", 32 * n))
        if once:
            ev_log.append(("once-init",))
        ev_log.append(("vt-pair", len(pairs), tuple(pairs), 8 if not pairs else "heap"))
        if n:
            ev_log.append(("dealloc", 32 * n, 0))
        res = c["vt"]
        if res[0] == "ok":
            bit = res[1] & 1
            tail = BOOL_TRUE if bit else BOOL_FALSE
            if "pair_bool_swap" in mut:
                tail = BOOL_FALSE if bit else BOOL_TRUE
            out[0:8] = STATIC_B.to_bytes(8, "little")
            out[8:16] = tail.to_bytes(8, "little")
            out[0x10:0x18] = (0x20).to_bytes(8, "little")
            out[0x18:0x20] = (0).to_bytes(8, "little")
            out[0x20:0x28] = cost.to_bytes(8, "little")
        else:
            tag, b8, w9, w10 = res[1:5]
            # the provider's two 8-byte words overlap by one byte (result bytes 9..16 and 0x10..0x17)
            tmp = bytearray(0x18)
            tmp[9:17] = w9.to_bytes(8, "little")
            tmp[0x10:0x18] = w10.to_bytes(8, "little")
            out[0x18:0x20] = tmp[0x10:0x18]
            out[0x11:0x19] = tmp[9:17]
            out[0x8:0x10] = tag.to_bytes(8, "little")
            out[0x10] = b8
            out[0:8] = (0).to_bytes(8, "little")
        return bytes(out), ev_log, None
    pad = PAD[fam]
    if "pad_off_by_one" in mut:
        pad -= 1
    in_place = ln >= pad if "pad_off_by_one" not in mut else ln > pad
    if in_place:
        buf = bytes(data)
        where1, where2 = "in+0", "in+64"
    else:
        buf = bytes(data) + bytes(pad - ln)
        where1, where2 = "stack", "stack"
        ev_log.append(("memcpy", ln))
    if once:
        ev_log.append(("once-init",))
    n2 = SLICE2[fam]
    if "mul_scalar_len" in mut and fam == "mul":
        n2 = 0x40
    ev_log.append(("vt-" + fam, where1, buf[0:64].hex(), where2, buf[64:64 + n2].hex(), 0x40, n2))
    res = c["vt"]
    if res[0] == "err":
        out[0:8] = (0).to_bytes(8, "little")
        out[8:0x20] = res[2]
        return bytes(out), ev_log, None
    ev_log.append(("alloc", 0x40))
    if c["alloc_fail"]:
        ev_log.append(("noreturn", "alloc-error", 1, 0x40))
        return bytes(out), ev_log, "alloc-error"
    ptr = ALLOC_BASE + c["parity"]
    odd = ptr & 1
    out[0:8] = (V_ODD if odd else V_EVEN).to_bytes(8, "little")
    out[8:16] = ptr.to_bytes(8, "little")
    out[0x10:0x18] = (0x40).to_bytes(8, "little")
    out[0x18:0x20] = (ptr if odd else ptr | 1).to_bytes(8, "little")
    out[0x20:0x28] = cost.to_bytes(8, "little")
    ev_log.append(("box", res[1].hex()))
    return bytes(out), ev_log, None


def model_wrapper(c, mut=frozenset()):
    """Reconstruct a wrapper: constants for the body, then widen the 0x28-byte result to the 0x58-byte frame."""
    fam = c["family"]
    inner = dict(c)
    if fam == "pair":
        inner["per"], inner["base"] = c["w_per"], c["w_base"]
        inner["limit"] = c["limit"]
    else:
        inner["cost"] = c["w_cost"]
    tmp, events, panic = model_run(inner, mut, under_wrapper=True)
    if panic:
        return bytes([OUT_FILL]) * 0x58, events, panic
    out = bytearray([OUT_FILL]) * 0x58
    tag = int.from_bytes(tmp[0:8], "little")
    word = lambda off: tmp[off:off + 8]  # noqa: E731
    if tag != 0:
        out[0:8] = OK_MARK.to_bytes(8, "little")
        out[8:0x18] = stale(16)
        out[0x18:0x20] = word(0)
        out[0x20:0x28] = word(8)
        out[0x28:0x38] = tmp[0x10:0x20]
        out[0x38:0x40] = word(0x20)
    else:
        out[0:8] = word(8)
        out[8:0x18] = tmp[0x10:0x20]
        out[0x18:0x20] = (STATIC_A if fam == "add" else STATIC_B).to_bytes(8, "little")
        out[0x20:0x28] = (1).to_bytes(8, "little")
        out[0x28:0x40] = bytes(0x18)
    out[0x40:0x50] = bytes(16)
    out[0x50:0x58] = c["ctx"].to_bytes(8, "little")
    return bytes(out), events, None


def model(c, mut=frozenset()):
    return (model_wrapper if c["wrapper"] else model_run)(c, mut)


# ---------------------------------------------------------------- evaluation rig
def region(m, lo):
    return next(buf for a, b, buf in m.regions if a == lo)


def rd(m, at, n):
    return bytes(m.load(at + i, 1) for i in range(n))


def setup(m, c):
    """Install the regions and stubs for one case; returns the event log."""
    events = []
    m.regions[0][2][:] = bytes([STACK_FILL]) * len(m.regions[0][2])
    m.add_region(OUT_AT, 0x58 if c["wrapper"] else 0x28, bytes([OUT_FILL]) * (0x58 if c["wrapper"] else 0x28))
    m.add_region(IN_AT, len(c["input"]), c["input"])
    vt = bytearray(0x50)
    for off, fn in ((0x30, FN_ADD), (0x38, FN_MUL), (0x40, FN_PAIR)):
        vt[off:off + 8] = fn.to_bytes(8, "little")
    m.add_region(VT_AT, len(vt), bytes(vt))
    st = bytearray(0x20)
    st[0:8] = DATA_PTR.to_bytes(8, "little")
    st[8:16] = VT_AT.to_bytes(8, "little")
    st[0x10:0x14] = c["once"].to_bytes(4, "little")
    static = m.add_region(STATIC_VA, 0x20, bytes(st))
    allocs = [0]

    def clobber(mc, keep=()):
        for r in (1, 2, 6, 8, 9, 10, 11):
            if r not in keep:
                mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1

    def src_label(p):
        if IN_AT <= p <= IN_AT + len(c["input"]):
            return f"in+{p - IN_AT}"
        return "stack"

    def once(mc):
        events.append(("once-init",))
        static[0x10:0x14] = bytes(4)
        clobber(mc)
        mc.regs[0] = 0xc1c1_c1c1_c1c1_c1c1

    def memcpy(mc):
        dst, src, n = mc.regs[7], mc.regs[6], mc.regs[2]
        events.append(("memcpy", n))
        for i in range(n):
            mc.store(dst + i, 1, mc.load(src + i, 1))
        mc.regs[0] = dst
        clobber(mc, keep=(7,))

    def vt_two(kind):
        def stub(mc):
            tmp, data, p1, l1, p2, l2 = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1], mc.regs[8], mc.regs[9]
            if data != DATA_PTR:
                fail("provider data pointer was not the static's first word")
            events.append(("vt-" + kind, src_label(p1), rd(mc, p1, l1).hex(), src_label(p2), rd(mc, p2, l2).hex(), l1, l2))
            res = c["vt"]
            if res[0] == "ok":
                mc.store(tmp, 1, 0)
                for i, b in enumerate(res[1]):
                    mc.store(tmp + 1 + i, 1, b)
            else:
                mc.store(tmp, 1, res[1])
                for i, b in enumerate(res[2]):
                    mc.store(tmp + 8 + i, 1, b)
            mc.regs[0] = tmp
            clobber(mc)
        return stub

    def vt_pair(mc):
        tmp, data, vec, cnt = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1]
        pairs = []
        for i in range(cnt):
            w = [mc.load(vec + 32 * i + 8 * k, 8) for k in range(4)]
            pairs.append((w[0] - IN_AT, w[1], w[2] - IN_AT, w[3]))
        events.append(("vt-pair", cnt, tuple(pairs), vec if cnt == 0 else "heap"))
        res = c["vt"]
        base = tmp
        if res[0] == "ok":
            mc.store(base, 8, OK_MARK)
            mc.store(base + 8, 1, res[1])
        else:
            tag, b8, w9, w10 = res[1:5]
            mc.store(base, 8, tag)
            mc.store(base + 8, 1, b8)
            mc.store(base + 9, 8, w9)
            mc.store(base + 0x10, 8, w10)
        mc.regs[0] = tmp
        clobber(mc)

    def alloc(mc):
        size = mc.regs[7]
        events.append(("alloc", size))
        if c["alloc_fail"]:
            mc.regs[0] = 0
        else:
            at = ALLOC_BASE + ALLOC_STRIDE * allocs[0] + c["parity"]
            allocs[0] += 1
            mc.add_region(at, size, bytes([0xaa]) * size)
            mc.regs[0] = at
        clobber(mc)

    def dealloc(mc):
        events.append(("dealloc", mc.regs[6], mc.regs[2]))
        clobber(mc)
        mc.regs[0] = 0xc1c1_c1c1_c1c1_c1c1

    m.stubs = {FN_ADD: vt_two("add"), FN_MUL: vt_two("mul"), FN_PAIR: vt_pair, ONCE_INIT: once,
               ev.IMPORT_BASE + 16 * 7: memcpy, ALLOC: alloc, DEALLOC: dealloc,
               ALLOC_ERR: "alloc-error", PANIC_MUL: "mul-overflow", PANIC_ADD: "add-overflow",
               PANIC_SLICE: "slice-range", VEC_GROW: "vec-grow"}
    return events


def run_case(m, c):
    m.reset()
    events = setup(m, c)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    fam = c["family"]
    m.regs[7] = OUT_AT
    m.regs[6] = IN_AT
    m.regs[2] = len(c["input"])
    if c["wrapper"]:
        m.regs[1], m.regs[8] = c["limit"], c["ctx"]
        m.regs[9] = 0x9999_9999_9999_9999
    elif fam == "pair":
        m.regs[1], m.regs[8], m.regs[9] = c["per"], c["base"], c["limit"]
    else:
        m.regs[1], m.regs[8], m.regs[9] = c["cost"], c["limit"], 0x9999_9999_9999_9999
    entry_rsp = m.regs[4] - 8
    stack = region(m, ev.STACK_TOP - 0x10000)
    top_before = bytes(stack[entry_rsp + 8 - (ev.STACK_TOP - 0x10000):])
    got = {"events": events}
    try:
        m.run(c["entry"], limit=40000)
    except Boundary as b:
        events.append(("noreturn", b.kind, b.regs[7], b.regs[6]) if b.kind == "alloc-error" else ("noreturn", b.kind))
        got["panic"] = b.kind
        got["out"] = bytes(region(m, OUT_AT))
        return got
    got["panic"] = None
    got["out"] = bytes(region(m, OUT_AT))
    got["ret_ok"] = m.regs[0] == OUT_AT
    got["regs_ok"] = [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == entry_rsp + 8
    got["rest_ok"] = bytes(stack[entry_rsp + 8 - (ev.STACK_TOP - 0x10000):]) == top_before
    if not c["wrapper"] and fam != "pair" and c["vt"][0] == "ok" and not c["alloc_fail"] and not got["panic"]:
        pass
    return got


def normalise_events(events):
    out = []
    for e in events:
        if e[0] == "noreturn" and e[1] != "alloc-error":
            out.append(("noreturn", e[1]))
        else:
            out.append(tuple(e))
    return out


def box_of(m, c, want):
    if not any(e[0] == "box" for e in want[1]):
        return None
    return rd(m, ALLOC_BASE + c["parity"], 0x40).hex()


def compare(c, want, got, boxed):
    out, events, panic = want
    if panic != got["panic"] or out != got["out"]:
        return False
    ev_got = normalise_events(got["events"])
    ev_want = [e for e in events if e[0] != "box"]
    if ev_want != ev_got:
        return False
    box = [e for e in events if e[0] == "box"]
    if box and box[0][1] != boxed:
        return False
    if panic:
        return True
    return got["ret_ok"] and got["regs_ok"] and got["rest_ok"]


# ---------------------------------------------------------------- cases
PER_TARGET = {"add-run": 1300, "mul-run": 1300, "pair-run": 1500, "add-wrap-150": 1000, "add-wrap-500": 1000,
              "mul-wrap-6000": 1000, "mul-wrap-40000": 1000, "pair-wrap-34000": 1300, "pair-wrap-80000": 1300}


def rand_bytes(s, n):
    return s.take(n)


def vt_result(s, fam):
    r = s.below(10)
    if fam == "pair":
        if r < 5:
            return ("ok", s.pick([0, 1, 0, 1, 2, 3, 0xfe, 0xff]))
        tag = s.pick([0, 1, 5, OK_MARK + 1, OK_MARK - 1, M64, 1 << 63, s.below(1 << 62)])
        return ("err", tag, s.pick([0, 1, 7, 0x80, 0xff]), int.from_bytes(s.take(8), "little"), int.from_bytes(s.take(8), "little"))
    if r < 6:
        return ("ok", rand_bytes(s, 64))
    return ("err", s.pick([1, 2, 0x7f, 0x80, 0xff, 3]), rand_bytes(s, 24))


def make_case(s, t):
    name, entry, fam, wcost, wper, wbase = t
    wrapper = wcost is not None or wper is not None
    c = {"target": name, "entry": entry, "family": fam, "wrapper": wrapper, "once": s.pick([0] * 6 + [1, 2, 0xffffffff]),
         "parity": s.pick([0, 1]), "alloc_fail": s.below(14) == 0, "ctx": int.from_bytes(s.take(8), "little"),
         "vt": vt_result(s, fam)}
    mode = s.pick(["normal"] * 5 + ["edge-lo", "edge-eq", "edge-hi", "oog-zero", "limit-max"])
    c["mode"] = mode
    if fam == "pair":
        n = s.pick([0, 1, 1, 2, 2, 3, 4, 5, 6, 8, 12, 17])
        delta = s.pick([0] * 8 + [1, 191, 95, 64, 3])
        ln = 192 * n + delta
        c["input"] = rand_bytes(s, ln)
        if wrapper:
            c["w_per"], c["w_base"] = wper, wbase
            per, base = wper, wbase
        else:
            per = s.pick([34000, 80000, 0, 1, M64, 1 << 63, s.below(1 << 40), 100000])
            base = s.pick([45000, 100000, 0, 1, M64, s.below(1 << 40)])
            if mode == "edge-hi":
                per, base = 1 << 63, s.pick([0, 5])
            c["per"], c["base"] = per, base
        nn = ln // 192
        cost = nn * per + base
        if wrapper or cost <= M64 or nn * per <= M64:
            pass
        c["cost_hint"] = cost
        limit = {"normal": cost + s.below(1000), "edge-lo": cost - 1, "edge-eq": cost, "edge-hi": cost + 1,
                 "oog-zero": 0, "limit-max": M64}[mode]
        c["limit"] = limit & M64
        if wrapper:
            c["cost"] = 0
        else:
            c["cost"] = 0
        c["limit"] = min(max(limit, 0), M64) if limit >= 0 else 0
    else:
        pad = PAD[fam]
        ln = s.pick([0, 1, 31, 32, 33, 63, 64, 65, pad - 2, pad - 1, pad, pad + 1, pad + 40, 300, s.below(2 * pad + 40), s.below(pad)])
        c["input"] = rand_bytes(s, ln)
        if wrapper:
            c["w_cost"] = wcost
            cost = wcost
            c["cost"] = 0
        else:
            cost = s.pick([150, 500, 6000, 40000, 0, 1, M64, s.below(1 << 20)])
            c["cost"] = cost
        limit = {"normal": cost + s.below(1000) if cost < M64 - 1000 else M64, "edge-lo": cost - 1, "edge-eq": cost,
                 "edge-hi": cost + 1, "oog-zero": 0, "limit-max": M64}[mode]
        c["limit"] = min(max(limit, 0), M64)
    return c


def all_cases():
    for t in TARGETS:
        s = Stream("bn254-" + t[0])
        for _ in range(PER_TARGET[t[0]]):
            yield make_case(s, t)


# ---------------------------------------------------------------- static evidence
def static_evidence(image):
    rows = ev.fde_rows(image, set(FUNC_STARTS))
    decoded = {}
    for start in FUNC_STARTS:
        s, e = rows[start]
        insns = ev.sweep(image, s, e)
        decoded[start] = insns
    slots = {}
    for name, slot in (("mul", SLOT_MUL), ("add", SLOT_ADD), ("pair", SLOT_PAIR), ("static", STATIC_GOT),
                       ("alloc", SLOT_ALLOC), ("alloc-error", SLOT_ALLOC_ERR), ("dealloc", SLOT_DEALLOC),
                       ("vec-grow", SLOT_GROW), ("vtable-even", 0x64df8c0), ("vtable-odd", 0x64df8c8),
                       ("panic-mul", 0x64df870), ("panic-add", 0x64df520), ("panic-slice", 0x64df570)):
        slots[name] = {"slot": f"{slot:#x}", "word": f"{image.relative[slot]:#x}" if slot in image.relative else None}
    slots["memcpy-import"] = {"slot": f"{SLOT_MEMCPY:#x}", "word": f"{image.relative[SLOT_MEMCPY]:#x}",
                              "symbol": image.import_name(SLOT_MEMCPY)}
    expected = {"mul": MUL_RUN, "add": ADD_RUN, "pair": PAIR_RUN, "static": STATIC_VA, "alloc": ALLOC,
                "alloc-error": ALLOC_ERR, "dealloc": DEALLOC, "vec-grow": VEC_GROW, "vtable-even": V_EVEN,
                "vtable-odd": V_ODD, "panic-mul": PANIC_MUL, "panic-add": PANIC_ADD, "panic-slice": PANIC_SLICE}
    for k, v in expected.items():
        if image.relative.get(int(slots[k]["slot"], 16)) != v:
            fail(f"relocation word {k} is not {v:#x}")
    static_bytes = image.read(STATIC_VA, 0x18)
    consts = {"binary_sha256": SHA256, "slots": slots, "static_initial_bytes": static_bytes.hex(),
              "immediates": {}, "call_sites": {}}
    for start, insns in decoded.items():
        imms, calls = [], []
        for va, f in insns:
            if f["op"] in (0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf) or 0xb8 <= f["op"] <= 0xbf:
                imms.append([f"{va:#x}", f"{f['imm']:#x}"])
            elif f["op"] in (0x83, 0x81, 0x3d) and "imm" in f:
                imms.append([f"{va:#x}", f"{f['imm'] & M64:#x}"])
            if f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip":
                slot = (va + f["len"] + f["rm"][4]) & M64
                calls.append([f"{va:#x}", f"{slot:#x}"])
            if f["op"] == 0xe8:
                calls.append([f"{va:#x}", f"{f['target']:#x}"])
        consts["immediates"][f"{start:#x}"] = imms
        consts["call_sites"][f"{start:#x}"] = calls
    return rows, decoded, consts


def evaluate(image, cases, override=None, mut=frozenset(), stop_on_first=False, machine=None, sink=None):
    m = machine or TraceMachine(image, override)
    total = bad = 0
    for i, c in enumerate(cases):
        try:
            want = model(c, mut)
            got = run_case(m, c)
            ok = compare(c, want, got, box_of(m, c, want))
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        total += 1
        bad += not ok
        if sink is not None:
            sink(i, c, want, got, ok)
        if stop_on_first and not ok:
            break
    return total, bad, m


# ---------------------------------------------------------------- controls
MODEL_MUTANTS = ["limit_ge", "pad_off_by_one", "mul_scalar_len", "pair_no_floor", "bad_len_code", "pair_bool_swap"]

# Byte edits the stated cases cannot observe, with the reason read from the instruction windows.
EQUIVALENT = {
    0x5c1633f: "length threshold cmp $0xbf: the multiple-of-192 test already left only 0 or >= 192, so any bound in 0..191 selects the same branch",
    0x5c16436: "initial vector length store: dead, the loop stores the index into the same slot before the provider call",
    0x5c16448: "capacity-end value 0x18(%rsp) is only the slice-end argument of the unreachable bounds panic",
    0x5c1658b: "landing pad (unwind cleanup) condition: no stubbed call unwinds",
    0x5c16595: "landing pad (unwind cleanup) shift: no stubbed call unwinds",
}


def byte_candidates(decoded):
    """Single-byte edits of every condition, small immediate and mov immediate in the nine functions."""
    out = []
    for start in sorted(decoded):
        for va, f in decoded[start]:
            op, b = f["op"], f["bytes"]
            if 0x70 <= op <= 0x7f:
                out.append((va + len(b) - 2, b[-2] ^ 1, f"{start:#x} short condition flipped"))
            elif 0x0f80 <= op <= 0x0f8f:
                out.append((va + b.index(op & 0xff), (op & 0xff) ^ 1, f"{start:#x} near condition flipped"))
            elif op in (0x83, 0xc1, 0x80, 0x6b) and "imm" in f:
                out.append((va + len(b) - 1, (b[-1] + 1) & 0xff, f"{start:#x} imm8 {b[-1]:#x} + 1"))
            elif 0xb8 <= op <= 0xbf:
                n = 8 if f["rex"] & 8 else 4
                out.append((va + len(b) - n, b[len(b) - n] ^ 1, f"{start:#x} mov imm{8 * n} low byte {b[len(b) - n]:#x} ^ 1"))
            elif op in (0x81, 0x3d, 0xc7) and "imm" in f:
                out.append((va + len(b) - 4, b[len(b) - 4] ^ 1, f"{start:#x} imm32 low byte {b[len(b) - 4]:#x} ^ 1"))
    return out


def controls(image, cases, decoded):
    rows, equivalents = [], []
    for name in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, cases, mut=frozenset([name]), stop_on_first=True)
        rows.append(("model", name, int(bad > 0)))
    for va, byte, what in byte_candidates(decoded):
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = evaluate(image, cases, override={va: byte}, stop_on_first=True)
        label = f"{va:#x}={byte:#04x} {what}"
        if bad:
            rows.append(("code", label, 1))
        elif va in EQUIVALENT:
            rows.append(("code", label, 0))
            equivalents.append((label, f"{va:#x}", EQUIVALENT[va]))
        else:
            fail(f"undetected byte mutant without an equivalence argument: {label}")
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
    try:
        ev.fde_rows(image, {ADD_RUN + 1})
        rows.append(("input", "address that starts no FDE", 0))
    except ToolError:
        rows.append(("input", "address that starts no FDE", 1))
    try:
        Image(image.data[:-1] + bytes([image.data[-1] ^ 1]))
        rows.append(("input", "one flipped trailing byte", 0))
    except ToolError:
        rows.append(("input", "one flipped trailing byte", 1))
    return rows, equivalents


# ---------------------------------------------------------------- output
def outcome(c, want):
    out, events, panic = want
    pre = ("wrap/" if c["wrapper"] else "body/") + c["family"] + "/"
    if panic:
        return pre + "panic:" + panic
    kinds = [e[0] for e in events]
    tag = int.from_bytes(out[8:16], "little")
    first = int.from_bytes(out[0:8], "little")
    if c["wrapper"]:
        body = "ok" if first == OK_MARK else "out-of-gas" if first == OOG else "bad-length" if first == BAD_LEN else "provider-error"
    else:
        body = "ok" if first != 0 else "out-of-gas" if tag == OOG else "bad-length" if tag == BAD_LEN else "provider-error"
    if c["family"] == "pair":
        extra = "/empty" if "vt-pair" in kinds and "alloc" not in kinds else ""
    else:
        extra = "/padded" if "memcpy" in kinds else ("/in-place" if "vt-add" in kinds or "vt-mul" in kinds else "")
    return pre + body + extra


def arg_text(c):
    if c["family"] == "pair":
        price = f"per={c['per']:#x},base={c['base']:#x}" if "per" in c else f"per={c['w_per']},base={c['w_base']}"
    else:
        price = f"cost={c['w_cost']}" if c["wrapper"] else f"cost={c['cost']:#x}"
    return (f"len={len(c['input'])},limit={c['limit']:#x},{price},once={c['once']:#x},parity={c['parity']},"
            f"alloc={'fail' if c['alloc_fail'] else 'ok'},vt={c['vt'][0]},mode={c['mode']}")


def result_text(got):
    if "error" in got:
        return got["error"]
    res = f"out={hashlib.sha256(got['out']).hexdigest()[:12]}"
    if got["panic"]:
        return res
    return res + f",rax={'out' if got['ret_ok'] else 'bad'},regs={int(got['regs_ok'])},stack={int(got['rest_ok'])}"


def event_text(got):
    if "error" in got:
        return "-"
    return ">".join(e[0] if e[0] != "noreturn" else "noreturn:" + e[1] for e in got["events"]) or "-"


def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    rows, decoded, consts = static_evidence(image)
    classes = {}
    digest = hashlib.sha256()
    machine = TraceMachine(image)
    with open(out / "cases.tsv", "w") as fh:
        fh.write("case\ttarget\tinput\toutcome\tevents\tresult\tmatch\n")

        def sink(i, c, want, got, ok):
            oc = "error" if want is None else outcome(c, want)
            classes[oc] = classes.get(oc, 0) + 1
            res = result_text(got)
            fh.write(f"{i}\t{c['target']}\t{arg_text(c)}\t{oc}\t{event_text(got)}\t{res}\t{'yes' if ok else 'NO'}\n")
            digest.update(("%d|%s|%s\n" % (i, oc, res)).encode())

        total, bad, m = evaluate(image, all_cases(), machine=machine, sink=sink)
    (out / "outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    lines = ["function\taddress\tlength\tbytes\topcode\texecuted"]
    covered = {}
    for start, insns in sorted(decoded.items()):
        hit = 0
        for va, f in insns:
            run = va in m.seen
            hit += run
            lines.append(f"{start:#x}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t{int(run)}")
        covered[f"{start:#x}"] = [hit, len(insns)]
    (out / "decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    lines = ["function\tstart\tend\tlength\trole"]
    for t in TARGETS:
        s, e = rows[t[1]]
        lines.append(f"{t[0]}\t{s:#x}\t{e:#x}\t{e - s}\t{ROLES[t[0]]}")
    (out / "functions.tsv").write_text("\n".join(lines) + "\n")
    ctl_cases = []
    for t in TARGETS:
        st = Stream("ctl-" + t[0])
        ctl_cases += [make_case(st, t) for _ in range(150)]
    ctl, equivalents = controls(image, ctl_cases, decoded)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "equivalent-mutants.tsv").write_text(
        "mutant\taddress\treason\n" + "".join("\t".join(r) + "\n" for r in equivalents))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    detected = sum(r[2] for r in ctl)
    summary = {"binary_sha256": SHA256, "cases": total, "mismatches": bad, "covered_instructions": covered,
               "outcome_classes": classes, "case_digest": digest.hexdigest(),
               "negative_controls": {"total": len(ctl), "detected": detected, "equivalent": len(equivalents)}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps(
        {"cases": total, "negative_controls": len(ctl), "negative_detected": detected,
         "equivalent": len(equivalents)}, indent=2, sort_keys=True) + "\n")
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
    print(json.dumps(summary["negative_controls"], sort_keys=True), summary["cases"], summary["mismatches"])
    nc = summary["negative_controls"]
    bad = summary["mismatches"] or nc["detected"] + nc["equivalent"] != nc["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
