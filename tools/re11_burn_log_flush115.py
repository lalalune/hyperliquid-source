#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM burn/transfer log emitters and the end-of-block burn-log flush.

The EVM host keeps a log vector (cap +0x0, ptr +0x8, len +0x10, 0x50-byte entries).  Three copy
families of the capture contain the same bodies: the log emitters (burn: 0x2970eb0, 0x4322d00,
0x54631e0; transfer: 0x29714f0, 0x54635f0) and two end-of-block flushes (0x2972200 and 0x4324300).

A flush returns when the spec byte (+0x126) is below 0x0e or either flag byte (+0x124, +0x125) is set.
Otherwise it walks the pending list (20-byte addresses, ptr +0x38, count +0x40), looks each address up in
the account map at +0xc8 (hashbrown, 0xa8-byte buckets, key = address, value u256 at bucket +0x40,
folded two-multiply hash with the process seed behind GOT slot 0x64dfa78) and collects the 0x38-byte
records (address, pad, value) whose value is nonzero into a Vec (first allocation 0xe0 bytes = four
records, then doubling).  Two to twenty records are insertion-sorted by memcmp over the 20 address bytes;
longer lists go to a GOT sort slot (recorded here, not evaluated).  Each record is handed to the burn log
emitter, which does nothing for a zero value, otherwise allocates the topic block (0x40 bytes: 32-byte
event word, the address left padded to 32 bytes) and the data block (0x20 bytes, the value big endian)
and appends an 0x50-byte entry (growing the log vector through GOT slot 0x64dfa48 when it is full).  The
transfer emitter is the same with three topics (block 0x60) and the value from its fourth argument.

The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real machine
code of all these bodies with a small concrete x86-64 evaluator (the repository evaluator in
re11_transient_storage115 plus two SSE forms; the binary is never executed) and compares every case
with one pure-Python reconstruction.  Allocator, free, vector-grow, memcmp and the big sort are stubs
that record their arguments.  Negative controls show that wrong reconstructions, inverted conditional
branches in the code bytes and out-of-range inputs are detected.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402,F401
import fde_extents  # noqa: E402,F401
import re11_transient_storage115 as ev  # noqa: E402

Image, Machine, Boundary, Stream = ev.Image, ev.Machine, ev.Boundary, ev.Stream
ToolError, fail, put, u, addr_hash = ev.ToolError, ev.fail, ev.put, ev.u, ev.addr_hash
M64, STACK_TOP, IMPORT_BASE = ev.M64, ev.STACK_TOP, ev.IMPORT_BASE
BINARY, SHA256 = ev.BINARY, ev.SHA256

FOLDER = "RE-011-burn-log-flush-115"
TOOL = "re11_burn_log_flush115"

# ---------------------------------------------------------------- the bodies
FLUSH = {  # flush -> (collect, closure lookup, sort, emitter)
    0x2972200: ("A", 0x2346480, 0x29dee60, 0x26d4140, 0x2970eb0),
    0x4324300: ("B", 0x3da9b20, None, 0x4376880, 0x4322d00),
}
BURN = (0x2970eb0, 0x4322d00, 0x54631e0)
TRANSFER = (0x29714f0, 0x54635f0)
GROW_VEC = 0x231e050  # Vec<0x38 byte record> grow, evaluated; its finish routine 0x231dc90 is a stub
CLOSURE_B = None  # discovered from the call sites of the B collect copy

# GOT slots (RELATIVE or GLOB_DAT words) that the bodies call through
S_MALLOC, S_ERR_A, S_ERR_B, S_FREE, S_UNWIND = 0x64df480, 0x64df490, 0x64df498, 0x64df4a0, 0x64df4c0
S_LOGGROW, S_MEMCMP, S_BIGSORT, S_SEED = 0x64dfa48, 0x64dfb50, 0x64e6d70, 0x64dfa78
S_VT_ODD, S_VT_EVEN = 0x64df8c8, 0x64df8c0
GROW_FINISH = 0x231dc90

# host layout
H_CAP, H_PTR, H_LEN, H_PEND, H_PENDN, H_F124, H_F125, H_SPEC, H_MAP = 0x0, 0x8, 0x10, 0x38, 0x40, 0x124, 0x125, 0x126, 0xc8
SPEC_MIN = 0x0e
ENTRY = 0x50
BUCKET = 0xa8
REC = 0x38

HOST_AT, HOST_SIZE = 0x7d00_0100_0000, 0x400
LOG_AT, GROWLOG_AT = 0x7d00_0200_0000, 0x7d00_0210_0000
PEND_AT, TABLE_AT = 0x7d00_0300_0000, 0x7d00_0400_0000
ARG_AT = 0x7d00_0500_0000
HEAP_AT, GROWVEC_AT = 0x7d00_0600_0000, 0x7d00_0700_0000
HOST_FILL, STACK_FILL, TABLE_FILL, LOG_FILL = 0x44, 0x5c, 0x66, 0x99
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
CLOBBER = 0xc1c1_c1c1_c1c1_c1c1


# ---------------------------------------------------------------- decoder additions (POR, MOVMSKPS)
def decode_ext(code, va, _orig=ev.decode):
    p = 0
    while code[p] in (0x66, 0x2e, 0xf3, 0xf2, 0x64):
        p += 1
    if 0x40 <= code[p] <= 0x4f:
        p += 1
    if code[p] == 0x0f and code[p + 1] in (0xeb, 0x50):
        sub = bytearray(code)
        real = sub[p + 1]
        sub[p + 1] = 0xef if real == 0xeb else 0xd7  # same ModRM shape as pxor / pmovmskb
        form = _orig(bytes(sub), va)
        form["op"] = 0x0f00 | real
        form["bytes"] = bytes(code[:form["len"]])
        return form
    return _orig(code, va)


ev.decode = decode_ext


class PM(Machine):
    def step(self, va):
        f = self.fetch(va)
        if f["op"] == 0x0feb:
            if f["rm"][0] != "r":
                fail("por with a memory operand")
            self.xmm[f["reg"]] |= self.xmm[f["rm"][1]]
            return (va + f["len"]) & M64
        if f["op"] == 0x0f50:
            if f["rm"][0] != "r":
                fail("movmskps with a memory operand")
            v = self.xmm[f["rm"][1]]
            self.set_reg(f["reg"], 32, sum(1 << i for i in range(4) if (v >> (32 * i + 31)) & 1), f)
            return (va + f["len"]) & M64
        return super().step(va)


# ---------------------------------------------------------------- binary facts
def facts(image):
    """FDE extents of every body, call sites in order, jcc positions; everything from the ELF bytes."""
    _, fdes = fde_extents.eh_frame_records(image.data, image.secs)
    ends = {f["start"]: f["end"] for f in fdes}
    bodies = {}
    names = set(BURN) | set(TRANSFER) | set(FLUSH) | {GROW_VEC}
    for fl, (_, col, clo, srt, emi) in FLUSH.items():
        names |= {col, srt, emi}
        if clo:
            names.add(clo)
    for a in sorted(names):
        if a not in ends:
            fail(f"no FDE starts at {a:#x}")
    return ends


def sweep_all(image, ends, addrs):
    out = {}
    for a in addrs:
        out[a] = ev.sweep(image, a, ends[a])
    return out


def call_sites(rows):
    """Direct calls (e8) in address order and indirect GOT calls (ff 15) as (site, kind, target/slot)."""
    res = []
    for va, f in rows:
        if f["op"] == 0xe8:
            res.append((va, "call", f["target"]))
        elif f["op"] == 0xff and f["rm"][0] == "m" and f["rm"][1] == "rip" and (f["reg"] & 7) == 2:
            res.append((va, "got", (va + f["len"] + f["rm"][4]) & M64))
    return res


def slot_targets(image):
    keys = {}
    for slot in (S_MALLOC, S_ERR_A, S_ERR_B, S_FREE, S_UNWIND, S_LOGGROW, S_MEMCMP, S_BIGSORT):
        keys[slot] = image.word(slot)
    return keys


# ---------------------------------------------------------------- role discovery (bytes only)
class Roles:
    """Per-body facts read from the decoded code bytes: GOT words and rodata constants."""

    def __init__(self, image, ends, a):
        self.a = a
        self.rows = ev.sweep(image, a, ends[a])
        self.sites = call_sites(self.rows)
        self.got = [image.word(t) for (_, k, t) in self.sites if k == "got"]
        self.direct = [t for (_, k, t) in self.sites if k == "call"]
        self.rip_loads = []
        for va, f in self.rows:
            rm = f.get("rm")
            if rm and rm[0] == "m" and rm[1] == "rip":
                self.rip_loads.append((va, f["op"], f["size"], (va + f["len"] + rm[4]) & M64))
        self.image = image

    def emitter(self):
        """burn/transfer emitter: [malloc, malloc, loggrow, errA, errB, unwind], constants, vtable words."""
        g = self.got
        mal1, mal2, grow, erra, errb = g[0], g[1], g[2], g[3], g[4]
        loads = [x for x in self.rip_loads if x[1] == 0x0f10]
        c_hi, c_lo, c_ent = (self.image.read(x[3], 16) for x in loads)
        vt = [x for x in self.rip_loads if x[1] in (0x8b, 0x0f44) and x[2] == 64]
        return {"malloc": mal1, "malloc2": mal2, "loggrow": grow, "erra": erra, "errb": errb,
                "c_lo": c_lo, "c_hi": c_hi, "c_ent": c_ent,
                "vt_odd": self.image.word(vt[0][3]), "vt_even": self.image.word(vt[1][3]),
                "vt_slots": (vt[0][3], vt[1][3]), "const_vas": tuple(x[3] for x in loads)}


def emitter_facts(image, ends, a):
    return Roles(image, ends, a).emitter()


# ---------------------------------------------------------------- hashbrown fixture (0xa8-byte buckets)
def layout(nb, entries, tombs, decoys):
    """entries [(key20, hash, payload)], decoys [(slot, h2, key20)]; first free byte of the first probe group."""
    mask = nb - 1
    mem = bytearray([TABLE_FILL]) * (nb * BUCKET + nb + 16)
    ctrl_off = nb * BUCKET
    ctrl = [0xff] * nb
    for i in tombs:
        ctrl[i] = 0x80
    taken = set(tombs)
    for i, h2, key in decoys:
        ctrl[i] = h2
        taken.add(i)
        at = ctrl_off - (i + 1) * BUCKET
        mem[at:at + len(key)] = key
    slots = {}
    for key, h, payload in entries:
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
        mem[at:at + 20] = key
        mem[at + 0x40:at + 0x40 + 32] = payload
    if 0xff not in ctrl:
        fail("table has no EMPTY slot")
    for i in range(nb):
        mem[ctrl_off + i] = ctrl[i]
    for i in range(16):
        mem[ctrl_off + nb + i] = ctrl[i % nb]
    return mem, ctrl_off, slots


# ---------------------------------------------------------------- deterministic addresses (host contract)
def heap_addr(idx, size, odd):
    return HEAP_AT + idx * 0x1000 + (1 if (size == 0x20 and odd) else 0)


def growlog_addr(k):
    return GROWLOG_AT + k * 0x10000


def growvec_addr(k):
    return GROWVEC_AT + k * 0x10000


def memcmp_ret(a, b):
    for x, y in zip(a, b):
        if x != y:
            return (x - y) & 0xffffffff
    return 0


# ---------------------------------------------------------------- reconstruction
def topic_pad(a):
    return bytes(12) + bytes(a)


def be_value(v):
    return bytes(v)[::-1]


def emit_model(st, E, kind, args, mut):
    """One emitter call on the abstract state st; returns None or a panic tuple.

    st: spec, f124, cap, ptr, len, entries(list of 0x50 bytes), tr(list), nmalloc, fail_at, odd, nloggrow
    args: burn (addr, value) / transfer (from, to, value)."""
    value = args[-1]
    if st["spec"] < (SPEC_MIN if "spec_ge0f" not in mut else SPEC_MIN + 1):
        return None
    if st["f124"] != 0 and "f124_ignored" not in mut:
        return None
    if not any(value) and "zero_value_logs" not in mut:
        return None
    nt = len(args) - 1
    tsize = 0x40 if nt == 1 else 0x60
    st["tr"].append(("malloc", tsize))
    idx = st["nmalloc"]
    st["nmalloc"] += 1
    if idx == st["fail_at"]:
        return ("panic", E["erra"], 1, tsize)
    topics_at = heap_addr(idx, tsize, st["odd"])
    topics = E["c_lo"] + E["c_hi"]
    for a in (args[:-1] if "swap_topics" not in mut else args[-2::-1]):
        topics += topic_pad(a) if "no_pad" not in mut else bytes(a) + bytes(12)
    st["tr"].append(("malloc", 0x20))
    idx2 = st["nmalloc"]
    st["nmalloc"] += 1
    if idx2 == st["fail_at"]:
        st["blocks"].append((topics_at, topics))
        return ("panic", E["errb"], 1, 0x20)
    data_at = heap_addr(idx2, 0x20, st["odd"])
    data = be_value(value) if "le_value" not in mut else bytes(value)
    odd = data_at & 1
    tagged = data_at if odd else data_at | 1
    vt = E["vt_odd"] if odd else E["vt_even"]
    if "swap_vt" in mut:
        vt = E["vt_even"] if odd else E["vt_odd"]
    cnt = nt + 1 if "count_off" not in mut else nt
    entry = struct.pack("<QQQQQQQ", cnt, topics_at, cnt, vt, data_at, 0x20, tagged)
    entry = entry[:0x38] + E["c_ent"] + struct.pack("<I", 0xfeffffff) + b"\0\0\0\0"
    if st["len"] == st["cap"]:
        k = st["nloggrow"]
        st["nloggrow"] += 1
        newcap = max(2 * st["cap"], 4) if "loggrow_double_only" not in mut else 2 * st["cap"]
        st["tr"].append(("loggrow", st["cap"], newcap, growlog_addr(k)))
        st["cap"], st["ptr"] = newcap, growlog_addr(k)
    st["entries"].append(entry)
    st["len"] += 1
    st["blocks"].append((topics_at, topics))
    st["blocks"].append((data_at, data))
    return None


def sort_records(recs, mut):
    n = len(recs)
    if n < 2:
        return recs, None
    if n >= 21 and "sort_always" not in mut:
        return recs, n
    out = list(recs)
    for i in range(1, n):
        j = i
        cur = out[i]
        if "sort_desc" in mut:
            while j > 0 and out[j - 1][0] < cur[0]:
                out[j] = out[j - 1]
                j -= 1
        else:
            while j > 0 and out[j - 1][0] > cur[0]:
                out[j] = out[j - 1]
                j -= 1
        out[j] = cur
    return out, None


def flush_model(st, E, F, mut):
    """End-of-block burn-log flush; st as for emit_model plus pending, table, items, seed, secret."""
    if st["spec"] < SPEC_MIN or ((st["f124"] != 0 or st["f125"] != 0) and "f125_ignored" not in mut):
        return None
    if "f125_ignored" in mut and st["f124"] != 0:
        return None
    recs = []
    for a in st["pending"]:
        if st["items"] == 0 and "ignore_items" not in mut:
            continue
        v = st["table"].get(a)
        if v is None or (not any(v) and "zero_value_kept" not in mut):
            continue
        recs.append((a, v))
    vcap = vptr = None
    if recs:
        st["tr"].append(("malloc", 0xe0))
        idx = st["nmalloc"]
        st["nmalloc"] += 1
        if idx == st["fail_at"]:
            return ("panic", F["col_err"], 8, 0xe0)
        vptr, vcap, k = heap_addr(idx, 0xe0, 0), 4, 0
        for i in range(len(recs)):
            if i == vcap:
                newcap = max(2 * vcap, i + 1, 4) if "growvec_plus" not in mut else vcap + 4
                k += 1
                st["tr"].append(("growvec", vcap, newcap, growvec_addr(k - 1)))
                vcap, vptr = newcap, growvec_addr(k - 1)
    n = len(recs)
    recs, big = sort_records(recs, mut)
    if big is not None:
        st["tr"].append(("bigsort", big))
    for a, v in recs:
        r = emit_model(st, E, "burn", (a, v), mut)
        if r:
            return r
    if vcap and "free_none" not in mut:
        st["tr"].append(("free", vptr, vcap * REC if "free_len" not in mut else n * REC))
    return None


# ---------------------------------------------------------------- harness
def region(m, base):
    return next(buf for lo, hi, buf in m.regions if lo == base)


def setup(m, c, E, F):
    """Build the machine state of case c; returns the trace list (stub events)."""
    tr = []
    st = {"nmalloc": 0, "nloggrow": 0, "nvec": 0}
    m.regions[0][2][:] = bytes([c.get("stack_fill", STACK_FILL)]) * len(m.regions[0][2])
    host = m.add_region(HOST_AT, HOST_SIZE, bytes([HOST_FILL]) * HOST_SIZE)
    put(host, H_CAP, 8, c["cap"])
    put(host, H_PTR, 8, LOG_AT)
    put(host, H_LEN, 8, c["len"])
    host[H_F124], host[H_SPEC] = c["f124"], c["spec"]
    if c["kind"] == "flush":
        host[H_F125] = c["f125"]
    log = m.add_region(LOG_AT, max(1, c["cap"]) * ENTRY, bytes([LOG_FILL]) * (max(1, c["cap"]) * ENTRY))
    for i, e in enumerate(c["init"]):
        log[i * ENTRY:(i + 1) * ENTRY] = e
    if c["kind"] == "flush":
        n = len(c["pending"])
        put(host, H_PEND, 8, PEND_AT)
        put(host, H_PENDN, 8, n)
        m.add_region(PEND_AT, max(1, n) * 20, b"".join(c["pending"]))
        entries = [(a, addr_hash(a, c["secret"], c["seed"]), v) for a, v in c["order"]]
        dec = [(s, h2, k) for s, h2, k in c["decoys"]]
        mem, coff, _ = layout(c["buckets"], entries, c["tombs"], dec)
        m.add_region(TABLE_AT, len(mem), bytes(mem))
        put(host, H_MAP, 8, TABLE_AT + coff)
        put(host, H_MAP + 8, 8, c["buckets"] - 1)
        put(host, H_MAP + 0x10, 8, 0x1234)
        put(host, H_MAP + 0x18, 8, c["items"])
        put(host, H_MAP + 0x20, 8, c["secret"])
        m.add_region(m.image.word(S_SEED), 8, c["seed"].to_bytes(8, "little"))
    else:
        args = c["args"]
        for i, a in enumerate(args):
            m.add_region(ARG_AT + 0x40 * i, 0x40, bytes(a) + bytes(0x40 - len(a)))

    def malloc(mc):
        size = mc.regs[7]
        tr.append(("malloc", size))
        idx = st["nmalloc"]
        st["nmalloc"] += 1
        if idx == c["fail_at"]:
            rax = 0
        else:
            rax = heap_addr(idx, size, c["odd"])
            mc.add_region(rax, size, bytes([0xcd]) * size)
        for r in (1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = CLOBBER
        mc.regs[0] = rax

    def free(mc):
        tr.append(("free", mc.regs[7], mc.regs[6]))
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = CLOBBER

    def loggrow(mc):
        h = mc.regs[7]
        cap, ln = mc.load(h + H_CAP, 8), mc.load(h + H_LEN, 8)
        newcap = max(2 * cap, 4)
        base = growlog_addr(st["nloggrow"])
        st["nloggrow"] += 1
        old = mc.load(h + H_PTR, 8)
        buf = mc.add_region(base, newcap * ENTRY, bytes([LOG_FILL]) * (newcap * ENTRY))
        for i in range(ln * ENTRY):
            buf[i] = mc.load(old + i, 1)
        mc.store(h + H_CAP, 8, newcap)
        mc.store(h + H_PTR, 8, base)
        tr.append(("loggrow", cap, newcap, base))
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = CLOBBER

    def memcmp(mc):
        a = bytes(mc.load(mc.regs[7] + i, 1) for i in range(mc.regs[2]))
        b = bytes(mc.load(mc.regs[6] + i, 1) for i in range(mc.regs[2]))
        for r in (1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = CLOBBER
        mc.regs[0] = memcmp_ret(a, b)

    def bigsort(mc):
        tr.append(("bigsort", mc.regs[6]))
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = CLOBBER

    def growvec(mc):
        out, oldcap, oldptr, newcap = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1]
        base = growvec_addr(st["nvec"])
        st["nvec"] += 1
        buf = mc.add_region(base, newcap * REC, bytes([0xcd]) * (newcap * REC))
        for i in range(oldcap * REC):
            buf[i] = mc.load(oldptr + i, 1)
        mc.store(out, 4, 0)
        mc.store(out + 8, 8, base)
        tr.append(("growvec", oldcap, newcap, base))
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            mc.regs[r] = CLOBBER

    stubs = {E["malloc"]: malloc, E["loggrow"]: loggrow, E["erra"]: f"err{E['erra']:x}",
             E["errb"]: f"err{E['errb']:x}"}
    if c["kind"] == "flush":
        stubs.update({F["malloc"]: malloc, F["col_err"]: f"err{F['col_err']:x}", F["free"]: free,
                      F["memcmp"]: memcmp, F["bigsort"]: bigsort, F['grow_finish']: growvec})
    m.stubs = stubs
    return tr, st


def run_case(m, c, E, F, entry):
    m.reset()
    tr, _ = setup(m, c, E, F)
    keep = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in (PEND_AT, TABLE_AT, ARG_AT, ARG_AT + 0x40, ARG_AT + 0x80)}
    for k, v in zip((3, 12, 13, 14, 15, 5), SAVED):
        m.regs[k] = v
    m.regs[7] = HOST_AT
    if c["kind"] == "burn":
        m.regs[6], m.regs[2] = ARG_AT, ARG_AT + 0x40
    elif c["kind"] == "transfer":
        m.regs[6], m.regs[2], m.regs[1] = ARG_AT, ARG_AT + 0x40, ARG_AT + 0x80
    got = {"trace": tr}
    try:
        m.run(entry, limit=400000)
        got["ret"] = None
        got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == STACK_TOP - 0x100
    except Boundary as b:
        got["ret"] = ("panic", int(b.kind[3:], 16), b.regs[7] & M64, b.regs[6] & M64)
        got["regs_ok"] = True
    host = bytes(region(m, HOST_AT))
    got["host"] = host
    cap, ptr, ln = u(host, H_CAP, 8), u(host, H_PTR, 8), u(host, H_LEN, 8)
    got["log"] = [bytes(m.load(ptr + i * ENTRY + j, 1) for j in range(ENTRY)) for i in range(ln)]
    got["blocks"] = {}
    for base, size in ((lo, hi - lo) for lo, hi, buf in m.regions if HEAP_AT <= lo < GROWVEC_AT):
        got["blocks"][base] = bytes(region(m, base))
    got["rest_ok"] = {lo: bytes(region(m, lo)) for lo in keep} == keep
    return got


def expected(c, E, F, mut=frozenset()):
    st = {"spec": c["spec"], "f124": c["f124"], "f125": c.get("f125", 0), "cap": c["cap"], "ptr": LOG_AT,
          "len": c["len"], "entries": list(c["init"]), "tr": [], "nmalloc": 0, "nloggrow": 0,
          "fail_at": c["fail_at"], "odd": c["odd"], "blocks": []}
    if c["kind"] == "flush":
        st["pending"] = c["pending"]
        st["table"] = {a: v for a, v in c["order"]}
        st["items"] = c["items"]
        ret = flush_model(st, E, F, mut)
    else:
        ret = emit_model(st, E, c["kind"], c["args"] if c["kind"] == "transfer" else c["args"], mut)
    host = bytearray([HOST_FILL]) * HOST_SIZE
    put(host, H_CAP, 8, st["cap"])
    put(host, H_PTR, 8, st["ptr"] if st["ptr"] != LOG_AT or st["cap"] == c["cap"] else LOG_AT)
    put(host, H_LEN, 8, st["len"])
    host[H_F124], host[H_SPEC] = c["f124"], c["spec"]
    if c["kind"] == "flush":
        host[H_F125] = c["f125"]
        put(host, H_PEND, 8, PEND_AT)
        put(host, H_PENDN, 8, len(c["pending"]))
        mem, coff, _ = layout(c["buckets"], [(a, addr_hash(a, c["secret"], c["seed"]), v) for a, v in c["order"]],
                              c["tombs"], c["decoys"])
        put(host, H_MAP, 8, TABLE_AT + coff)
        put(host, H_MAP + 8, 8, c["buckets"] - 1)
        put(host, H_MAP + 0x10, 8, 0x1234)
        put(host, H_MAP + 0x18, 8, c["items"])
        put(host, H_MAP + 0x20, 8, c["secret"])
    return {"ret": ret, "trace": st["tr"], "host": bytes(host), "log": st["entries"], "blocks": st["blocks"]}


def compare(c, want, got, mut_blocks=True):
    if want["ret"] != got["ret"] or want["trace"] != got["trace"] or want["host"] != got["host"]:
        return False
    if len(want["log"]) != len(got["log"]):
        return False
    n0 = len(c["init"])
    for i, (w, g) in enumerate(zip(want["log"], got["log"])):
        if (w if i < n0 else w[:0x4c]) != (g if i < n0 else g[:0x4c]):
            return False
    for base, data in want["blocks"]:
        if got["blocks"].get(base, b"")[:len(data)] != data:
            return False
    return bool(got["regs_ok"] and got["rest_ok"])


# ---------------------------------------------------------------- cases
def rand_bytes(s, n):
    kind = s.below(12)
    if kind == 0:
        return bytes(n)
    if kind == 1:
        return b"\xff" * n
    return s.take(n)


def rand_value(s):
    k = s.below(10)
    if k < 2:
        return bytes(32)
    if k < 5:
        v = bytearray(32)
        i = s.below(4)
        v[8 * i:8 * i + 8] = s.take(8) if s.below(2) else (1).to_bytes(8, "little")
        return bytes(v)
    if k == 5:
        return b"\xff" * 32
    return s.take(32)


def spec_f124(s, flush):
    spec = s.below(0x0e) if s.below(8) == 0 else 0x0e + s.pick((0, 0, 0, 1, 2, 6, 0x20, 0xf1))
    f124 = 0 if s.below(7) else s.pick((1, 2, 0x80, 0xff))
    f125 = 0 if (not flush or s.below(7)) else s.pick((1, 2, 0xff))
    return spec, f124, f125


def log_state(s):
    cap = 1 + s.below(5)
    ln = cap if s.below(3) == 0 else s.below(cap + 1)
    return cap, ln, [s.take(ENTRY) for _ in range(ln)]


def emit_case(fn, kind, idx):
    s = Stream(f"{kind}-{fn:x}-{idx}")
    spec, f124, _ = spec_f124(s, False)
    cap, ln, init = log_state(s)
    nargs = 3 if kind == "transfer" else 2
    args = [rand_bytes(s, 20) for _ in range(nargs - 1)] + [rand_value(s)]
    fail_at = s.pick((None,) * 9 + (0, 1)) if s.below(4) == 0 else None
    return {"id": f"{fn:x}-{idx}", "fn": fn, "kind": kind, "spec": spec, "f124": f124, "f125": 0, "cap": cap,
            "len": ln, "init": init, "args": args, "odd": s.below(2), "fail_at": fail_at}


def flush_case(fn, idx):
    s = Stream(f"flush-{fn:x}-{idx}")
    spec, f124, f125 = spec_f124(s, True)
    cap, ln, init = log_state(s)
    pool = [s.take(20) for _ in range(1 + s.below(10))]
    roll = s.below(20)
    n = 0 if roll == 0 else (1 + s.below(8) if roll < 13 else (9 + s.below(12) if roll < 18 else 21 + s.below(10)))
    pending = [s.pick(pool) for _ in range(n)]
    order, seen = [], set()
    for a in pool:
        if s.below(10) < 7 and a not in seen:
            seen.add(a)
            order.append((a, bytes(32) if s.below(7) == 0 else s.take(32)))
    for _ in range(s.below(4)):
        a = s.take(20)
        if a not in seen:
            seen.add(a)
            order.append((a, s.take(32)))
    seed, secret = int.from_bytes(s.take(8), "little") | 1, int.from_bytes(s.take(8), "little")
    nb = 16 if len(order) <= 7 else 32
    mask = nb - 1
    decoys, used = [], set()
    for a, v in order:
        h = addr_hash(a, secret, seed)
        slot = h & mask
        if s.below(10) < 3 and slot not in used:
            used.add(slot)
            other = bytes(s.take(20))
            if other != a:
                decoys.append((slot, h >> 57, other))
    tombs = []
    for _ in range(s.below(3)):
        t = s.below(nb)
        if t not in used:
            used.add(t)
            tombs.append(t)
    items = len(order) if s.below(20) else 0
    fail_at = 0 if s.below(25) == 0 else (s.pick((1, 2, 3)) if s.below(25) == 0 else None)
    return {"id": f"{fn:x}-{idx}", "fn": fn, "kind": "flush", "spec": spec, "f124": f124, "f125": f125,
            "cap": cap, "len": ln, "init": init, "pending": pending, "order": order, "buckets": nb,
            "decoys": decoys, "tombs": tombs, "items": items, "seed": seed, "secret": secret, "odd": s.below(2),
            "fail_at": fail_at}


COUNTS = {"emit": 1700, "flush": 2300}


def all_cases():
    for fn in BURN:
        for i in range(COUNTS["emit"]):
            yield emit_case(fn, "burn", i)
    for fn in TRANSFER:
        for i in range(COUNTS["emit"]):
            yield emit_case(fn, "transfer", i)
    for fn in FLUSH:
        for i in range(COUNTS["flush"]):
            yield flush_case(fn, i)


# ---------------------------------------------------------------- evaluation
class Context:
    def __init__(self, image):
        self.image = image
        self.ends = facts(image)
        self.E, self.F, self.rows = {}, {}, {}
        for fn in BURN + TRANSFER:
            self.E[fn] = emitter_facts(image, self.ends, fn)
        for fl, (_, col, clo, srt, emi) in FLUSH.items():
            r = Roles(image, self.ends, fl)
            rc = Roles(image, self.ends, col)
            rs = Roles(image, self.ends, srt)
            self.F[fl] = {"free": r.got[0], "bigsort": r.got[1], "malloc": rc.got[0], "col_err": rc.got[1],
                          "memcmp": next(image.word(x[3]) for x in rs.rip_loads if x[1] == 0x8b and x[2] == 64),
                          "emitter": emi, "collect": col, "sort": srt, "closure": rc.direct[0],
                          "grow": rc.direct[2],
                          "grow_finish": Roles(image, self.ends, rc.direct[2]).direct[0]}
            self.E[fl] = self.E[emi]
            for body in (fl, col, self.F[fl]["closure"], srt, self.F[fl]["grow"]):
                self.rows[body] = ev.sweep(image, body, self.ends[body])
        for fn in BURN + TRANSFER:
            self.rows[fn] = ev.sweep(image, fn, self.ends[fn])


def machine_for(ctx, override=None):
    return PM(ctx.image, override or {})


def evaluate_one(ctx, m, c, mut=frozenset()):
    fn = c["fn"]
    E = ctx.E[fn]
    F = ctx.F.get(fn)
    got = run_case(m, c, E, F, fn)
    want = expected(c, E, F, mut)
    return compare(c, want, got), got, want


def digest(c, got):
    h = hashlib.sha256()
    h.update(repr((got["ret"], got["trace"], len(got["log"]))).encode())
    return h.hexdigest()[:12]


def describe(c):
    if c["kind"] == "flush":
        return f"spec={c['spec']:#x} f124={c['f124']:#x} f125={c['f125']:#x} pend={len(c['pending'])} map={len(c['order'])} nb={c['buckets']} items={c['items']} cap={c['cap']} len={c['len']} fail={c['fail_at']}"
    return f"spec={c['spec']:#x} f124={c['f124']:#x} cap={c['cap']} len={c['len']} odd={c['odd']} fail={c['fail_at']} value={'0' if not any(c['args'][-1]) else 'nz'}"


def outcome(c, got):
    if got["ret"]:
        return f"panic:{got['ret'][1]:x}:{got['ret'][2]}:{got['ret'][3]:#x}"
    n = len(got["log"]) - len(c["init"])
    return f"logged={n} grow={sum(1 for t in got['trace'] if t[0] == 'loggrow')} bigsort={sum(1 for t in got['trace'] if t[0] == 'bigsort')}"


# ---------------------------------------------------------------- controls
MODEL_MUTANTS = ("spec_ge0f", "f124_ignored", "zero_value_logs", "no_pad", "le_value", "swap_vt", "sort_always",
                 "sort_desc", "f125_ignored", "ignore_items", "zero_value_kept", "free_len",
                 "count_off", "loggrow_double_only", "swap_topics", "growvec_plus", "free_none")
POOL = 150


def jcc_sites(rows):
    for va, f in rows:
        if 0x70 <= f["op"] <= 0x7f:
            yield va, va, f["op"]
        elif 0x0f80 <= f["op"] <= 0x0f8f:
            yield va, va + 1, f["op"]


def detect_bytes(ctx, pool, fn, flipped_va, new):
    m = machine_for(ctx, {flipped_va: new})
    E, F = ctx.E[fn], ctx.F.get(fn)
    for c in pool:
        want = expected(c, E, F)
        try:
            got = run_case(m, c, E, F, fn)
        except (ToolError, Boundary, KeyError, IndexError, ValueError, struct.error):
            return True
        if not compare(c, want, got):
            return True
    return False


def run_controls(ctx, pools, rows):
    """Returns (list of control tuples, list of uncounted byte mutants)."""
    ctl, uncounted = [], []
    data = ctx.image.data
    for mut in MODEL_MUTANTS:
        fam = "flush" if mut in ("sort_always", "sort_desc", "f125_ignored", "ignore_items",
                                 "zero_value_kept", "free_len", "growvec_plus", "free_none") else "emit"
        hit = None
        for fn, pool in pools.items():
            if fam == "flush" and fn not in FLUSH:
                continue
            for c, got in pool:
                if not compare(c, expected(c, ctx.E[fn], ctx.F.get(fn), frozenset({mut})), got):
                    hit = c["id"]
                    break
            if hit:
                break
        ctl.append(("model", mut, hit is not None, hit or "-"))
    # byte corruption: invert every conditional branch of every evaluated body
    plan = []
    for fn in BURN + TRANSFER:
        plan.append((fn, fn, pools[fn]))
    for fl, (_, col, clo, srt, emi) in FLUSH.items():
        F = ctx.F[fl]
        for body in (fl, col, F["closure"], srt, F["grow"]):
            plan.append((fl, body, pools[fl]))
    for fn, body, pool in plan:
        pl = [c for c, _ in pool][:POOL]
        for va, at, op in jcc_sites(ctx.rows[body]):
            old = ctx.image.code(at, 1)[0]
            new = old ^ 1
            det = detect_bytes(ctx, pl, fn, at, new)
            name = f"{body:#x}+{at - body:#x}"
            if det:
                ctl.append(("byte", f"jcc-invert {name} {old:#04x}->{new:#04x}", True, "-"))
            else:
                uncounted.append(f"{name} (family {fn:#x})")
    # out-of-range / corrupted inputs
    a = ctx.E[0x2970eb0]
    bad = bytearray(data)
    bad[len(bad) // 2] ^= 1
    try:
        Image(bytes(bad))
        det = False
    except ToolError:
        det = True
    ctl.append(("input", "binary byte flip changes the SHA-256 check", det, "-"))
    try:
        ev.sweep(ctx.image, 0x2970eb0, ctx.ends[0x2970eb0] - 1)
        det = False
    except ToolError:
        det = True
    ctl.append(("input", "decode window ending one byte early overruns an instruction", det, "-"))
    try:
        emitter_facts(ctx.image, ctx.ends, 0x29710e0)  # the journal revert next to the emitters is not one
        det = False
    except (ToolError, KeyError, IndexError, ValueError):
        det = True
    ctl.append(("input", "emitter role discovery on a non-emitter body fails", det, "-"))
    try:
        Roles(ctx.image, ctx.ends, 0x2970eb1)
        det = False
    except (ToolError, KeyError):
        det = True
    ctl.append(("input", "address that is not an FDE start has no extent", det, "-"))
    pool = pools[0x2970eb0][:POOL]
    m = machine_for(ctx)
    det = False
    for c, _ in pool:
        try:
            got = run_case(m, dict(c), ctx.E[0x2970eb0], None, 0x29714f0)
            if not compare(c, expected(c, ctx.E[0x2970eb0], None), got):
                det = True
                break
        except (ToolError, Boundary, KeyError, IndexError, ValueError, struct.error):
            det = True
            break
    ctl.append(("input", "burn arguments fed to the transfer emitter", det, "-"))
    pool = pools[0x2972200][:POOL]
    det = False
    for c, got in pool:
        if c["spec"] >= SPEC_MIN and not c["f124"] and not c["f125"]:
            c2 = dict(c, spec=SPEC_MIN - 1)
            if not compare(c2, expected(c2, ctx.E[0x2972200], ctx.F[0x2972200]), got) and got["log"] != c["init"]:
                det = True
                break
    ctl.append(("input", "spec byte below 0x0e must not reach the emitter", det, "-"))
    return ctl, uncounted


# ---------------------------------------------------------------- evidence
def tsv_line(cols):
    return "\t".join(str(x) for x in cols) + "\n"


ROLE = {0x2972200: "flush A", 0x4324300: "flush B", 0x2970eb0: "burn log emitter A", 0x4322d00: "burn log emitter B",
        0x54631e0: "burn log emitter C", 0x29714f0: "transfer log emitter A", 0x54635f0: "transfer log emitter C"}


def write_static(ctx, out):
    image = ctx.image
    bodies = []
    for fn in BURN + TRANSFER:
        bodies.append((fn, ROLE[fn]))
    for fl, (fam, col, clo, srt, emi) in sorted(FLUSH.items()):
        F = ctx.F[fl]
        bodies += [(fl, ROLE[fl]), (col, f"collect {fam}"), (F["closure"], f"account lookup closure {fam}"),
                   (srt, f"insertion sort {fam}"), (F["grow"], f"record vec grow {fam}")]
    with open(out / "functions.tsv", "w") as fh:
        fh.write(tsv_line(("address", "fde_end", "size", "sha256_of_code", "role")))
        for a, role in sorted(bodies):
            e = ctx.ends[a]
            fh.write(tsv_line((f"{a:#x}", f"{e:#x}", e - a, hashlib.sha256(image.code(a, e - a)).hexdigest(), role)))
    with open(out / "callsites.tsv", "w") as fh:
        fh.write(tsv_line(("body", "site", "kind", "target_or_slot", "word_in_slot")))
        for a, _ in sorted(bodies):
            for site, kind, t in call_sites(ctx.rows[a]):
                word = f"{image.word(t):#x}" if kind == "got" else "-"
                fh.write(tsv_line((f"{a:#x}", f"{site:#x}", kind, f"{t:#x}", word)))
    with open(out / "constants.tsv", "w") as fh:
        fh.write(tsv_line(("body", "field", "address_or_slot", "value")))
        for fn in BURN + TRANSFER:
            E = ctx.E[fn]
            va_hi, va_lo, va_ent = E["const_vas"]
            fh.write(tsv_line((f"{fn:#x}", "topic block +0x00", f"{va_lo:#x}", E["c_lo"].hex())))
            fh.write(tsv_line((f"{fn:#x}", "topic block +0x10", f"{va_hi:#x}", E["c_hi"].hex())))
            fh.write(tsv_line((f"{fn:#x}", "entry +0x38", f"{va_ent:#x}", E["c_ent"].hex())))
            fh.write(tsv_line((f"{fn:#x}", "entry +0x18 odd data pointer", f"{E['vt_slots'][0]:#x}", f"{E['vt_odd']:#x}")))
            fh.write(tsv_line((f"{fn:#x}", "entry +0x18 even data pointer", f"{E['vt_slots'][1]:#x}", f"{E['vt_even']:#x}")))
            for k in ("malloc", "loggrow", "erra", "errb"):
                fh.write(tsv_line((f"{fn:#x}", f"word {k}", "-", f"{E[k]:#x}")))
        for fl in sorted(FLUSH):
            F = ctx.F[fl]
            for k in ("collect", "closure", "sort", "emitter", "grow", "grow_finish"):
                fh.write(tsv_line((f"{fl:#x}", f"callee {k}", "-", f"{F[k]:#x}")))
            for k in ("free", "bigsort", "malloc", "col_err", "memcmp"):
                fh.write(tsv_line((f"{fl:#x}", f"word {k}", "-", f"{F[k]:#x}")))


def generate(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    data = BINARY.read_bytes()
    image = Image(data)
    ctx = Context(image)
    write_static(ctx, out)
    m = machine_for(ctx)
    pools = {fn: [] for fn in BURN + TRANSFER + tuple(FLUSH)}
    stats = {}
    total = bad = 0
    pad_checked = pad_diff = 0
    with open(out / "cases.tsv", "w") as fh:
        fh.write(tsv_line(("case", "kind", "inputs", "outcome", "digest")))
        for c in all_cases():
            fn = c["fn"]
            ok, got, want = evaluate_one(ctx, m, c)
            total += 1
            s = stats.setdefault(f"{fn:#x}", {"cases": 0, "mismatch": 0, "logged": 0, "panic": 0, "noop": 0,
                                              "loggrow": 0, "growvec": 0, "bigsort": 0})
            s["cases"] += 1
            if not ok:
                s["mismatch"] += 1
                bad += 1
            o = outcome(c, got)
            if got["ret"]:
                s["panic"] += 1
            elif len(got["log"]) == len(c["init"]):
                s["noop"] += 1
            else:
                s["logged"] += 1
            s["loggrow"] += sum(1 for t in got["trace"] if t[0] == "loggrow")
            s["growvec"] += sum(1 for t in got["trace"] if t[0] == "growvec")
            s["bigsort"] += sum(1 for t in got["trace"] if t[0] == "bigsort")
            idx = int(c["id"].split("-")[1])
            if idx % 2 == 0:
                fh.write(tsv_line((c["id"], c["kind"], describe(c), o, digest(c, got))))
            if len(pools[fn]) < 400:
                pools[fn].append((c, got))
            if c["kind"] != "flush" and idx % 40 == 0 and not got["ret"]:
                c2 = dict(c, stack_fill=0xa3)
                g2 = run_case(m, c2, ctx.E[fn], ctx.F.get(fn), fn)
                pad_checked += 1
                same = all(a[:0x4c] == b[:0x4c] for a, b in zip(got["log"], g2["log"])) and got["trace"] == g2["trace"]
                if not same:
                    bad += 1
                if got["log"] != g2["log"]:
                    pad_diff += 1
    ctl, uncounted = run_controls(ctx, pools, ctx.rows)
    with open(out / "controls.tsv", "w") as fh:
        fh.write(tsv_line(("class", "control", "detected", "first_case")))
        for row in ctl:
            fh.write(tsv_line((row[0], row[1], int(row[2]), row[3])))
    detected = sum(1 for r in ctl if r[2])
    summary = {"binary_sha256": SHA256, "cases": total, "mismatches": bad, "per_body": stats,
               "pad_sensitivity": {"stack_fill_reruns": pad_checked, "reruns_with_different_pad_bytes": pad_diff,
                                   "masked_bytes": "entry +0x4c..+0x50 (stale stack word)"},
               "controls": {"counted": len(ctl), "detected": detected, "byte_mutants_not_detected": len(uncounted),
                            "byte_mutants_not_detected_sites": uncounted}}
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": total + pad_checked, "negative_controls": len(ctl),
                                                  "negative_detected": detected, "mismatches": bad},
                                                 indent=1, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    s = generate(args.out)
    print(json.dumps({k: s[k] for k in ("cases", "mismatches")}), json.dumps(s["controls"]["counted"]),
          json.dumps(s["controls"]["detected"]))
    return 0 if s["mismatches"] == 0 and s["controls"]["counted"] == s["controls"]["detected"] else 1


if __name__ == "__main__":
    sys.exit(main())
