#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM journaled-state account operations around the account-map lookup 0x3ed7e80.

The journaled state `J` (a revm-style JournaledState) holds a logs Vec {cap, ptr, len} at +0x00 (0x50-byte
entries), a journal Vec {cap, ptr +0x20, len +0x28} at +0x18 (0x58-byte entries: tag byte, then payload), a
checkpoint minimum at +0x40, the account hashbrown map header {ctrl, mask, growth, items, hash key} at +0xc8 with
0xa8-byte buckets (20-byte address, account fields from +0x18), the call depth at +0x118, a flag byte at +0x124 and
the spec id byte at +0x126.  This tool runs the real machine code of the lookup 0x3ed7e80, the native transfer
0x4322860, the code setter 0x4323110, the Transfer-log emitter 0x4323270, the create-account checkpoint 0x43234e0
and the checkpoint revert 0x4322f30 with a small concrete x86-64 evaluator (imported from the merged storage-load
tool; the binary is never executed) and compares every case with one pure-Python reconstruction of the accounting:
touch rules, balance borrow/carry rules, journal tags 2/4/7/0xb, the ERC-20 style Transfer log, the empty-code
collision rule and the exact order of side effects before each failure.  Negative controls show that wrong
reconstructions, corrupted code bytes and out-of-range inputs are detected.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_storage_cache_load115 as ev  # noqa: E402

ToolError, Boundary, fail, Image, Stream = ev.ToolError, ev.Boundary, ev.fail, ev.Image, ev.Stream
BINARY, SHA256, M64, M256 = ev.BINARY, ev.SHA256, ev.M64, (1 << 256) - 1
STACK_TOP, FILL_STACK = ev.STACK_TOP, 0x5c

LOOKUP, TRANSFER, SET_CODE, LOG, CREATE, REVERT = 0x3ed7e80, 0x4322860, 0x4323110, 0x4323270, 0x43234e0, 0x4322f30
FUNCS = (LOOKUP, TRANSFER, SET_CODE, LOG, CREATE, REVERT)
SEED_GOT = 0x64dfa78
GOT = {"alloc": 0x64df480, "oom_a": 0x64df490, "oom_b": 0x64df498, "panic_overflow": 0x64df520, "panic_unwrap": 0x64df830,
       "free": 0x64df4a0, "log_grow": 0x64dfa48, "arc_drop": 0x64e4fa8, "journal_grow": 0x64e68e8,
       "revert_entry": 0x64e6d68, "vt_even": 0x64df8c0, "vt_odd": 0x64df8c8}
ACCT, ENTRY, LOGE = 0xa8, 0x58, 0x50
PANIC_STR = {"transfer_from": 0x6485c98, "transfer_to": 0x6485cb0, "transfer_to_zero": 0x6485cc8, "transfer_same": 0x6485ce0,
             "set_code": 0x6485cf8, "create_target": 0x6485d10, "create_caller": 0x6485d28, "depth": 0x6485c38}
PANIC_SITES = {  # lea rdi,[rip+rel32] immediately before the panic call
    0x4322c6b: "transfer_same", 0x4322cd5: "transfer_from", 0x4322ce2: "transfer_to_zero", 0x4322cef: "transfer_to",
    0x4323225: "set_code", 0x4323837: "create_target", 0x4323844: "create_caller", 0x4323851: "depth"}
CONST_HASH_LO, CONST_HASH_HI = 0x4537f0, 0x452020  # compared with account +0x48 / +0x58 (revm KECCAK_EMPTY halves)
LOG_TOPIC0_LO, LOG_TOPIC0_HI, LOG_SENDER = 0x4581e0, 0x4581f0, 0x7ca51f

J_AT = 0x7d00_0000_1000
J_SIZE = 0x130
OUT_AT = 0x7d00_0010_0000
ADDR_AT = 0x7d00_0020_0000  # caller / target / from / to 20-byte inputs, 0x40 apart
VAL_AT = 0x7d00_0030_0000
CP_AT = 0x7d00_0040_0000
ARC_AT = 0x7d00_0050_0000
HASH_AT = 0x7d00_0060_0000
TABLE_AT = 0x7d00_0400_0000
TABLE_SIZE = 0x40000
HEAP_AT = 0x7d00_1000_0000
HEAP_SIZE = 0x40000
HEAP_FILL, JFILL, LFILL = 0x31, 0x77, 0x66
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]
# account bucket offsets (bucket = 0x18 address block + account fields; P = bucket + 0x18)
B_BAL, B_HASH, B_NONCE, B_ARC, B_STATUS = 0x40, 0x60, 0x80, 0x88, 0xa4


def decode(code, va):
    """ev.decode plus the forms this path needs: lock prefix, por, movmskps and `not r/m8` (f6 /2)."""
    code = bytes(code)
    if code[0] == 0xf0:
        form = ev.decode(code[1:] + b"\0", va + 1)
        form["len"] += 1
        form["bytes"] = code[:form["len"]]
        form["lock"] = True
        return form
    p = 0
    while code[p] in (0x66, 0x2e, 0xf3, 0xf2, 0x64):
        p += 1
    p += 1 if 0x40 <= code[p] <= 0x4f else 0
    if code[p] == 0x0f and code[p + 1] in (0xeb, 0x50):
        swap = {0xeb: 0xef, 0x50: 0xd7}[code[p + 1]]
        form = ev.decode(code[:p + 1] + bytes([swap]) + code[p + 2:], va)
        form["op"] = 0x0f00 | code[p + 1]
        form["bytes"] = code[:form["len"]]
        return form
    if code[p] == 0xf6 and (code[p + 1] >> 3) & 7 == 2:
        form = ev.decode(code[:p + 1] + bytes([code[p + 1] & 0xc7]) + code[p + 2:], va)
        form["op"], form["len"] = 0xf602, form["len"] - 1
        form["bytes"] = code[:form["len"]]
        return form
    return ev.decode(code, va)


class Mach(ev.TraceMachine):
    def fetch(self, va):
        form = self.cache.get(va)
        if form is None:
            code = bytearray(self.image.code(va, 16))
            for i in range(16):
                if va + i in self.override:
                    code[i] = self.override[va + i]
            form = decode(bytes(code), va)
            self.cache[va] = form
        return form

    def step(self, va):
        f = self.fetch(va)
        op = f["op"]
        if op not in (0x0f50, 0x0feb, 0xf602):
            return super().step(va)
        self.seen.add(va)
        if op == 0x0feb:
            self.xmm[f["reg"]] |= self.xmm[f["rm"][1]]
        elif op == 0x0f50:
            v = self.xmm[f["rm"][1]]
            self.set_reg(f["reg"], 32, sum(1 << i for i in range(4) if (v >> (32 * i + 31)) & 1), f)
        else:
            self.put(f["rm"], 8, ~self.get(f["rm"], 8, f, va) & 0xff, f, va)
        return (va + f["len"]) & M64


def le(n, k):
    return (n & ((1 << (8 * k)) - 1)).to_bytes(k, "little")


def balance_of(b):
    return int.from_bytes(b[B_BAL:B_BAL + 32], "little")


def put_balance(b, v):
    b[B_BAL:B_BAL + 32] = v.to_bytes(32, "little")


# ---------------------------------------------------------------- state and reconstruction
class ModelPanic(Exception):
    def __init__(self, name):
        super().__init__(name)
        self.name = name


class St:
    """Logical state of the journaled state plus the allocator sequence."""

    def __init__(self, c, mut):
        self.mut = mut
        self.k0, self.g0 = c["k0"], c["g0"]
        self.depth, self.spec, self.flag, self.j40 = c["depth"], c["spec"], c["flag"], c["j40"]
        self.journal, self.jcap = [bytearray(e) for e in c["journal"]], c["jcap"]
        self.logs, self.lcap = [bytearray(e) for e in c["logs"]], c["lcap"]
        self.slots = {i: bytearray(b) for i, b in c["slots"].items()}
        self.mask, self.ctrl_at = c["mask"], c["ctrl_at"]
        self.table = c["table"]
        self.heap = HEAP_AT + c["heap_used"]
        self.blocks = {}
        self.events = []

    def alloc(self, n):
        at = self.heap
        self.heap += (n + 15) & ~15
        return at

    def lookup(self, addr):
        """0x3ed7e80: slot index of the bucket holding `addr`, or None (also when the map is empty)."""
        t = self.table
        if t.items == 0:
            return None
        h = ev.hash_addr(addr, self.k0, self.g0)
        i = t.find(h, addr, lambda s, a: bytes(s[:20]) == a)
        return None if i is None else i

    def acct(self, i):
        return self.slots[i]

    def push(self, tag, payload, at=1):
        if len(self.journal) == self.jcap:
            self.events.append(("journal_grow", len(self.journal)))
            self.jcap = ev.grow_cap(self.jcap)
            self.jptr = self.alloc(ENTRY * self.jcap)
        e = bytearray([JFILL]) * ENTRY
        e[0] = tag
        e[at:at + len(payload)] = payload
        self.journal.append(e)
        return e

    def touch(self, i, addr):
        b = self.slots[i]
        if not b[B_STATUS] & 4:
            self.push(2, addr)
            b[B_STATUS] |= 4


def m_log(st, frm, to, val, consts):
    """0x4323270: ERC-20 style Transfer(from, to, value) log pushed when spec >= 0xe, flag +0x124 clear, value != 0."""
    gate_spec = 0xe if "log_spec" not in st.mut else 0xd
    if st.spec < gate_spec or (st.flag != 0 and "log_flag" not in st.mut) or (val == 0 and "log_zero" not in st.mut):
        return
    st.events.append(("alloc", 0x60))
    if st.oom == 1:
        raise ModelPanic("oom_a")
    blk1 = st.alloc(0x60)
    st.events.append(("alloc", 0x20))
    if st.oom == 2:
        raise ModelPanic("oom_b")
    blk2 = st.alloc(0x20)
    topic = bytes(12) + frm
    topic2 = bytes(12) + to
    if "log_topic_swap" in st.mut:
        topic, topic2 = topic2, topic
    st.blocks[blk1] = consts["topic0"] + topic + topic2
    st.blocks[blk2] = val.to_bytes(32, "big") if "log_le" not in st.mut else val.to_bytes(32, "little")
    e = bytearray(LOGE)
    for at, v in ((0, 3), (8, blk1), (0x10, 3), (0x18, consts["vt_even"]), (0x20, blk2), (0x28, 0x20), (0x30, blk2 | 1)):
        e[at:at + 8] = le(v, 8)
    e[0x38:0x48] = consts["sender16"]
    e[0x48:0x4c] = consts["sender_imm"]
    e[0x4c:0x50] = bytes([FILL_STACK]) * 4
    if len(st.logs) == st.lcap:
        st.events.append(("log_grow", len(st.logs)))
        st.lcap = ev.grow_cap(st.lcap)
        st.lptr = st.alloc(LOGE * st.lcap)
    st.logs.append(e)


def m_transfer(st, frm, to, val, consts):
    """0x4322860: native transfer; returns 3 = Ok, 0 = insufficient balance, 1 = receiver overflow."""
    if frm == to:
        i = st.lookup(frm)
        if i is None:
            raise ModelPanic("transfer_same")
        return 3 if balance_of(st.slots[i]) >= val or "same_always_ok" in st.mut else 0
    if val == 0:
        i = st.lookup(to)
        if i is None:
            raise ModelPanic("transfer_to_zero")
        if "zero_no_touch" not in st.mut:
            st.touch(i, to)
        return 3
    i = st.lookup(frm)
    if i is None:
        raise ModelPanic("transfer_from")
    st.touch(i, frm)
    bal = balance_of(st.slots[i])
    if bal < val and "no_borrow_check" not in st.mut:
        return 0
    put_balance(st.slots[i], (bal - val) & M256)
    j = st.lookup(to)
    if j is None:
        raise ModelPanic("transfer_to")
    st.touch(j, to)
    nb = balance_of(st.slots[j]) + val
    if nb > M256 and "no_carry_check" not in st.mut:
        return 1
    put_balance(st.slots[j], nb & M256)
    st.push(4, frm + to + bytes([FILL_STACK]) * 7 + val.to_bytes(32, "little"))
    m_log(st, frm, to, val, consts)
    return 3


def arc_release(st, i):
    """Drop the Arc held by account bucket i: decrement the strong count, free when it reaches zero."""
    b = st.slots[i]
    ptr = int.from_bytes(b[B_ARC:B_ARC + 8], "little")
    if ptr:
        st.arc[ptr] = (st.arc[ptr] - 1) & M64
        if st.arc[ptr] == 0 or "arc_always_drop" in st.mut:
            st.events.append(("arc_drop", i))


def m_set_code(st, addr, new_arc, code_hash):
    """0x4323110: touch, journal CodeChange (tag 0xb), replace code hash (+0x48) and code Arc (+0x70)."""
    i = st.lookup(addr)
    if i is None:
        raise ModelPanic("set_code")
    st.touch(i, addr)
    st.push(0xb if "tag_b" not in st.mut else 0xa, addr)
    b = st.slots[i]
    b[B_HASH:B_HASH + 32] = code_hash
    arc_release(st, i)
    b[B_ARC:B_ARC + 8] = le(new_arc, 8)


def m_create(st, caller, target, val, spec, consts):
    """0x43234e0: checkpoint + create-account accounting; returns ("ok", cp) or ("err", code)."""
    cp = (len(st.logs), len(st.journal), st.j40)
    if st.depth == M64 and "no_depth_check" not in st.mut:
        raise ModelPanic("depth")
    st.depth = (st.depth + 1) & M64
    i = st.lookup(target)
    if i is None:
        raise ModelPanic("create_target")
    b = st.slots[i]
    empty = bytes(b[B_HASH:B_HASH + 32]) == consts["empty_hash"]
    nonce = int.from_bytes(b[B_NONCE:B_NONCE + 8], "little")
    if not (empty and (nonce == 0 or "nonce_ignored" in st.mut)):
        st.events.append(("revert", cp))
        return ("err", 2)
    old = b[B_STATUS]
    b[B_STATUS] = old | 0x81
    st.push(7, target + bytes([(~old) & 1]))
    arc_release(st, i)
    b[B_ARC:B_ARC + 8] = bytes(8)
    if spec > (2 if "spec_gate" not in st.mut else 3):
        b[B_NONCE:B_NONCE + 8] = le(1, 8)
    if not b[B_STATUS] & 4:
        st.push(2, target)
        b[B_STATUS] |= 4
    if val != 0:
        nb = balance_of(b) + val
        if nb > M256:
            st.events.append(("revert", cp))
            return ("err", 1)
        put_balance(b, nb)
        k = st.lookup(caller)
        if k is None:
            raise ModelPanic("create_caller")
        put_balance(st.slots[k], (balance_of(st.slots[k]) - val) & M256)
        st.push(4, caller + target + bytes([FILL_STACK]) * 7 + val.to_bytes(32, "little"))
        m_log(st, caller, target, val, consts)
    return ("ok", cp)


def m_revert(st, cp, consts):
    """0x4322f30: unwind to a checkpoint: depth-1, drop logs, min the +0x40 word, undo journal entries top-down."""
    st.depth = max(st.depth - 1, 0) if "depth_wrap" not in st.mut else (st.depth - 1) & M64
    spec = st.spec
    if cp[0] <= len(st.logs):
        for k in range(cp[0], len(st.logs)):
            e = st.logs[k]
            if int.from_bytes(e[0:8], "little"):
                st.events.append(("topics_free", int.from_bytes(e[8:16], "little"), int.from_bytes(e[0:8], "little") << 5))
            st.events.append(("bytes_drop", k, int.from_bytes(e[0x20:0x28], "little"), int.from_bytes(e[0x28:0x30], "little")))
        del st.logs[cp[0]:]
    if cp[2] <= st.j40:
        st.j40 = cp[2]
    if cp[1] < len(st.journal):
        top = st.journal[cp[1]:]
        del st.journal[cp[1]:]
        for e in reversed(top):
            if e[0] == 0xc:
                break
            st.events.append(("revert_entry", e[0], hashlib.sha256(bytes(e)).hexdigest()[:12],
                              int(spec >= (3 if "revert_spec" not in st.mut else 4))))


# ---------------------------------------------------------------- memory image of one case
def round16(n):
    return (n + 15) & ~15


def build_j(c, jlen, jptr, jcap, llen, lptr, lcap, depth, j40):
    j = bytearray([0x5a]) * J_SIZE
    for at, v in ((0, lcap), (8, lptr), (0x10, llen), (0x18, jcap), (0x20, jptr), (0x28, jlen), (0x40, j40),
                  (0xc8, c["ctrl_at"]), (0xd0, c["mask"]), (0xd8, c["table"].growth_left), (0xe0, c["table"].items),
                  (0xe8, c["k0"]), (0x118, depth)):
        j[at:at + 8] = le(v, 8)
    j[0x124] = c["flag"]
    j[0x126] = c["spec"]
    return j


def finish(c):
    t = c["table"]
    c["mask"] = t.mask
    nb = t.mask + 1
    c["ctrl_at"] = ev.EMPTY_CTRL if t.static else TABLE_AT + nb * ACCT
    c["jptr"] = HEAP_AT
    c["lptr"] = HEAP_AT + round16(max(1, c["jcap"]) * ENTRY)
    c["heap_used"] = round16(max(1, c["jcap"]) * ENTRY) + round16(max(1, c["lcap"]) * LOGE)
    c["jbytes"] = bytes(build_j(c, len(c["journal"]), c["jptr"], c["jcap"], len(c["logs"]), c["lptr"], c["lcap"],
                                c["depth"], c["j40"]))
    return c


def setup(m, c, consts):
    image = m.image
    events = []
    m.regions[0][2][:] = bytes([FILL_STACK]) * len(m.regions[0][2])
    seeds = m.add_region(ev.SEED_AT, 0x40)
    ev.put(seeds, 0, 8, c["g0"])
    tables = ev.Heap(m, TABLE_AT, TABLE_SIZE, HEAP_FILL)
    heap = ev.Heap(m, HEAP_AT, HEAP_SIZE, HEAP_FILL)
    m.add_region(J_AT, J_SIZE, c["jbytes"])
    ev.write_table(m, tables, c["table"], J_AT + 0xc8, bytes)
    jptr, lptr = heap.alloc(max(1, c["jcap"]) * ENTRY), heap.alloc(max(1, c["lcap"]) * LOGE)
    if (jptr, lptr) != (c["jptr"], c["lptr"]):
        fail("journal/log buffer placement drifted")
    for k in range(max(1, c["jcap"]) * ENTRY):
        m.store(jptr + k, 1, JFILL)
    for k in range(max(1, c["lcap"]) * LOGE):
        m.store(lptr + k, 1, LFILL)
    for j, e in enumerate(c["journal"]):
        for k in range(ENTRY):
            m.store(jptr + ENTRY * j + k, 1, e[k])
    for j, e in enumerate(c["logs"]):
        for k in range(LOGE):
            m.store(lptr + LOGE * j + k, 1, e[k])
    for name, data in c["inputs"].items():
        m.add_region(INPUT_AT[name], 0x40, data + bytes([0x44]) * (0x40 - len(data)))
    m.add_region(OUT_AT, 0x40, bytes([0x44]) * 0x40)
    arcs = m.add_region(ARC_AT, 0x1000)
    for ptr, count in c["arcs"].items():
        ev.put(arcs, ptr - ARC_AT, 8, count)
    ctrl = c["ctrl_at"]

    def jvec_grow(base, size, label):
        def grow(mc):
            if mc.regs[7] != base:
                fail(f"{label} grow argument {mc.regs[7]:#x}")
            cap, ptr, ln = (mc.load(base + 8 * k, 8) for k in range(3))
            if ln != cap:
                fail(f"{label} grow called with spare capacity")
            events.append((label, ln))
            ncap = ev.grow_cap(cap)
            nptr = heap.alloc(size * ncap)
            for k in range(size * ncap):
                mc.store(nptr + k, 1, mc.load(ptr + k, 1) if k < size * ln else (JFILL if size == ENTRY else LFILL))
            mc.store(base, 8, ncap)
            mc.store(base + 8, 8, nptr)
        return grow

    def alloc(mc):
        size = mc.regs[7]
        events.append(("alloc", size))
        if c["oom"] and size == (0x60 if c["oom"] == 1 else 0x20):
            mc.regs[0] = 0
            return
        mc.regs[0] = heap.alloc(size)
        for k in range(size):
            mc.store(mc.regs[0] + k, 1, HEAP_FILL)

    def boundary(kind):
        def stub(mc):
            raise Boundary(kind, mc.regs)
        return stub

    def arc_drop(mc):
        bucket = mc.regs[7] - B_ARC
        events.append(("arc_drop", (ctrl - bucket) // ACCT - 1))

    def revert_stub(mc):
        events.append(("revert", tuple(mc.load(mc.regs[6] + 8 * k, 8) for k in range(3))))

    def free(mc):
        events.append(("topics_free", mc.regs[7], mc.regs[6]))

    def bytes_drop(mc):
        events.append(("bytes_drop", (mc.regs[7] - 0x30 - mc.load(J_AT + 8, 8)) // LOGE, mc.regs[6], mc.regs[2]))

    def revert_entry(mc):
        raw = bytes(mc.load(mc.regs[7] + k, 1) for k in range(ENTRY))
        events.append(("revert_entry", raw[0], hashlib.sha256(raw).hexdigest()[:12], mc.regs[1] & 0xff))

    w = image.word
    m.stubs = {w(GOT["alloc"]): alloc, w(GOT["oom_a"]): boundary("oom_a"), w(GOT["oom_b"]): boundary("oom_b"),
               w(GOT["panic_overflow"]): boundary("panic"), w(GOT["panic_unwrap"]): boundary("panic"),
               w(GOT["free"]): free, w(GOT["log_grow"]): jvec_grow(J_AT, LOGE, "log_grow"),
               w(GOT["arc_drop"]): arc_drop, w(GOT["journal_grow"]): jvec_grow(J_AT + 0x18, ENTRY, "journal_grow"),
               w(GOT["revert_entry"]): revert_entry,
               image.word(consts["vt_even"] + 0x20): bytes_drop, image.word(consts["vt_odd"] + 0x20): bytes_drop}
    if c["fn"] == "create":
        m.stubs[REVERT] = revert_stub
    return events


INPUT_AT = {"a": ADDR_AT, "b": ADDR_AT + 0x40, "v": VAL_AT, "h": HASH_AT, "cp": CP_AT}


def read_consts(image):
    sender_imm = image.code(0x43233ed, 4)
    if image.code(0x43233e9, 4) != bytes.fromhex("c7442450"):
        fail("expected movl imm32 to 0x50(%rsp) at 0x43233e9")
    return {"topic0": image.read(LOG_TOPIC0_LO, 16) + image.read(LOG_TOPIC0_HI, 16),
            "empty_hash": image.read(CONST_HASH_LO, 16) + image.read(CONST_HASH_HI, 16),
            "sender16": image.read(LOG_SENDER, 16), "sender_imm": sender_imm,
            "vt_even": image.word(GOT["vt_even"]), "vt_odd": image.word(GOT["vt_odd"])}


def region(m, at):
    return next(buf for lo, hi, buf in m.regions if lo == at)


def snapshot(m, c, events, blocks):
    jraw = bytes(region(m, J_AT))
    w = lambda at: int.from_bytes(jraw[at:at + 8], "little")
    jptr, jlen, lptr, llen = w(0x20), w(0x28), w(8), w(0x10)
    got = {"j": jraw, "events": tuple(events)}
    got["journal"] = tuple(bytes(m.load(jptr + ENTRY * j + k, 1) for k in range(ENTRY)) for j in range(jlen))
    got["logs"] = tuple(bytes(m.load(lptr + LOGE * j + k, 1) for k in range(LOGE)) for j in range(llen))
    t = c["table"]
    ctrl = c["ctrl_at"]
    got["slots"] = tuple((i, bytes(m.load(ctrl - (i + 1) * ACCT + k, 1) for k in range(ACCT))) for i in sorted(t.slots))
    got["blocks"] = tuple((a, bytes(m.load(a + k, 1) for k in range(len(blocks[a])))) for a in sorted(blocks))
    got["arcs"] = tuple((p, m.load(p, 8)) for p in sorted(c["arcs"]))
    got["inputs"] = {name: bytes(region(m, INPUT_AT[name])) for name in c["inputs"]}
    got["out"] = bytes(region(m, OUT_AT))
    return got


def run_case(m, c, consts, blocks):
    m.reset()
    events = setup(m, c, consts)
    before = {name: bytes(region(m, INPUT_AT[name])) for name in c["inputs"]}
    for k, v in zip((3, 12, 13, 14, 15, 5), SAVED):
        m.regs[k] = v
    r, fn = m.regs, c["fn"]
    A, B, V, H = INPUT_AT["a"], INPUT_AT["b"], INPUT_AT["v"], INPUT_AT["h"]
    if fn == "lookup":
        r[7], r[6], start = J_AT + 0xc8, A, LOOKUP
    elif fn == "transfer":
        r[7], r[6], r[2], r[1], start = J_AT, A, B, V, TRANSFER
    elif fn == "set_code":
        r[7], r[6], r[2], r[1], start = J_AT, A, c["new_arc"], H, SET_CODE
    elif fn == "log":
        r[7], r[6], r[2], r[1], start = J_AT, A, B, V, LOG
    elif fn == "create":
        r[7], r[6], r[2], r[1], r[8], r[9], start = OUT_AT, J_AT, A, B, V, c["spec_arg"], CREATE
    elif fn == "revert":
        r[7], r[6], start = J_AT, INPUT_AT["cp"], REVERT
    else:
        fail(f"unknown function {fn}")
    boundary = None
    try:
        m.run(start, limit=400000)
    except Boundary as b:
        boundary = (b.kind, b.regs[7] if b.kind == "panic" else None)
    got = snapshot(m, c, events, blocks)
    got["boundary"] = boundary
    got["inputs_ok"] = got.pop("inputs") == before
    if boundary is None:
        got["regs_ok"] = [m.regs[k] for k in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == STACK_TOP - 0x100
        got["ret"] = m.regs[0] if fn == "lookup" else (m.regs[0] & 0xff if fn == "transfer" else None)
    return got


def model(c, mut, consts):
    st = St(c, mut)
    st.arc, st.oom, st.jptr, st.lptr = dict(c["arcs"]), c["oom"], c["jptr"], c["lptr"]
    inp = c["inputs"]
    fn, ret, boundary = c["fn"], None, None
    try:
        if fn == "lookup":
            i = st.lookup(inp["a"][:20])
            ret = 0 if i is None else c["ctrl_at"] - (i + 1) * ACCT + 0x18
        elif fn == "transfer":
            ret = m_transfer(st, inp["a"][:20], inp["b"][:20], int.from_bytes(inp["v"], "little"), consts)
        elif fn == "set_code":
            m_set_code(st, inp["a"][:20], c["new_arc"], inp["h"])
        elif fn == "log":
            m_log(st, inp["a"][:20], inp["b"][:20], int.from_bytes(inp["v"], "little"), consts)
        elif fn == "create":
            ret = m_create(st, inp["a"][:20], inp["b"][:20], int.from_bytes(inp["v"], "little"), c["spec_arg"] & 0xff, consts)
        elif fn == "revert":
            cp = tuple(int.from_bytes(inp["cp"][8 * k:8 * k + 8], "little") for k in range(3))
            m_revert(st, cp, consts)
    except ModelPanic as p:
        boundary = ("panic", PANIC_STR[p.name]) if p.name in PANIC_STR else (p.name, None)
    out = bytearray([0x44]) * 0x40
    if fn == "create" and boundary is None:
        if ret[0] == "ok":
            out[0] = 0
            for k, v in enumerate(ret[1]):
                out[8 + 8 * k:16 + 8 * k] = le(v, 8)
        else:
            out[0], out[1] = 1, ret[1] if "err_code" not in mut else 0
    want = {"boundary": boundary, "events": tuple(st.events), "out": bytes(out), "ret": None, "inputs_ok": True,
            "regs_ok": True}
    if boundary is None and fn in ("lookup", "transfer"):
        want["ret"] = ret
    want["j"] = bytes(build_j(c, len(st.journal), st.jptr, st.jcap, len(st.logs), st.lptr, st.lcap, st.depth, st.j40))
    want["journal"] = tuple(bytes(e) for e in st.journal)
    want["logs"] = tuple(bytes(e) for e in st.logs)
    want["slots"] = tuple((i, bytes(st.slots[i])) for i in sorted(c["table"].slots))
    want["blocks"] = tuple((a, st.blocks[a]) for a in sorted(st.blocks))
    want["arcs"] = tuple((p, st.arc[p]) for p in sorted(c["arcs"]))
    if boundary is not None:
        del want["regs_ok"], want["ret"]
    return want


def compare(want, got):
    keys = ("boundary", "events", "j", "journal", "logs", "slots", "blocks", "arcs", "inputs_ok", "out")
    if any(want[k] != got[k] for k in keys):
        return False
    return want["boundary"] is not None or (want["ret"] == got["ret"] and got["regs_ok"])


# ---------------------------------------------------------------- deterministic cases
def rand_u256(s, near=None):
    kind = s.below(6)
    if kind == 0:
        return 0
    if kind == 1:
        return s.below(1000)
    if kind == 2:
        return int.from_bytes(s.take(32), "little")
    if kind == 3:
        return int.from_bytes(s.take(8), "little")
    if kind == 4:
        return M256 - s.below(50)
    return int.from_bytes(s.take(16), "little") << 128 | (near or 0)


def make_world(s, shape):
    """Account map: `shape` picks a sparse small table, a dense 32-bucket table (full probe groups) or an empty map."""
    consts = CONSTS
    g0 = int.from_bytes(s.take(8), "little")
    k0 = int.from_bytes(s.take(8), "little")
    n = {"empty": 0, "small": 1 + s.below(5), "dense": 20 + s.below(7)}[shape]
    nb = 8 if shape == "small" and n <= 4 else (16 if shape == "small" else 32)
    t = ev.Table(ACCT, k0)
    arcs, slots, addrs = {}, {}, []
    if n:
        t.mask, t.static, t.ctrl, t.slots = nb - 1, False, bytearray(b"\xff" * (nb + 16)), {}
        t.growth_left = ev.full_cap(t.mask)
    for _ in range(n):
        addr = s.take(20)
        while addr in addrs:
            addr = s.take(20)
        b = bytearray(s.take(ACCT))
        b[:20] = addr
        put_balance(b, rand_u256(s))
        r = s.below(10)
        b[B_HASH:B_HASH + 32] = consts["empty_hash"] if r < 5 else (bytes(32) if r < 6 else s.take(32))
        b[B_NONCE:B_NONCE + 8] = le(0 if s.below(10) < 6 else s.below(5) + 1, 8)
        b[B_STATUS] = s.pick((0, 1, 4, 5, 0x80, 0x81, 0x84, 0x85, 0x24, s.below(256)))
        i = len(arcs)
        r = s.below(3)
        ptr = 0 if r == 0 else ARC_AT + 0x10 * (len(addrs) + 1)
        b[B_ARC:B_ARC + 8] = le(ptr, 8)
        if ptr:
            arcs[ptr] = 1 if r == 1 else 2 + s.below(3)
        h = ev.hash_addr(addr, k0, g0)
        slot = t.insert_slot(h)
        t.put(slot, h, bytes(b))
        slots[slot] = bytes(b)
        addrs.append(addr)
    return {"g0": g0, "k0": k0, "table": t, "slots": slots, "addrs": addrs, "arcs": arcs}


def bucket_of(world, addr):
    return next((i, b) for i, b in world["slots"].items() if bytes(b[:20]) == addr)


def rand_journal(s, n, tags):
    out = []
    for _ in range(n):
        e = bytearray(s.take(ENTRY))
        e[0] = s.pick(tags)
        out.append(bytes(e))
    return out


def rand_logs(s, n):
    out = []
    for _ in range(n):
        e = bytearray(s.take(LOGE))
        e[0:8] = le(s.pick((0, 1, 3, 4, 7)), 8)
        e[8:16] = le(0x7d00_2000_0000 + 0x100 * s.below(64), 8)
        e[0x18:0x20] = le(s.pick((CONSTS["vt_even"], CONSTS["vt_odd"])), 8)
        out.append(bytes(e))
    return out


def base_case(s, fn, shape):
    w = make_world(s, shape)
    jcap = 1 + s.below(6)
    jlen = s.below(jcap + 1) if s.below(4) else jcap  # a full journal one time in four-plus
    lcap = 1 + s.below(4)
    llen = s.below(lcap + 1) if s.below(3) else lcap
    c = {"fn": fn, "k0": w["k0"], "g0": w["g0"], "table": w["table"], "slots": w["slots"], "arcs": dict(w["arcs"]),
         "addrs": w["addrs"], "world": w,
         "depth": s.pick((0, 1, 2, s.below(1 << 16), M64, M64 - 1)), "spec": s.pick((0, 2, 3, 0xd, 0xe, 0xf, 0x10, s.below(256))),
         "flag": s.pick((0, 0, 0, 1, s.below(256))), "j40": s.pick((0, 3, s.below(16), M64)),
         "journal": rand_journal(s, jlen, (0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 0xc, 0xd)), "jcap": jcap,
         "logs": rand_logs(s, llen), "lcap": lcap, "oom": 0, "new_arc": 0, "spec_arg": 0, "inputs": {}}
    return c


def pick_addr(s, c, absent_one_in=0):
    if absent_one_in and s.below(absent_one_in) == 0 or not c["addrs"]:
        return s.take(20)
    return s.pick(c["addrs"])


def amount_for(s, c, frm, to, scenario):
    fb = balance_of(bucket_of(c["world"], frm)[1]) if frm in c["addrs"] else 0
    tb = balance_of(bucket_of(c["world"], to)[1]) if to in c["addrs"] else 0
    if scenario == "zero":
        return 0
    if scenario == "exact":
        return fb
    if scenario == "short":
        return fb + 1 if fb < M256 else M256
    if scenario == "overflow":
        return min(fb, M256 - tb + 1) if tb else fb
    if scenario == "small":
        return min(fb, 1 + s.below(1000))
    return min(fb, rand_u256(s))


def case_transfer(s):
    shape = s.pick(("small", "small", "dense", "dense", "empty"))
    c = base_case(s, "transfer", shape)
    scen = s.pick(("zero", "exact", "short", "overflow", "small", "any", "same", "absent_from", "absent_to", "any"))
    frm = pick_addr(s, c, 12 if scen != "absent_from" else 1)
    to = frm if scen == "same" else pick_addr(s, c, 12 if scen != "absent_to" else 1)
    if scen in ("overflow",) and c["addrs"]:
        # make the receiver nearly full and the sender rich enough
        for a, hi in ((to, True), (frm, True)):
            if a in c["addrs"]:
                i, b = bucket_of(c["world"], a)
                nb = bytearray(b)
                put_balance(nb, M256 - s.below(100) if a == to else M256 // 2 + s.below(1000))
                c["slots"][i] = bytes(nb)
                c["table"].slots[i] = bytes(nb)
    val = amount_for(s, c, frm, to, scen)
    c["inputs"] = {"a": frm, "b": to, "v": val.to_bytes(32, "little")}
    c["scenario"] = scen
    if s.below(8) == 0:
        c["oom"] = 1 + s.below(2)
    return c


def case_log(s):
    c = base_case(s, "log", "empty")
    frm, to = s.take(20), s.take(20)
    val = s.pick((0, 1, rand_u256(s), M256))
    c["inputs"] = {"a": frm, "b": to, "v": val.to_bytes(32, "little")}
    c["spec"] = s.pick((0xd, 0xe, 0xf, 0x80, s.below(256)))
    c["oom"] = s.pick((0, 0, 0, 1, 2))
    c["scenario"] = "log"
    return c


def case_set_code(s):
    shape = s.pick(("small", "dense", "dense", "dense", "empty"))
    c = base_case(s, "set_code", shape)
    addr = pick_addr(s, c, 10)
    c["inputs"] = {"a": addr, "h": s.take(32)}
    c["new_arc"] = s.pick((0, ARC_AT + 0x800 + 0x10 * s.below(8)))
    c["scenario"] = "set_code"
    return c


def case_create(s):
    shape = s.pick(("small", "small", "small", "dense", "dense", "dense", "dense", "empty"))
    c = base_case(s, "create", shape)
    c["depth"] = s.pick((0, 1, 2, s.below(1 << 16), M64 - 1))
    scen = s.pick(("clean", "clean", "clean", "collide_hash", "collide_nonce", "overflow", "absent_target", "absent_caller", "free"))
    target = pick_addr(s, c, 1 if scen == "absent_target" else 15)
    caller = pick_addr(s, c, 1 if scen == "absent_caller" else 15)
    if scen in ("clean", "overflow", "absent_caller", "free", "collide_nonce") and target in c["addrs"]:
        i, b = bucket_of(c["world"], target)
        nb = bytearray(b)
        nb[B_HASH:B_HASH + 32] = CONSTS["empty_hash"]
        nb[B_NONCE:B_NONCE + 8] = le(0 if scen != "collide_nonce" else 1 + s.below(3), 8)
        if scen == "overflow":
            put_balance(nb, M256 - s.below(40))
        c["slots"][i] = bytes(nb)
        c["table"].slots[i] = bytes(nb)
    val = 0 if scen == "free" else rand_u256(s) if scen != "overflow" else 41 + s.below(1000)
    c["inputs"] = {"a": caller, "b": target, "v": val.to_bytes(32, "little")}
    c["spec_arg"] = s.pick((0, 2, 3, 0xe, s.below(256), (1 << 32) | s.below(256)))
    if scen == "free":
        c["depth"] = s.pick((M64, 0))
    c["spec"] = s.pick((0xd, 0xe, 0xf, s.below(256)))
    c["scenario"] = scen
    return c


def case_revert(s):
    c = base_case(s, "revert", "empty")
    jn, ln = len(c["journal"]), len(c["logs"])
    if s.below(2):
        c["journal"] = rand_journal(s, jn + s.below(4), (0, 1, 2, 3, 4, 7, 0xb, 0xc))
        c["jcap"] = max(c["jcap"], len(c["journal"]))
    cp0 = s.below(len(c["logs"]) + 3)
    cp1 = s.below(len(c["journal"]) + 3)
    cp2 = s.pick((0, 3, s.below(16), M64))
    c["inputs"] = {"cp": le(cp0, 8) + le(cp1, 8) + le(cp2, 8)}
    c["scenario"] = "revert"
    return c


def case_lookup(s):
    shape = s.pick(("small", "dense", "dense", "empty"))
    c = base_case(s, "lookup", shape)
    c["inputs"] = {"a": pick_addr(s, c, 4)}
    c["scenario"] = "lookup"
    return c


CASE_PLAN = (("transfer", case_transfer, 3700), ("create", case_create, 2600), ("set_code", case_set_code, 1500),
             ("revert", case_revert, 1900), ("log", case_log, 600), ("lookup", case_lookup, 900))


def all_cases():
    for fn, maker, count in CASE_PLAN:
        s = Stream(f"journal-{fn}")
        for _ in range(count):
            yield finish(maker(s))


# ---------------------------------------------------------------- evaluation
CONSTS = None


def prepare(image):
    global CONSTS
    ev.prepare(image)
    CONSTS = read_consts(image)


def evaluate(image, override=None, mut=frozenset(), stop_on_first=False, fn=None, limit=None, keep=None):
    """Run every case of the plan; `keep(i, c, want, got, ok)` receives each result (no result list is stored)."""
    m = Mach(image, override)
    bad = n = 0
    for c in all_cases():
        if fn is not None and c["fn"] != fn:
            continue
        if limit is not None and n >= limit:
            break
        try:
            want = model(c, mut, CONSTS)
            got = run_case(m, c, CONSTS, dict(want["blocks"]))
            ok = compare(want, got)
        except ToolError as exc:
            want, got, ok = None, {"error": str(exc)}, False
        bad += not ok
        if keep is not None:
            keep(n, c, want, got, ok)
        n += 1
        if stop_on_first and not ok:
            break
    return n, bad, m


MODEL_MUTANTS = [("log_spec", "log"), ("log_flag", "log"), ("log_zero", "log"), ("log_topic_swap", "log"),
                 ("log_le", "log"), ("same_always_ok", "transfer"), ("zero_no_touch", "transfer"),
                 ("no_borrow_check", "transfer"), ("no_carry_check", "transfer"), ("arc_always_drop", "set_code"),
                 ("tag_b", "set_code"), ("no_depth_check", "create"), ("nonce_ignored", "create"),
                 ("spec_gate", "create"), ("err_code", "create"), ("depth_wrap", "revert"), ("revert_spec", "revert")]
BYTE_MUTANTS = [
    (0x4322a7a, 0x05, "transfer journal tag 4 -> 5", "transfer"),
    (0x4322901, 0x03, "transfer touch tag 2 -> 3", "transfer"),
    (0x43228e5, 0x08, "transfer touched-bit test 0x04 -> 0x08", "transfer"),
    (0x4322a76, 0x50, "transfer journal entry stride 0x58 -> 0x50", "transfer"),
    (0x4322a2c, 0x02, "transfer overflow code 1 -> 2", "transfer"),
    (0x4322c1d, 0x02, "transfer zero-value Ok code 3 -> 2", "transfer"),
    (0x4322fb4, 0x50, "revert journal entry stride 0x58 -> 0x50", "revert"),
    (0x4322ff6, 0x0d, "revert stop tag 0xc -> 0xd", "revert"),
    (0x4322fff, 0x04, "revert spec threshold 3 -> 4", "revert"),
    (0x4323182, 0x03, "set_code touch tag 2 -> 3", "set_code"),
    (0x43231c3, 0x0a, "set_code CodeChange tag 0xb -> 0xa", "set_code"),
    (0x4323157, 0x08, "set_code touched-bit test 0x04 -> 0x08", "set_code"),
    (0x43235ed, 0x06, "create AccountCreated tag 7 -> 6", "create"),
    (0x4323636, 0x03, "create nonce spec threshold 2 -> 3", "create"),
    (0x43235c8, 0x80, "create status or 0x81 -> 0x80", "create"),
    (0x4323587, 0x60, "create nonce offset 0x68 -> 0x60", "create"),
    (0x432359d, 0x00, "create Err tag 1 -> 0", "create"),
    (0x4323804, 0x03, "create overflow error code 1 -> 3", "create"),
    (0x4323284, 0x0f, "log spec gate 0xe -> 0xf", "log"),
    (0x4323294, 0x01, "log flag gate 0 -> 1", "log"),
    (0x43232c6, 0x50, "log topic block size 0x60 -> 0x50", "log"),
    (0x4323393, 0x30, "log data block size 0x20 -> 0x30", "log"),
    (0x43233f6, 0x02, "log topic count 3 -> 2", "log"),
    (0x3ed7e84, 0x01, "lookup empty-map items compare 0 -> 1", "lookup"),
    (0x3ed7ebc, 0x38, "lookup h2 shift 57 -> 56", "lookup"),
    (0x3ed7f08, 0xa0, "lookup bucket stride 0xa8 -> 0xa0", "lookup"),
]


def controls(image):
    rows = []
    for name, fn in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, mut=frozenset([name]), stop_on_first=True, fn=fn)
        rows.append(("model", f"{name} ({fn})", int(bad > 0)))
    for va, byte, what, fn in BYTE_MUTANTS:
        if image.code(va, 1)[0] == byte:
            fail(f"byte mutant at {va:#x} does not change the byte")
        _, bad, _ = evaluate(image, override={va: byte}, stop_on_first=True, fn=fn)
        rows.append(("code", f"{va:#x}={byte:#04x} {what}", int(bad > 0)))
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
    return rows


# ---------------------------------------------------------------- static evidence
def sweep(image, lo, hi):
    """Linear decode of one FDE extent (int3 padding rows carry no form)."""
    rows, va = [], lo
    while va < hi:
        if image.code(va, 1)[0] == 0xcc:
            rows.append((va, None))
            va += 1
            continue
        form = decode(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


def static_evidence(image):
    rows = ev.fde_rows(image, FUNCS)
    decoded, funcs = {}, {}
    for f in FUNCS:
        lo, hi = rows[f]
        decoded[f] = sweep(image, lo, hi)
        funcs[f"{f:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                            "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                            "instructions": sum(1 for _, fm in decoded[f] if fm is not None)}
    slots = {}
    for name, slot in GOT.items():
        if slot in image.imports:
            fail(f"{name} slot is not a RELATIVE relocation")
        slots[name] = {"slot": f"{slot:#x}", "relocation": "RELATIVE", "target": f"{image.word(slot):#x}"}
    slots["seed_block"] = {"slot": f"{SEED_GOT:#x}", "relocation": "RELATIVE", "target": f"{image.word(SEED_GOT):#x}"}
    sites = {}
    for site, name in sorted(PANIC_SITES.items()):
        raw = image.code(site, 7)
        if raw[:3] != bytes.fromhex("488d3d"):
            fail(f"panic site {site:#x} is not lea rdi,[rip+rel32]")
        target = site + 7 + struct.unpack("<i", raw[3:])[0]
        if target != PANIC_STR[name]:
            fail(f"panic string at {site:#x} changed")
        sites[f"{site:#x}"] = {"name": name, "string_va": f"{target:#x}"}
    out = {"binary_sha256": SHA256, "functions": funcs, "got_slots": slots, "panic_sites": sites,
           "journaled_state": {"logs_vec": "0x0 {cap, ptr, len+0x10}, entry 0x50", "journal_vec": "0x18 {cap, ptr+0x20, len+0x28}, entry 0x58",
                               "checkpoint_min": "0x40", "account_map": "0xc8 {ctrl, mask, growth, items+0xe0, key+0xe8}",
                               "depth": "0x118", "flag": "0x124", "spec": "0x126", "bucket": ACCT},
           "account_bucket": {"address": "0x00..0x14", "balance": hex(B_BAL), "code_hash": hex(B_HASH), "nonce": hex(B_NONCE),
                              "code_arc": hex(B_ARC), "status": hex(B_STATUS)},
           "journal_tags": {"touch": 2, "balance_transfer": 4, "account_created": 7, "code_change": 0xb, "stop": 0xc},
           "log_constants": {"topic0": CONSTS["topic0"].hex(), "sender16": CONSTS["sender16"].hex(),
                             "sender_imm": CONSTS["sender_imm"].hex(), "empty_code_hash": CONSTS["empty_hash"].hex()}}
    return out, decoded


# ---------------------------------------------------------------- output
def event_text(events):
    return ";".join(":".join(str(x) for x in e) for e in events) or "-"


def outcome(c, want):
    if want["boundary"] is not None:
        b = want["boundary"]
        return f"{c['fn']}:{b[0]}" + (f":{b[1]:#x}" if b[1] else "")
    if c["fn"] in ("transfer", "lookup"):
        r = want["ret"]
        return f"{c['fn']}:ret={'found' if (c['fn'] == 'lookup' and r) else 'miss' if c['fn'] == 'lookup' else r}"
    if c["fn"] == "create":
        return f"create:{'ok' if want['out'][0] == 0 else 'err' + str(want['out'][1])}"
    return f"{c['fn']}:done"


def generate(out):
    image = Image(BINARY.read_bytes())
    prepare(image)
    out.mkdir(parents=True, exist_ok=True)
    classes, per_fn, digest = {}, {}, hashlib.sha256()
    sample = ["case\tfunction\tscenario\toutcome\tevents\tjournal_len\tlogs_len\tmatch"]

    def keep(i, c, want, got, ok):
        oc = outcome(c, want) if want else "error"
        classes[oc] = classes.get(oc, 0) + 1
        per_fn[c["fn"]] = per_fn.get(c["fn"], 0) + 1
        digest.update(repr((i, c["fn"], oc, want and want["events"], want and want["j"], ok)).encode())
        if i % 3 == 0 or not ok:
            sample.append(f"{i}\t{c['fn']}\t{c.get('scenario', '-')}\t{oc}\t{event_text(want['events']) if want else '-'}\t"
                          f"{len(want['journal']) if want else '-'}\t{len(want['logs']) if want else '-'}\t{'yes' if ok else 'NO'}")

    n, bad, m = evaluate(image, keep=keep)
    consts, decoded = static_evidence(image)
    (out / "cases.tsv").write_text("\n".join(sample) + "\n")
    (out / "outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    lines = ["function\taddress\tlength\tbytes\topcode\texecuted"]
    covered = {}
    for start, insns in sorted(decoded.items()):
        hit = total = 0
        for va, f in insns:
            if f is None:
                lines.append(f"{start:#x}\t{va:#x}\t1\tcc\tpadding\t0")
                continue
            run = va in m.seen
            hit += run
            total += 1
            lines.append(f"{start:#x}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t{int(run)}")
        covered[f"{start:#x}"] = [hit, total]
    (out / "decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    ctl = controls(image)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    detected = sum(r[2] for r in ctl)
    (out / "measure.json").write_text(json.dumps({"cases": n, "negative_controls": len(ctl), "negative_detected": detected},
                                                 indent=2, sort_keys=True) + "\n")
    summary = {"binary_sha256": SHA256, "cases": n, "cases_per_function": per_fn, "mismatches": bad,
               "all_case_digest": digest.hexdigest(), "covered_instructions": covered, "outcome_classes": classes,
               "negative_controls": {"total": len(ctl), "detected": detected}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
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
