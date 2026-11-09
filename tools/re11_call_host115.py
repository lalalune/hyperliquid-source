#!/usr/bin/env python3
"""Reconstruct the node #115 EVM CALL-family host 0x546c330 and its ordinary twin 0x4335cf0.

Both bodies (identical 0x870-byte extents) are the account-access and gas-charging step that every
CALL-family handler reaches through the host slots 0x64e6e08 (alternate) and 0x64e6e00 (ordinary).
Arguments (SysV): rdi = result slot, rsi = pointer to (frame, vm), rdx = target address word,
ecx = value flag, r8b = new-account flag, r9 = requested forwarded gas.  The frame carries the gas
counter (+0x188), a refund-style counter (+0x190), a saturating signed total (+0x198) and the spec
byte (+0x1a9); the vm carries the cost table behind +0x250 and the flags +0x265 / +0x396.

Reconstructed flow: (1) a value transfer first charges cost[+0x78]; (2) the target account is loaded
through the loader (stubbed, arguments recorded) with a cold-access hint when gas < cost[+0x80] and
spec >= 7; (3) status byte 2 or a short balance is an out-of-gas result (result byte 0x20, tag 2);
(4) emptiness is computed from the account (spec > 2: code hash is the empty hash or zero, balance
words and nonce zero; otherwise flag bits 3 and not 2); (5) a new-account flag on an empty account
adds cost[+0x88] (skipped from spec 3 when the low value bit is clear); (6) otherwise a code object
of kind 1 with at least 23 bytes is an EIP-7702 style designator: its bytes 3..22 are the delegate
address, charged cost[+0x90] plus a second loader call, and the delegate's code hash is reported;
(7) the total is deducted from gas, cost[+0x158] is drawn from the refund counter first (when the
value flag and vm byte +0x265 hold), the requested gas is capped by the 63/64 rule from spec 2, a
stipend cost[+0xc0] is added with saturation when a value is sent, and the result slot is filled
with (code object, forwarded gas, code hash, flag).  Reference counts of the code objects are
modelled with the overflow abort.  The tool reads every code byte, relocation and FDE extent from
the ELF file, runs the real machine code with the repository's concrete x86-64 evaluator (extended
here with lock, por, movmskps, not, div and the signed condition codes), and compares every case
with one pure-Python model.  The binary is never executed.
"""
import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_transient_storage115 as base  # noqa: E402

BINARY, SHA256, M64 = base.BINARY, base.SHA256, base.M64
ToolError, Boundary, fail, Image = base.ToolError, base.Boundary, base.fail, base.Image
Stream = base.Stream

HOSTS = {
    "alt": dict(start=0x546c330, loader=0x5463980, prep=0x54793e0, cleanup=0x563e0e0, init=0x5b084ff),
    "ord": dict(start=0x4335cf0, loader=0x4323870, prep=0x433c700, cleanup=0x4357560, init=0x435059c),
}
GOT_DROP, GOT_LAZY = 0x64e4fa8, 0x64e6c78
GOT_PANICS = (0x64df4c0, 0x64df520, 0x64df570, 0x64df878)
HOST_LEN = 0x870
UNIT = 0x6000_0000_0000
FRAME, VM, CFG, PAIR, OUT = (UNIT + 0x10000 * i for i in range(5))
ACC = (UNIT + 0x50000, UNIT + 0x60000)
ARC = (UNIT + 0x70000, UNIT + 0x80000, UNIT + 0x90000)  # code objects of account 1, account 2, global default
LAZY = UNIT + 0xa0000
BYTES = (UNIT + 0xb0000, UNIT + 0xc0000)
SENTINEL = 0xA5


# ---------------------------------------------------------------- decoder / evaluator extension
_orig_decode = base.decode


def decode(code, va):
    """Repository decoder plus the few forms of the host: lock prefix, por, movmskps, not, div."""
    if code[0] == 0xf0:
        f = _orig_decode(code[1:], va + 1)
        f["len"] += 1
        f["bytes"] = bytes(code[:f["len"]])
        f["lock"] = True
        if "rel" in f:
            f["target"] = (va + f["len"] + f["rel"]) & M64
        return f
    p = 0
    while code[p] in (0x66, 0xf2, 0xf3):
        p += 1
    q = p + (1 if 0x40 <= code[p] <= 0x4f else 0)
    swap = None
    if code[q] == 0x0f and code[q + 1] == 0xeb:
        swap = (q + 1, 0xdb, 0x0feb)
    elif code[q] == 0x0f and code[q + 1] == 0x50:
        swap = (q + 1, 0xd7, 0x0f50)
    elif code[q] == 0xf6 and (code[q + 1] >> 3) & 7 == 2:
        swap = (q, 0x84, 0x1f6)
    elif code[q] == 0xf7 and (code[q + 1] >> 3) & 7 == 6:
        swap = (q, 0xf7, 0x1f7)
    if swap is None:
        return _orig_decode(code, va)
    where, repl, newop = swap
    tmp = bytearray(code)
    tmp[where] = repl
    if newop == 0x1f7:
        tmp[q + 1] = (tmp[q + 1] & 0xc7) | (3 << 3)  # f7 /6 -> f7 /3 (same ModRM shape, no immediate)
    f = _orig_decode(bytes(tmp), va)
    f["op"] = newop
    return f


base.decode = decode


class HostMachine(base.Machine):
    """Concrete evaluator with the extra forms and per-branch outcome counters."""

    def __init__(self, image, override=None):
        self.branches = {}
        super().__init__(image, override)

    def cond(self, code, va):
        if code in (0xc, 0xd, 0xe, 0xf):
            if getattr(self, "of", None) is None:
                fail(f"overflow flag read without a defining op at {va:#x}")
            lt = self.sf != self.of
            return {0xc: lt, 0xd: not lt, 0xe: lt or self.zf, 0xf: not (lt or self.zf)}[code]
        return super().cond(code, va)

    def step(self, va):
        f = self.fetch(va)
        op = f["op"]
        nxt = (va + f["len"]) & M64
        if op == 0x0feb:
            self.xmm[f["reg"]] |= self.xmm[f["rm"][1]]
        elif op == 0x0f50:
            v = self.xmm[f["rm"][1]]
            self.set_reg(f["reg"], 32, sum(1 << i for i in range(4) if (v >> (32 * i + 31)) & 1), f)
        elif op == 0x1f6:
            self.put(f["rm"], 8, ~self.get(f["rm"], 8, f, va) & 0xff, f, va)
        elif op == 0x1f7:
            size = f["size"]
            den = self.get(f["rm"], size, f, va)
            if den == 0:
                fail("division by zero reached")
            num = (self.regs[2] << size | self.regs[0]) if size == 64 else (self.regs[2] & 0xffffffff) << 32 | self.regs[0] & 0xffffffff
            q, r = divmod(num, den)
            if q >> size:
                fail("division overflow")
            self.set_reg(0, size, q, f)
            self.set_reg(2, size, r, f)
        else:
            nxt2 = super().step(va)
            if (0x70 <= op <= 0x7f or 0x0f80 <= op <= 0x0f8f) and HOST_RANGE[0] <= va < HOST_RANGE[1]:
                key = (va, nxt2 != nxt)
                self.branches[key] = self.branches.get(key, 0) + 1
            return nxt2
        return nxt


HOST_RANGE = (0, 0)


# ---------------------------------------------------------------- case model
def u64(x):
    return x & M64


def sat_s64(a, b):
    """Signed saturating 64-bit add of two u64 words (the lea/sar/xor/cmovo idiom)."""
    s = (a - (1 << 64) if a >> 63 else a) + (b - (1 << 64) if b >> 63 else b)
    if s > (1 << 63) - 1:
        return (1 << 63) - 1
    if s < -(1 << 63):
        return 1 << 63
    return s & M64


def empty_account(a, v396, keccak_empty):
    if v396 > 2:
        if a["hash"] != keccak_empty and a["hash"] != bytes(32):
            return False
        return a["w28"] == bytes(32) and a["nonce"] == 0
    return bool(a["f8c"] & 8) and not a["f8c"] & 4


class Panic(Exception):
    pass


def model(c, keccak_empty, mut=frozenset()):
    """Pure model of one host call; returns the observable record (dict of plain values)."""
    cost, ev = c["cfg"], []
    st = dict(gas=c["gas"], f190=c["f190"], f198=c["f198"])
    cells = {"a1": c["arc"][0]["ref"] if c["arc"][0] else None, "a2": c["arc"][1]["ref"] if c["arc"][1] else None, "g": c["arc"][2]["ref"]}
    out = {"b0": None, "err": None, "w8": None, "hash": None, "flag": None}
    res = dict(kind="ok", out=out, st=st, ev=ev, cells=cells)
    err_byte = 0x36 if "err36" in mut else 0x20

    def error(code=None):
        out["err"] = err_byte if code is None else code

    def inc(name):
        cells[name] = u64(cells[name] + (2 if "inc2" in mut else 1))
        # lock inc then jle: taken when the result is zero or negative without signed overflow
        old = u64(cells[name] - (2 if "inc2" in mut else 1))
        if cells[name] == 0 or (cells[name] >> 63 and old != (1 << 63) - 1):
            raise Panic("ud2")

    def dec(name):
        cells[name] = u64(cells[name] - 1)
        if cells[name] == 0 and "nodrop" not in mut:
            ev.append(("drop", name))

    lazy = [c["lazy_state"]]

    def arc_for(i, slot):
        """The code object counted for account i: its own, or the global default."""
        a = c["acc"][i]
        if a["arc"] is not None:
            inc("a%d" % (i + 1))
            return "a%d" % (i + 1)
        if lazy[0]:
            ev.append(("init",))
            lazy[0] = 0
        inc("g")
        return "g"

    try:
        spec = c["spec"]
        r15 = st["gas"]
        if c["ecx"] & 0xffffffff:
            r15 = u64(st["gas"] - cost[0x78])
            if st["gas"] < cost[0x78]:
                error()
                out["tag"] = 2
                return res
            st["gas"] = r15
        warm_hint = int(spec >= (6 if "spec6" in mut else 7) and r15 < cost[0x80])
        ev.append(("load", c["target"], warm_hint))
        resp = c["resp"][0]
        s1 = resp["status"]
        if s1 == 2:
            error(err_byte)
            out["tag"] = 2
            return res
        ev.append(("prep", 1, resp["arg"]))
        e1 = empty_account(c["acc"][0], c["v396"], keccak_empty)
        r13 = cost[0x80] if s1 & 1 else 0
        if spec < 7:
            r13 = 0
        held = arc_for(0, 0)
        hv = c["ecx"] & 0xffffffff
        hv8 = hv & 0xff
        h_acc = 0
        hash_ = c["acc"][0]["hash"]
        rbx = 0
        if c["flag24"] & 0xff and e1:
            thr = 4 if "spec4" in mut else 3
            rcx = 0 if (spec >= thr and not hv & 1) else cost[0x88]
            if rcx + r13 >> 64:
                raise Panic("caf8")
            total = rcx + r13
            if hv8 and c["v265"]:
                rbx = cost[0x158]
        else:
            ar = c["acc"][0]["arc"]
            if ar is None or ar["kind"] != 1:
                total = r13
            else:
                if ar["len"] <= (0x17 if "len17" in mut else 0x16):
                    raise Panic("cace")
                addr = ar["bytes"][2 if "off2" in mut else 3:][:20]
                r13 += 0 if "nodel" in mut else cost[0x90]
                if r13 >> 64:
                    raise Panic("cb10")
                if r13 > r15:
                    dec(held)
                    error(err_byte)
                    out["tag"] = 2
                    return res
                c80n = cost[0x80] + r13
                if c80n >> 64:
                    raise Panic("cb19")
                ev.append(("load", addr, int(r15 <= c80n if "le" in mut else r15 < c80n)))
                resp2 = c["resp"][1]
                if resp2["status"] == 2:
                    dec(held)
                    error(err_byte)
                    out["tag"] = 2
                    return res
                ev.append(("prep", 2, resp2["arg"]))
                if resp2["status"] & 1:
                    r13 = c80n
                new = arc_for(1, 0)
                dec(held)
                held = new
                hash_ = c["acc"][1]["hash"]
                total = r13
        gas = st["gas"]
        if (total >= gas) if "ge" in mut else (total > gas):
            dec(held)
            error(err_byte)
            out["tag"] = 2
            return res
        rcx = gas - total
        st["gas"] = rcx
        r8 = c["req"]
        if st["f190"] >= rbx:
            st["f198"] = sat_s64(st["f198"], rbx) if "unsat" not in mut else u64(st["f198"] + rbx)
            st["f190"] = st["f190"] - rbx
        else:
            rcx -= rbx - st["f190"]
            if rcx < 0:
                dec(held)
                error(err_byte)
                out["tag"] = 2
                return res
            st["f198"] = sat_s64(st["f198"], rbx)
            st["gas"] = rcx
            st["f190"] = st["f190"] if "keep190" in mut else 0
        if spec > (0 if "s0" in mut else 1):
            div = cost[0x70]
            if div == 0:
                raise Panic("cb01")
            r8 = min(r8, rcx - rcx // (div * 2 if "div2" in mut else div))
        rcx -= r8
        if rcx < 0:
            dec(held)
            error(err_byte)
            out["tag"] = 2
            return res
        st["gas"] = rcx
        if hv8 and "nostipend" not in mut:
            r8 = r8 + cost[0xc0]
            if r8 >> 64:
                r8 = r8 if "wrap" in mut else M64
        out["b0"], out["w8"], out["hash"] = held, r8 & M64, hash_
        out["flag"] = int(rbx == 0) if "flagneg" in mut else int(rbx != 0)
        return res
    except Panic as p:
        res["kind"] = "panic:" + {"cace": "64df570", "caf8": "64df520", "cb10": "64df520", "cb19": "64df520", "cb01": "64df878"}.get(str(p), str(p))
        return res


# ---------------------------------------------------------------- harness
class Run:
    def __init__(self, image, which, override=None):
        self.image, self.h = image, HOSTS[which]
        self.override = override
        keys = image.read(0x4537f0, 16) + image.read(0x452020, 16)
        self.keccak_empty = keys

    def build(self, c):
        im, h = self.image, self.h
        m = HostMachine(im, self.override)
        frame = bytearray(0x200)
        base.put(frame, 0x188, 8, c["gas"])
        base.put(frame, 0x190, 8, c["f190"])
        base.put(frame, 0x198, 8, c["f198"])
        frame[0x1a9] = c["spec"]
        m.add_region(FRAME, 0x200, bytes(frame))
        cfg = bytearray(0x200)
        for off, v in c["cfg"].items():
            base.put(cfg, off, 8, v)
        m.add_region(CFG, 0x200, bytes(cfg))
        vm = bytearray(0x400)
        base.put(vm, 0x250, 8, CFG)
        vm[0x265], vm[0x396] = c["v265"], c["v396"]
        m.add_region(VM, 0x400, bytes(vm))
        m.add_region(PAIR, 16, FRAME.to_bytes(8, "little") + VM.to_bytes(8, "little"))
        m.add_region(OUT, 0x40, bytes([SENTINEL]) * 0x40)
        arcs = {}
        for i in range(2):
            a = c["acc"][i]
            ab = bytearray(0x100)
            ab[0x28:0x48], ab[0x48:0x68] = a["w28"], a["hash"]
            base.put(ab, 0x68, 8, a["nonce"])
            ab[0x8c] = a["f8c"]
            if a["arc"] is not None:
                base.put(ab, 0x70, 8, ARC[i])
            m.add_region(ACC[i], 0x100, bytes(ab))
        for i in range(3):
            a = c["arc"][i]
            if a is None:
                continue
            ob = bytearray(0x100)
            base.put(ob, 0, 8, a["ref"])
            base.put(ob, 0x38, 8, BYTES[i] if i < 2 else 0)
            base.put(ob, 0x40, 8, a["len"])
            ob[0x7c] = a["kind"]
            m.add_region(ARC[i], 0x100, bytes(ob))
            if i < 2:
                m.add_region(BYTES[i], 0x100, bytes(a["bytes"]).ljust(0x100, b"\0"))
        lazy = bytearray(16)
        base.put(lazy, 0, 8, 0 if c["lazy_state"] else ARC[2])
        base.put(lazy, 8, 4, c["lazy_state"])
        m.add_region(LAZY, 16, bytes(lazy))
        m.add_region(GOT_LAZY, 8, LAZY.to_bytes(8, "little"))
        ev, order = [], {"load": 0}
        names = {ACC[0]: 1, ACC[1]: 2}

        def loader(mm):
            k = order["load"]
            order["load"] += 1
            rcx = mm.regs[1]
            target = rcx if k == 0 else bytes(mm.load(rcx + j, 1) for j in range(20))
            ev.append(("load", target, mm.regs[8] & 0xff))
            if mm.regs[6] != VM + 0x270 or mm.regs[2] != VM + 0x398:
                fail("loader called with unexpected vm pointers")
            r = c["resp"][k]
            mm.store(mm.regs[7], 8, ACC[k])
            mm.store(mm.regs[7] + 0x18, 8, r["arg"])
            mm.store(mm.regs[7] + 0x38, 1, r["status"])

        def prep(mm):
            ev.append(("prep", names[mm.regs[7]], mm.regs[6]))

        def drop(mm):
            ptr = mm.load(mm.regs[7], 8)
            ev.append(("drop", {ARC[0]: "a1", ARC[1]: "a2", ARC[2]: "g"}[ptr]))

        def init(mm):
            ev.append(("init",))
            mm.store(LAZY + 8, 4, 0)
            mm.store(LAZY, 8, ARC[2])

        m.stubs[h["loader"]] = loader
        m.stubs[h["prep"]] = prep
        m.stubs[im.word(GOT_DROP)] = drop
        m.stubs[h["init"]] = init
        for slot in GOT_PANICS:
            m.stubs[im.word(slot)] = "panic:%x" % slot
        m.regs[7], m.regs[6], m.regs[2], m.regs[1] = OUT, PAIR, c["target"], c["ecx"]
        m.regs[8], m.regs[9] = c["flag24"], c["req"]
        return m, ev

    def run(self, c):
        m, ev = self.build(c)
        try:
            m.run(self.h["start"])
            kind = "ok"
        except Boundary as b:
            kind = b.kind
        except ToolError as e:
            if "ud2" not in str(e):
                raise
            kind = "panic:ud2"
        return m, ev, kind

    def observe(self, c):
        """Machine-side observation in the same shape as model()."""
        m, ev, kind = self.run(c)
        rd = lambda base_, off, n: m.load(base_ + off, n)
        st = dict(gas=rd(FRAME, 0x188, 8), f190=rd(FRAME, 0x190, 8), f198=rd(FRAME, 0x198, 8))
        cells = {n: rd(ARC[i], 0, 8) if c["arc"][i] else None for i, n in enumerate(("a1", "a2", "g"))}
        out = {"b0": None, "err": None, "w8": None, "hash": None, "flag": None}
        buf = bytes(m.load(OUT + j, 1) for j in range(0x38))
        if kind == "ok":
            if buf[0] in (0x20, 0x36) and rd(OUT, 0x30, 1) == 2:
                out["err"] = buf[0]
            else:
                out["b0"] = {ARC[0]: "a1", ARC[1]: "a2", ARC[2]: "g"}[int.from_bytes(buf[:8], "little")]
                out["w8"] = int.from_bytes(buf[8:16], "little")
                out["hash"] = buf[16:48]
                out["flag"] = rd(OUT, 0x30, 1)
        return dict(kind=kind, out=out, st=st, ev=ev, cells=cells, buf=buf)


def norm_events(ev):
    return [tuple(e) for e in ev]


def compare(c, obs, mod):
    if obs["kind"] != mod["kind"]:
        return "kind"
    o, mo = obs["out"], mod["out"]
    for k in ("b0", "err", "w8", "hash", "flag"):
        if o[k] != mo[k]:
            return "out." + k
    if obs["st"] != mod["st"]:
        return "frame"
    if obs["cells"] != mod["cells"]:
        return "cells"
    if norm_events(obs["ev"]) != norm_events(mod["ev"]):
        return "events"
    if mod["kind"] == "ok" and mod["out"].get("tag") == 2 and obs["buf"][0x30] != 2:
        return "tag"
    return None


# ---------------------------------------------------------------- case generation
COSTS = (0, 1, 100, 700, 2300, 2600, 9000, 25000, 0x7fff, 0xffff_ffff, 1 << 40, M64 - 3, M64)
GASES = (0, 1, 99, 100, 2599, 2600, 2601, 5000, 9000, 11599, 11600, 30000, 100000, 1 << 32, (1 << 32) + 5, 1 << 40, M64 - 1, M64)
STATUS = (0, 1, 1, 0, 2, 3, 0x80, 0x81)
REFS = (1, 2, 5, 1000, 7, 300, 1 << 20, 1, 2, 5, M64 >> 1, M64 - 1, M64, 0)


def rand_account(s, kind):
    h = {0: bytes(32), 1: None, 2: None, 3: None}[kind] if kind < 1 else None
    return h


def make_case(s, keccak_empty):
    pick = s.pick
    spec = pick((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x20))

    def acct():
        hk = s.below(6)
        hash_ = keccak_empty if hk < 2 else bytes(32) if hk == 2 else s.take(32) if hk == 3 else keccak_empty[:31] + bytes([keccak_empty[31] ^ 1]) if hk == 4 else bytes(16) + keccak_empty[16:]
        w28 = bytes(32) if s.below(3) else s.take(32)
        if s.below(5) == 0:
            w28 = bytes(31) + bytes([s.below(256)])
        nonce = 0 if s.below(3) else pick((1, 2, M64, s.below(1 << 20)))
        return dict(hash=hash_, w28=w28, nonce=nonce, f8c=pick((0, 8, 12, 4, 8, 0xff, 0x38, s.below(256))), arc=None)

    def arc_obj(deleg):
        kind = 1 if deleg else pick((0, 1, 2, 0xff))
        data = s.take(32)
        ln = pick((0x17, 0x18, 0x16, 0x20, 0, 5)) if kind == 1 else pick((0, 0x17, 0x40))
        if deleg:
            ln = pick((0x17, 0x17, 0x18, 0x20, 0x16, 0xf))
        return dict(ref=pick(REFS), kind=kind, len=ln, bytes=b"\xef\x01\x00" + data[:29])

    acc = [acct(), acct()]
    arcs = [None, None, dict(ref=pick(REFS), kind=0, len=0, bytes=b"")]
    r = s.below(10)
    if r < 6:
        arcs[0] = arc_obj(r < 4)
        acc[0]["arc"] = arcs[0]
    if s.below(3):
        arcs[1] = arc_obj(False)
        acc[1]["arc"] = arcs[1]
    cfg = {off: pick(COSTS) for off in (0x78, 0x80, 0x90, 0x88, 0x158, 0xc0)}
    cfg[0x70] = pick((64, 64, 64, 32, 1, 2, 0, 0x1_0000_0001, 3, 1 << 40, 1 << 33))
    if s.below(4):
        for off in (0x78, 0x80, 0x90, 0x88, 0xc0):
            cfg[off] = pick((0, 100, 700, 2300, 2600, 9000, 25000, s.below(40000)))
    gas = pick(GASES) if s.below(2) else s.below(60000)
    c = dict(
        spec=spec, gas=gas, f190=pick((0, 1, 5000, 1 << 40, M64, s.below(30000))), f198=pick((0, 5, M64 >> 1, 1 << 63, M64, s.below(1 << 30))),
        cfg=cfg, v265=pick((0, 1, 1, 7)), v396=pick((0, 1, 2, 3, 4, 9, 255)),
        ecx=pick((0, 1, 1, 1, 2, 0x100, 0xffffffff, 0x1_0000_0000 | 1)), flag24=pick((0, 1, 1, 0x100, 2)),
        target=s.below(1 << 64) if s.below(2) else pick((0, 9, M64)), req=pick((0, 1, 100, 1 << 63, M64, s.below(100000), gas)),
        acc=acc, arc=arcs,
        resp=[dict(status=pick(STATUS) if s.below(5) else 0, arg=s.below(1 << 64)) for _ in range(2)],
        lazy_state=pick((0, 0, 1)), lazy_state2=0,
    )
    # keep the interesting fraction: sometimes force a path that survives the early gates
    if s.below(3):
        c["cfg"][0x78] = min(c["cfg"][0x78], gas) if gas else 0
        c["resp"][0]["status"] = pick((0, 1))
        c["resp"][1]["status"] = pick((0, 1, 1))
    fam = s.below(10)
    if fam == 0:  # equality edge of the second-load hint threshold
        c["spec"], c["ecx"], c["flag24"] = pick((7, 8, 12)), 0, 0
        c["cfg"][0x80], c["cfg"][0x90] = pick((100, 2600)), pick((0, 100, 2600))
        c["resp"][0]["status"], c["resp"][1]["status"] = pick((0, 1)), pick((0, 1))
        c["arc"][0] = dict(ref=pick((1, 5)), kind=1, len=pick((0x17, 0x20)), bytes=b"\xef\x01\x00" + s.take(29))
        c["acc"][0]["arc"] = c["arc"][0]
        r13 = (c["cfg"][0x80] if c["resp"][0]["status"] & 1 else 0) + c["cfg"][0x90]
        c["gas"] = c["cfg"][0x80] + r13 + pick((-1, 0, 1))
        c["req"] = pick((0, 5, c["gas"]))
    elif fam == 1:  # signed saturation of the running total
        c["spec"], c["ecx"], c["flag24"], c["v265"], c["v396"] = pick((2, 5, 12)), 1, 1, 1, 4
        c["acc"][0].update(hash=keccak_empty, w28=bytes(32), nonce=0)
        c["cfg"][0x88], c["cfg"][0x80] = pick((0, 25000)), pick((0, 2600))
        c["cfg"][0x158], c["f190"], c["f198"] = pick((1, 5, 100)), pick((M64, 1 << 40)), pick((M64 >> 1, (M64 >> 1) - 3, 1 << 63, (1 << 63) + 2, 5))
        c["gas"], c["req"], c["cfg"][0x78], c["cfg"][0x70] = 1 << 40, pick((0, 7)), pick((0, 100)), 64
        c["acc"][0]["arc"], c["arc"][0] = None, None
        c["resp"][0]["status"] = pick((0, 1))
        c["lazy_state"] = pick((0, 1))
    elif fam == 2:  # stipend addition overflow
        c["spec"], c["ecx"], c["flag24"], c["v265"] = pick((0, 1)), 1, 0, 0
        c["cfg"][0xc0], c["cfg"][0x78], c["f190"] = pick((1, 2300, 5)), 0, M64
        c["gas"], c["req"] = M64, M64 - pick((0, 1, 2))
        c["acc"][0]["arc"], c["arc"][0] = None, None
        c["resp"][0]["status"] = 0
    elif fam == 3:  # new account on an empty account at the spec-3 threshold
        c["spec"], c["ecx"], c["flag24"], c["v396"] = pick((2, 3, 4)), pick((0, 1, 2, 0x100)), 1, pick((3, 4, 1))
        c["acc"][0].update(hash=keccak_empty, w28=bytes(32), nonce=0, f8c=pick((8, 0xc, 0)))
        c["resp"][0]["status"] = pick((0, 1))
        c["gas"] = pick(((c["cfg"][0x88] + c["cfg"][0x80] + 5) & M64, 1 << 20, c["cfg"][0x88] - 1 if c["cfg"][0x88] else 0))
    return c


def case_row(i, c, mod):
    o = mod["out"]
    res = o["err"] if o["err"] is not None else ("ok" if mod["kind"] == "ok" else mod["kind"])
    return "\t".join(str(x) for x in (
        i, c["spec"], c["gas"], c["ecx"] & 0xffffffff, c["flag24"] & 0xff, c["req"],
        "-" if c["acc"][0]["arc"] is None else c["acc"][0]["arc"]["kind"], mod["kind"] if mod["kind"] != "ok" else res,
        mod["st"]["gas"], o["w8"] if o["w8"] is not None else "-", o["flag"] if o["flag"] is not None else "-", len(mod["ev"])))


MUTANTS = ("err36", "inc2", "nodrop", "spec6", "spec4", "len17", "off2", "nodel", "le", "ge", "unsat", "keep190", "s0", "div2",
           "nostipend", "wrap", "flagneg")


def stream_cases(n, label, keccak_empty):
    s = Stream(label)
    for i in range(n):
        yield i, make_case(s, keccak_empty)


def jcc_sites(image, which):
    h = HOSTS[which]
    rows, va = [], h["start"]
    end = va + HOST_LEN
    while va < end:
        f = decode(image.code(va, 16), va)
        if (0x70 <= f["op"] <= 0x7f) or (0x0f80 <= f["op"] <= 0x0f8f):
            rows.append((va, f["op"], f["len"]))
        va += f["len"]
    if va != end:
        fail("host decode does not end on its FDE end")
    return rows


def generate(out_dir, n_cases=6400, pool=300):
    global HOST_RANGE
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        fail("input binary SHA-256 does not match node #115")
    image = Image(data)
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fde = base.fde_rows(image, [HOSTS["alt"]["start"], HOSTS["ord"]["start"]])
    cases_total = mismatches = 0
    cov = {}
    coverage_hosts = {}
    ctl_rows, undetected = [], []
    cases_f = open(out_dir / "cases.tsv", "w")
    cases_f.write("case\thost\tspec\tgas\tvalue\tnewacct\treq\tcode_kind\tresult\tgas_after\tforwarded\tflag\tevents\n")
    keccak = None
    try:
        for which in ("alt", "ord"):
            h = HOSTS[which]
            if fde[h["start"]][1] - h["start"] != HOST_LEN:
                fail("unexpected host extent")
            HOST_RANGE = (h["start"], h["start"] + HOST_LEN)
            run = Run(image, which)
            keccak = run.keccak_empty
            cov_h = {}
            for i, c in stream_cases(n_cases, "call-host-" + which, keccak):
                obs = run.observe(c)
                mod = model(c, keccak)
                cases_total += 1
                bad = compare(c, obs, mod)
                if bad:
                    mismatches += 1
                    if mismatches < 6:
                        fail(f"{which} case {i}: mismatch {bad}: {obs['out']} {mod['out']} {obs['kind']} {mod['kind']} {obs['ev']} {mod['ev']} {obs['st']} {mod['st']}")
                if i % 2 == 0:
                    cases_f.write("%s\t%s\n" % (which, case_row(i, c, mod)))
            coverage_hosts[which] = cov_h
            # branch coverage on a fresh pass over a pool (exact outcome counts per jcc)
            sites = jcc_sites(image, which)
            tot = {}
            for i, c in stream_cases(1500, "call-host-cov-" + which, keccak):
                m, ev, kind = run.run(c)
                for key, v in m.branches.items():
                    tot[key] = tot.get(key, 0) + v
            cov[which] = [(va, tot.get((va, False), 0), tot.get((va, True), 0)) for va, _, _ in sites]
            # controls: model mutants
            pool_cases = [c for _, c in stream_cases(pool, "call-host-ctl-" + which, keccak)]
            obs_pool = [run.observe(c) for c in pool_cases]
            for mu in MUTANTS:
                caught = sum(1 for c, o in zip(pool_cases, obs_pool) if compare(c, o, model(c, keccak, frozenset([mu]))))
                ctl_rows.append((which, "model-" + mu, caught))
                if not caught:
                    undetected.append((which, "model-" + mu))
            # controls: invert every conditional branch of the real bytes
            for va, op, ln in sites:
                ov = {va: op ^ 1} if op < 0x100 else {va + 1: (op ^ 1) & 0xff}
                bad_run = Run(image, which, override=ov)
                caught = 0
                for c, o in zip(pool_cases, obs_pool):
                    try:
                        obs2 = bad_run.observe(c)
                        if compare(c, obs2, model(c, keccak)):
                            caught += 1
                    except (ToolError, Boundary, KeyError, AssertionError, OverflowError):
                        caught += 1
                ctl_rows.append((which, "jcc-%x" % va, caught))
                if not caught:
                    undetected.append((which, "jcc-%x" % va))
            # byte corruption of a code byte and an out-of-range input
            cor = Run(image, which, override={h["start"] + 0x14: 0x74})
            c0 = pool_cases[0]
            try:
                caught = int(bool(compare(c0, cor.observe(c0), model(c0, keccak))))
            except (ToolError, Boundary, KeyError, AssertionError):
                caught = 1
            ctl_rows.append((which, "byte-corruption", caught))
    finally:
        cases_f.close()
    kept = [r for r in ctl_rows if r[2]]
    with open(out_dir / "controls.tsv", "w") as f:
        f.write("host\tcontrol\tdetected_cases\n")
        for r in kept:
            f.write("%s\t%s\t%d\n" % r)
    with open(out_dir / "undetected-controls.tsv", "w") as f:
        f.write("host\tcontrol\n")
        for r in undetected:
            f.write("%s\t%s\n" % r)
    with open(out_dir / "branches.tsv", "w") as f:
        f.write("host\tjcc_va\tfallthrough\ttaken\n")
        for which in ("alt", "ord"):
            for va, a, b in cov[which]:
                f.write("%s\t%#x\t%d\t%d\n" % (which, va, a, b))
    with open(out_dir / "functions.tsv", "w") as f:
        f.write("host\tstart\tend\tloader\tprep\tcleanup\tinit\n")
        for which in ("alt", "ord"):
            h = HOSTS[which]
            f.write("%s\t%#x\t%#x\t%#x\t%#x\t%#x\t%#x\n" % (which, h["start"], fde[h["start"]][1], h["loader"], h["prep"], h["cleanup"], h["init"]))
    summary = dict(cases=cases_total, mismatches=mismatches, negative_controls=len(kept), negative_detected=len(kept),
                   undetected_not_counted=len(undetected), cases_per_host=n_cases)
    (out_dir / "measure.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    print(json.dumps(generate(args.out), sort_keys=True))


if __name__ == "__main__":
    main()
