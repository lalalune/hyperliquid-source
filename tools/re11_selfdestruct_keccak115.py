#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM SELFDESTRUCT handlers 0x2991290 / 0x2991cc0 and KECCAK256 0x29982d0 (+ twin).

SELFDESTRUCT (opcode 0xff) pops the beneficiary, loads it through the host account loader (GOT slot 0x64e6ce8,
stubbed here), computes whether the beneficiary is an empty account (pre-Spurious-Dragon flag test, or the
code-hash == KECCAK_EMPTY / zero-balance / zero-nonce test), walks the two-level host balance map (hashbrown,
0xa8-byte buckets keyed by the 20-byte address, balance at +0x40, flag byte at +0xa4) for the executing address
and the beneficiary, moves the balance, writes journal entries of kinds 2 (touch), 1 (destruct) and 4 (EIP-6780
balance-only transfer), pushes the address on the destruct list, charges the cold-access and new-account gas and
applies the refund bookkeeping.  KECCAK256 (opcode 0x20) pops offset and length, charges words * per-word gas,
expands memory through the resize helper, and hashes the memory slice with the sponge helpers absorb/squeeze
(stubbed with a pure-Python Keccak-f[1600]); the tail buffer, 0x01 ... 0x80 padding and rate 0x88 are the handler's.
The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real machine code with
the concrete x86-64 evaluator of tools/re11_transient_storage115.py (extended here with POR and MOVMSKPS) and
compares the final bytes of every modelled region, the return byte, the stub events and the panic message of each
case with one pure-Python reconstruction.  Negative controls show that wrong reconstructions and corrupted code
bytes are detected.  The binary is never executed.
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

Image, TraceMachine, Boundary, ToolError, fail = base.Image, base.TraceMachine, base.Boundary, base.ToolError, base.fail
Stream, addr_hash, M64, M256 = base.Stream, base.addr_hash, base.M64, base.M256
BINARY, SHA256 = base.BINARY, base.SHA256

SD_A, SD_B, KECCAK = 0x2991290, 0x2991cc0, 0x29982d0
SD_SIZE, KECCAK_SIZE = 2603, 850
SEED_GOT = base.SEED_GOT

INTERP_AT, HOST_AT, STK_AT, MAP_AT = base.INTERP_AT, base.HOST_AT, base.STK_AT, base.TABLE_AT
P_AT, ACCT_AT, JRN_AT, LST_AT = 0x7d00_0600_0000, 0x7d00_0700_0000, 0x7d00_0800_0000, 0x7d00_0900_0000
MEMOBJ_AT, DATA_AT = 0x7d00_0a00_0000, 0x7d00_0b00_0000
INTERP_SIZE, HOST_SIZE = 0x200, 0x400
STALE = 0x5c  # fill byte of the machine stack: unwritten frame bytes copied into journal entries show it
BUCKET = 0xa8


# ---------------------------------------------------------------- decoder / evaluator extension
def decode(code, va):
    """base decoder plus POR (0f eb) and MOVMSKPS (0f 50), which share the ModRM shape of PAND / PMOVMSKB."""
    p = 0
    while code[p] in (0x66, 0x2e, 0xf3, 0xf2, 0x64):
        p += 1
    if 0x40 <= code[p] <= 0x4f:
        p += 1
    if code[p] == 0x0f and code[p + 1] in (0xeb, 0x50):
        patched = bytearray(code)
        patched[p + 1] = {0xeb: 0xdb, 0x50: 0xd7}[code[p + 1]]
        form = base.decode(bytes(patched), va)
        form["op"] = 0x0f00 | code[p + 1]
        form["bytes"] = bytes(code[:form["len"]])
        return form
    return base.decode(code, va)


class Machine(TraceMachine):
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
        if f["op"] in (0x0feb, 0x0f50):
            self.seen.add(va)
            rm = f["rm"]
            if f["op"] == 0x0feb:
                other = self.xmm[rm[1]] if rm[0] == "r" else self.load(self.ea(rm, f, va), 16)
                self.xmm[f["reg"]] |= other
            else:
                v = self.xmm[rm[1]]
                self.set_reg(f["reg"], 32, sum(1 << i for i in range(4) if (v >> (32 * i + 31)) & 1), f)
            return (va + f["len"]) & M64
        return super().step(va)


def put(buf, off, size, value):
    buf[off:off + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")


def u(buf, off, size):
    return int.from_bytes(buf[off:off + size], "little")


def bswap(x):
    return int.from_bytes(x.to_bytes(8, "little"), "big")


# ---------------------------------------------------------------- Keccak-f[1600]
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b,
      0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088,
      0x0000000080008009, 0x000000008000000a, 0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]


def keccak_f(lanes):
    a = [[lanes[x + 5 * y] for y in range(5)] for x in range(5)]
    for rnd in range(24):
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & M64) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = ROT[x][y]
                v = a[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((v << r) | (v >> (64 - r))) & M64 if r else v
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= RC[rnd]
    return [a[x][y] for y in range(5) for x in range(5)]


def keccak256(data):
    rate, st = 136, [0] * 25
    buf = bytearray(data) + b"\x01"
    buf += bytes((-len(buf)) % rate)
    buf[-1] |= 0x80
    for off in range(0, len(buf), rate):
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(buf[off + 8 * i:off + 8 * i + 8], "little")
        st = keccak_f(st)
    return b"".join(x.to_bytes(8, "little") for x in st)[:32]


def absorb_blocks(state, data, rate):
    """Sponge helper stand-in: xor whole blocks into the lanes and permute; returns the unconsumed byte count."""
    lanes = [int.from_bytes(state[8 * i:8 * i + 8], "little") for i in range(25)]
    done = 0
    while len(data) - done >= rate:
        for i in range(rate // 8):
            lanes[i] ^= int.from_bytes(data[done + 8 * i:done + 8 * i + 8], "little")
        lanes = keccak_f(lanes)
        done += rate
    return b"".join(x.to_bytes(8, "little") for x in lanes), len(data) - done


# ---------------------------------------------------------------- hashbrown fixture (0xa8-byte buckets)
def layout(nb, entries, tombs, decoys):
    """entries [(key20, hash, payload)], tombs [slot], decoys [(slot, h2, key20)] -> (memory, ctrl offset, {key: slot})."""
    mask = nb - 1
    mem = bytearray([base.TABLE_FILL]) * (nb * BUCKET + nb + 16)
    ctrl_off = nb * BUCKET
    ctrl = [0xff] * nb
    for i in tombs:
        ctrl[i] = 0x80
    taken = set()
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
        mem[at:at + len(key)] = key
        mem[at + 0x40:at + 0x40 + len(payload)] = payload  # balance at +0x40 ... flags at +0xa4
    if 0xff not in ctrl:
        fail("table has no EMPTY slot")
    for i in range(nb):
        mem[ctrl_off + i] = ctrl[i]
    for i in range(16):
        mem[ctrl_off + nb + i] = ctrl[i % nb]
    return mem, ctrl_off, slots


def find_slot(mem, ctrl_off, nb, h, key):
    """hashbrown find as the handler runs it: 16-byte groups, h2 match, EMPTY ends the probe.  Returns bucket end offset."""
    mask, pos, stride, h2 = nb - 1, h & (nb - 1), 0, h >> 57
    while True:
        group = mem[ctrl_off + pos:ctrl_off + pos + 16]
        for i, cb in enumerate(group):
            if cb == h2:
                idx = (pos + i) & mask
                at = ctrl_off - (idx + 1) * BUCKET
                if bytes(mem[at:at + 20]) == key:
                    return ctrl_off - idx * BUCKET
        if 0xff in group:
            return None
        stride += 16
        pos = (pos + stride) & mask


# ---------------------------------------------------------------- site tables read from the code bytes
SD_SITES = {  # call-site offsets inside a SELFDESTRUCT copy -> role
    0xf5: "load", 0x421: "journal_grow", 0x64c: "transfer", 0x70d: "list_grow", 0x79d: "transfer", 0x7b3: "burn",
    0x81e: "journal_grow", 0x5e5: "none", 0x5f2: "none", 0x6e1: "none", 0xa0b: "ovf", 0xa18: "ovf", 0xa25: "ovf"}
SD_MSG = {"self1": 0x5de, "self2": 0x5eb, "target": 0x6da, "sum": 0xa04, "cost": 0xa11, "refund": 0xa1e}
KC_SITES = {0x184: "absorb", 0x1aa: "memcpy", 0x1e2: "memset", 0x20e: "absorb", 0x224: "squeeze", 0x303: "resize",
            0x31c: "ovf", 0x332: "ovf"}
KC_MSG = {"end": 0x315, "base": 0x322, "span": 0x32b}


class Panic(Exception):
    def __init__(self, role, msg):
        super().__init__(role)
        self.role, self.msg = role, msg


def callee_of(image, va):
    form = decode(image.code(va, 16), va)
    if form["op"] == 0xe8:
        return form["target"]
    if form["bytes"][:2] == b"\xff\x15":
        return image.word((va + form["len"] + form["rm"][4]) & M64)
    fail(f"call site {va:#x} is neither e8 nor ff 15")


def site_tables(image, start, sites, msgs):
    roles, msg = {}, {}
    for off, role in sites.items():
        roles.setdefault(role, set()).add(callee_of(image, start + off))
    for name, off in msgs.items():
        va = start + off
        form = decode(image.code(va, 16), va)
        if form["bytes"][:3] != b"\x48\x8d\x3d":
            fail(f"panic string load at {va:#x} is not lea rdi, [rip+disp]")
        msg[name] = (va + form["len"] + form["rm"][4]) & M64
    return roles, msg


# ---------------------------------------------------------------- shared helpers
POOL64 = (0, 1, 2, 3, 100, 2500, 4800, 1 << 62, (1 << 63) - 1, 1 << 63, M64 - 1, M64)
GASP = (0, 1, 50, 2599, 2600, 9000, 30000, 1 << 40, (1 << 63) - 1, M64 - 1)
BALP = (0, 1, 2, 10 ** 18, (1 << 64) - 1, 1 << 64, (1 << 128) - 1, 1 << 192, M256, M256 - 1)
SMALLP = (0, 1, 5, 100, 2500, 4800)


def rand_addr(s):
    k = s.below(8)
    if k == 0:
        return bytes(20)
    if k == 1:
        return bytes([0xff]) * 20
    return s.take(20)


def rand_bal(s):
    if s.below(10) < 5:
        return s.pick(BALP)
    return int.from_bytes(s.take(32), "little") >> (8 * s.below(32))


def frame_target(word):
    """The 20 frame bytes the handler builds from the popped word (limbs 0..2; limb 3 and the top of limb 2 are ignored)."""
    w0, w1, w2 = ((word >> (64 * i)) & M64 for i in range(3))
    return struct.pack("<I", (bswap(w2) >> 32) & 0xffffffff) + bswap(w1).to_bytes(8, "little") + bswap(w0).to_bytes(8, "little")


def words_for(tgt, s):
    """A stack word whose handler decoding is the 20 frame bytes tgt; the ignored bits are random."""
    w2 = bswap(struct.unpack("<I", tgt[0:4])[0] << 32 | s.below(1 << 32))
    w1, w0 = bswap(u(tgt, 4, 8)), bswap(u(tgt, 12, 8))
    word = w0 | w1 << 64 | w2 << 128 | s.below(1 << 64) << 192
    assert frame_target(word) == tgt
    return word


class Sim:
    """Byte-level copy of the modelled regions, addressed by the same virtual addresses as the evaluator."""

    def __init__(self, regs):
        self.r = {base_: bytearray(buf) for base_, buf in regs.values()}

    def find(self, va, n):
        for base_, buf in self.r.items():
            if base_ <= va and va + n <= base_ + len(buf):
                return buf, va - base_
        fail(f"model access outside regions at {va:#x}")

    def rd(self, va, n):
        buf, o = self.find(va, n)
        return bytes(buf[o:o + n])

    def wr(self, va, data):
        buf, o = self.find(va, len(data))
        buf[o:o + len(data)] = data

    def u(self, va, n):
        return int.from_bytes(self.rd(va, n), "little")

    def w(self, va, n, value):
        self.wr(va, (value & ((1 << (8 * n)) - 1)).to_bytes(n, "little"))


def clobber(mc):
    for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):  # a callee may use every caller-saved register
        mc.regs[r] = 0xc1c1_c1c1_c1c1_c1c1


# ---------------------------------------------------------------- SELFDESTRUCT: cases
def sd_case(s, i, copy):
    c = {"kind": "sd", "copy": copy, "i": i}
    c["spec"] = s.pick((0, 2, 3, 3, 10, 11, 11, 12, 16))
    c["hf"] = s.pick((0, 1, 2, 3, 3, 10, 11, 11, 12))
    c["static"] = 0 if s.below(100) < 94 else s.pick((1, 2, 0x80))
    c["n"] = 0 if s.below(100) < 4 else 1 + s.below(3)
    c["self"] = rand_addr(s)
    mode = s.below(100)
    if mode < 18:
        c["tgt"] = c["self"]
    else:
        c["tgt"] = rand_addr(s)
        if c["tgt"] == c["self"]:
            c["tgt"] = bytes([c["tgt"][0] ^ 1]) + c["tgt"][1:]
    c["word"] = words_for(c["tgt"], s)
    c["stack"] = [rand_bal(s) for _ in range(c["n"] - 1)] + ([c["word"]] if c["n"] else [])
    c["gas"] = s.pick(GASP) if s.below(100) < 40 else 1 << 40
    c["g190"], c["g198"], c["g1a0"] = s.pick(POOL64), s.pick(POOL64), s.pick((0, 10, M64 - 5, M64))
    c["p80"], c["p90"] = s.pick(SMALLP + (M64,)) if s.below(100) < 3 else s.pick(SMALLP), s.pick(SMALLP)
    c["pd8"], c["pb8"] = s.pick(SMALLP + (M64,)), s.pick(SMALLP + (M64,))
    c["p158"] = s.pick(POOL64)
    c["h265"], c["h395"] = s.take(1)[0], s.pick((0, 0, 1, 7))
    c["load_status"] = s.pick((0, 1, 1, 0, 1, 7, 2)) if s.below(100) < 96 else 2
    acct = {"hash": s.pick(("empty", "empty", "zero", "other", "lo-only")),
            "bal": s.pick((0, 0, 1, M256)), "nonce": s.pick((0, 0, 1, M64)), "flags": s.take(1)[0]}
    c["acct"] = acct
    c["secret"], c["seed"] = int.from_bytes(s.take(8), "little"), int.from_bytes(s.take(8), "little")
    c["nb"] = s.pick((4, 8, 16, 16, 32))
    ents = {}
    flagpool = (0, 0, 2, 4, 0x40, 0x80, 0xc2, 0x42, 0x82, 0x06, 0xff, 0x44)
    ents[c["self"]] = {"bal": rand_bal(s), "flags": s.pick(flagpool) | (s.below(1 << 24) << 8)}
    if c["tgt"] != c["self"]:
        ents[c["tgt"]] = {"bal": rand_bal(s), "flags": s.pick(flagpool) | (s.below(1 << 24) << 8)}
    for _ in range(s.below(3)):
        a = rand_addr(s)
        ents.setdefault(a, {"bal": rand_bal(s), "flags": s.pick(flagpool)})
    drop = s.below(100)
    if drop < 3:
        ents.pop(c["self"], None) if c["tgt"] != c["self"] or drop < 2 else None
    elif drop < 6:
        ents.pop(c["tgt"], None)
    if len(ents) + 1 >= c["nb"]:
        for a in list(ents)[c["nb"] - 3:]:
            if a not in (c["self"], c["tgt"]):
                ents.pop(a)
    c["ents"] = ents
    c["decoy"] = c["nb"] >= 8 and s.below(100) < 25
    c["items"] = len(ents) if s.below(100) < 97 else s.pick((0, len(ents) + 1))
    c["jlen"], c["llen"] = s.below(4), s.below(4)
    c["jcap"] = c["jlen"] if s.below(100) < 30 else c["jlen"] + 3
    c["lcap"] = c["llen"] if s.below(100) < 30 else c["llen"] + 3
    return c


def sd_regions(c):
    """Initial bytes of every modelled region for a SELFDESTRUCT case."""
    regs = {}
    it = bytearray([base.INTERP_FILL]) * INTERP_SIZE
    put(it, 0x28, 8, STK_AT)
    put(it, 0x30, 8, c["n"])
    it[0x78:0x8c] = c["self"]
    put(it, 0x188, 8, c["gas"])
    put(it, 0x190, 8, c["g190"])
    put(it, 0x198, 8, c["g198"])
    put(it, 0x1a0, 8, c["g1a0"])
    it[0x1a8], it[0x1a9] = c["static"], c["spec"]
    regs["interp"] = (INTERP_AT, it)
    host = bytearray([base.HOST_FILL]) * HOST_SIZE
    put(host, 0x250, 8, P_AT)
    host[0x265] = c["h265"]
    put(host, 0x288, 8, c["jcap"])
    put(host, 0x290, 8, JRN_AT)
    put(host, 0x298, 8, c["jlen"])
    put(host, 0x2a0, 8, c["lcap"])
    put(host, 0x2a8, 8, LST_AT)
    put(host, 0x2b0, 8, c["llen"])
    entries = []
    for addr, e in c["ents"].items():
        pay = bytearray([base.TABLE_FILL]) * 0x68
        pay[0:32] = e["bal"].to_bytes(32, "little")
        pay[0x64:0x68] = (e["flags"] & 0xffffffff).to_bytes(4, "little")
        entries.append((addr, addr_hash(addr, c["secret"], c["seed"]), bytes(pay)))
    decoys = []
    if c["decoy"]:
        h = addr_hash(c["self"], c["secret"], c["seed"])
        other = bytes([c["self"][0], c["self"][1] ^ 0x5a]) + c["self"][2:]
        if other not in c["ents"]:
            decoys.append((h & (c["nb"] - 1), h >> 57, other))
    mem, coff, _ = layout(c["nb"], entries, [], decoys)
    regs["map"] = (MAP_AT, mem)
    put(host, 0x338, 8, MAP_AT + coff)
    put(host, 0x340, 8, c["nb"] - 1)
    put(host, 0x350, 8, c["items"])
    put(host, 0x358, 8, c["secret"])
    host[0x395], host[0x396] = c["h395"], c["hf"]
    regs["host"] = (HOST_AT, host)
    p = bytearray([base.TABLE_FILL]) * 0x200
    for off, key in ((0x80, "p80"), (0x90, "p90"), (0xd8, "pd8"), (0xb8, "pb8"), (0x158, "p158"), (0x48, "p48")):
        put(p, off, 8, c.get(key, 0))
    regs["params"] = (P_AT, p)
    acct = bytearray([0x77]) * 0x100
    a = c["acct"]
    acct[0x28:0x48] = a["bal"].to_bytes(32, "little")
    acct[0x48:0x68] = {"empty": c["consts"]["h_lo"] + c["consts"]["h_hi"], "zero": bytes(32),
                       "other": bytes(range(32)), "lo-only": c["consts"]["h_lo"] + bytes(16)}[a["hash"]]
    put(acct, 0x68, 8, a["nonce"])
    acct[0x8c] = a["flags"]
    regs["acct"] = (ACCT_AT, acct)
    regs["journal"] = (JRN_AT, bytearray([0x99]) * (0x58 * 16))
    regs["list"] = (LST_AT, bytearray([0xaa]) * (20 * 16))
    regs["stack"] = (STK_AT, bytearray(b"".join(w.to_bytes(32, "little") for w in c["stack"]) or bytes(32)))
    return regs


# ---------------------------------------------------------------- SELFDESTRUCT: reconstruction
def satadd(a, b):
    """Signed 64-bit add that saturates (add; cmovo with 0x8000.. xor sign)."""
    s = ((a + b) & M64)
    sa, sb = a - (1 << 64) if a >> 63 else a, b - (1 << 64) if b >> 63 else b
    if -(1 << 63) <= sa + sb < (1 << 63):
        return s
    return 0x7fffffffffffffff if s >> 63 else 0x8000000000000000


def sd_model(c, sim, k, mut=frozenset()):
    """0x2991290 / 0x2991cc0 reconstructed on the Sim bytes; returns (result, events)."""
    ev = []
    gI = lambda off, n: sim.u(INTERP_AT + off, n)  # noqa: E731
    sI = lambda off, n, v: sim.w(INTERP_AT + off, n, v)  # noqa: E731
    gH = lambda off, n: sim.u(HOST_AT + off, n)  # noqa: E731
    gP = lambda off: sim.u(P_AT + off, 8)  # noqa: E731
    msg = k["msg"]

    def done(code):
        return ("ret", code), ev

    def lookup(addr, name):
        if gH(0x350, 8) == 0:
            raise Panic("none", msg[name])
        h = addr_hash(addr, gH(0x358, 8), c["seed"])
        end = find_slot(sim.r[MAP_AT], gH(0x338, 8) - MAP_AT, gH(0x340, 8) + 1, h, addr)
        if end is None:
            raise Panic("none", msg[name])
        return MAP_AT + end

    def jpush(parts):
        jl, cap = gH(0x298, 8), gH(0x288, 8)
        if jl == cap:
            ev.append(("journal_grow", 0x288))
            sim.w(HOST_AT + 0x288, 8, cap + 4)
        for off, data in parts:
            sim.wr(gH(0x290, 8) + jl * 0x58 + off, data)
        sim.w(HOST_AT + 0x298, 8, jl + 1)

    try:
        if gI(0x1a8, 1) != (0 if "static_eq1" not in mut else 1):
            return done(0x28)
        n = gI(0x30, 8)
        if n == 0:
            return done(0x2c)
        word = sim.u(STK_AT + 32 * (n - 1), 32)
        sI(0x30, 8, n - 1)
        tgt = frame_target(word)
        me = sim.rd(INTERP_AT + 0x78, 20)
        frame = bytearray([STALE]) * 0x148
        frame[8:0x1c] = tgt
        frame[0x20:0x34] = me
        base_cost = gP(0x90) + gP(0x80)
        if base_cost >> 64:
            raise Panic("ovf", msg["sum"])
        spec, gas0 = gI(0x1a9, 1), gI(0x188, 8)
        below = int(gas0 < base_cost)
        ev.append(("load", tgt.hex(), below, 0x270, 0x398))
        status = c["load_status"]
        if status == 2:
            return done(0x20)
        cold = status != 0
        a = sim.rd(ACCT_AT, 0x100)
        hf = gH(0x396, 1)
        fl8c = a[0x8c]
        if hf <= (2 if "fork_le3" not in mut else 3):
            empty = int(bool(fl8c & 8) and not fl8c & 4)
        else:
            if a[0x48:0x58] == k["h_lo"] and a[0x58:0x68] == k["h_hi"]:
                hash_ok = True
            else:
                hash_ok = a[0x48:0x68] == bytes(32)
            if not hash_ok:
                empty = 0
            elif a[0x28:0x48] != bytes(32):
                empty = 0
            else:
                empty = int(u(a, 0x68, 8) == 0) if "nonce_ignored" not in mut else 1
        same = tgt == me
        r9 = 0
        if not same:
            end_me = lookup(me, "self1")
            bal_me = sim.rd(end_me - 0x68, 32)
            end_t = lookup(tgt, "target")
            if not sim.u(end_t - 4, 1) & 4 or "touch_always" in mut:
                jpush([(0, b"\x02"), (1, bytes(frame[8:0x18])), (0x11, bytes(frame[0x18:0x1c]))])
                sim.w(end_t - 4, 1, sim.u(end_t - 4, 1) | 4)
            nb_ = (int.from_bytes(sim.rd(end_t - 0x68, 32), "little") + int.from_bytes(bal_me, "little")) & M256
            if "carry_drop" in mut:
                nb_ = (nb_ & ((1 << 192) - 1)) | (int.from_bytes(sim.rd(end_t - 0x68, 32), "little") >> 192 << 192)
            sim.wr(end_t - 0x68, nb_.to_bytes(32, "little"))
            r9 = 1
        end_me = lookup(me, "self2")
        oldbal = sim.rd(end_me - 0x68, 32)
        frame[0x40:0x60] = oldbal
        fl = sim.u(end_me - 4, 1)
        c40 = (hf >= 0x0b) and not fl & 0x80
        if "ignore_bit80" in mut:
            c40 = hf >= 0x0b
        r10 = 0
        r13 = me[0]  # low byte of the executing-address qword the handler keeps in r12
        path = None
        if fl & 2:
            r10 = 1 if not fl & 0x40 else 2
            path = "B" if c40 else "A"
            r13_a = r10
        elif c40:
            path, r10 = "B", 0
        else:
            path, r13_a = "A", 0
            if gH(0x395, 1) == 0 or "list_ignore_flag" in mut:
                ll, lc = gH(0x2b0, 8), gH(0x2a0, 8)
                if ll == lc:
                    ev.append(("list_grow", 0x2a0))
                    sim.w(HOST_AT + 0x2a0, 8, lc + 4)
                sim.wr(gH(0x2a8, 8) + ll * 20, me)
                sim.w(HOST_AT + 0x2b0, 8, ll + 1)
        if path == "A":
            sim.w(end_me - 4, 1, fl | 0x42)
            sim.wr(end_me - 0x68, bytes(32))
            if not same:
                ev.append(("transfer", 0x270, tgt.hex(), oldbal.hex()))
            else:
                ev.append(("burn", 0x270, oldbal.hex()))
            frame[0xc0:0xe0] = oldbal
            frame[0x80:0x94] = me
            frame[0x60:0x74] = tgt
            r10 = r13_a
            kind, r13 = 1, r13_a
        elif r9:
            sim.wr(end_me - 0x68, bytes(32))
            ev.append(("transfer", 0x270, tgt.hex(), oldbal.hex()))
            pack = me[1:20] + tgt
            frame[0x100:0x127] = pack
            frame[0xc0:0xe0] = oldbal
            frame[0x80:0x94] = pack[0:20]
            frame[0x60:0x73] = tgt[1:20]
            kind = 4
        else:
            kind = None
        if kind is not None:
            parts = [(0, bytes([kind])), (1, bytes([r13])), (0x12, bytes(frame[0x90:0x94])), (2, bytes(frame[0x80:0x90])),
                     (0x16, bytes(frame[0x60:0x70])), (0x26, bytes(frame[0x70:0x74])), (0x2a, bytes(frame[0xba:0xca])),
                     (0x3a, bytes(frame[0xca:0xda])), (0x48, bytes(frame[0xd8:0xe0]))]
            jpush(parts)
        nz = int(oldbal != bytes(32))
        if spec > 2:
            charged = empty & nz
        else:
            charged = empty
        if "ignore_nz" in mut:
            charged = empty
        cost, dl = (gP(0xd8), 1) if charged else (0, 0)
        if cold:
            if base_cost >> 64:
                raise Panic("ovf", msg["sum"])
            if (cost + base_cost) >> 64:
                raise Panic("ovf", msg["cost"])
            cost += base_cost
        if "no_cold" in mut:
            cost -= base_cost if cold else 0
        if gas0 < cost:
            return done(0x20)
        left = gas0 - cost
        sI(0x188, 8, left)
        if gH(0x265, 1) & dl:
            p158, g190, g198 = gP(0x158), gI(0x190, 8), gI(0x198, 8)
            if g190 >= p158:
                sI(0x198, 8, satadd(p158, g198))
                sI(0x190, 8, g190 - p158)
            else:
                need = p158 - g190
                if left < need:
                    return done(0x20)
                sI(0x188, 8, left - need)
                sI(0x198, 8, satadd(p158, g198))
                sI(0x190, 8, 0)
        if r10 == 2:
            return done(3)
        a1, b1 = gI(0x1a0, 8), gP(0xb8)
        sa, sb = a1 - (1 << 64) if a1 >> 63 else a1, b1 - (1 << 64) if b1 >> 63 else b1
        if not -(1 << 63) <= sa + sb < (1 << 63):
            raise Panic("ovf", msg["refund"])
        sI(0x1a0, 8, a1 + b1)
        return done(3)
    except Panic as p:
        return ("panic", p.role, p.msg), ev


# ---------------------------------------------------------------- KECCAK256: cases, regions, reconstruction
OFFP = (0, 0, 1, 31, 32, 33, 64, 100, 300)
LENP = (0, 1, 31, 32, 33, 64, 135, 136, 137, 200, 271, 272, 273, 408, 500, 0x600)
DATA_SIZE = 0x1000
EMPTY_KECCAK = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


def kc_case(s, i, start):
    c = {"kind": "kc", "copy": start, "i": i}
    c["n"] = s.pick((0, 1, 2, 2, 2, 2, 2, 2, 3, 4))
    off, ln = s.pick(OFFP), s.pick(LENP)
    r = s.below(100)
    if r < 4:
        ln |= 1 << (64 * (1 + s.below(3)))
    elif r < 8:
        off |= 1 << (64 * (1 + s.below(3)))
    elif r < 11:
        off = M64 - s.below(4)
        ln = 1 + s.below(8)
    elif r < 13:
        ln = s.pick((1 << 40, M64, 1 << 63))
    c["off"], c["len"] = off, ln
    c["stack"] = [rand_bal(s) for _ in range(max(0, c["n"] - 2))] + ([ln, off] if c["n"] >= 2 else [off] * c["n"])
    c["i18"] = s.pick((0, 0, 5, 32, 0x40))
    c["gas"] = s.pick(GASP) if s.below(100) < 35 else 1 << 40
    c["p48"] = s.pick((0, 3, 6, 6, 6, 1 << 60, M64))
    c["i170"] = s.pick((0, 1, 2, 10, 0x1000, 1 << 40))
    c["ctr"] = s.below(5)
    c["resize_ret"] = 0 if s.below(100) < 85 else s.pick((0x20, 0x21, 0x2d, 0xff))
    span = off + ln + c["i18"]
    if c["n"] >= 2 and off < (1 << 64) and ln < (1 << 64) and span > 0xf00 and span < (1 << 64):
        c["i170"] = 0  # force the resize call; the data region is only 0x1000 bytes
        if c["resize_ret"] == 0:
            c["resize_ret"] = 0x20
        c["gas"] = min(c["gas"], M64 - 1)
    return c


def kc_regions(c, data):
    regs = {}
    it = bytearray([base.INTERP_FILL]) * INTERP_SIZE
    put(it, 0x10, 8, MEMOBJ_AT)
    put(it, 0x18, 8, c["i18"])
    put(it, 0x28, 8, STK_AT)
    put(it, 0x30, 8, c["n"])
    put(it, 0x170, 8, c["i170"])
    put(it, 0x188, 8, c["gas"])
    regs["interp"] = (INTERP_AT, it)
    host = bytearray([base.HOST_FILL]) * HOST_SIZE
    put(host, 0x250, 8, P_AT)
    regs["host"] = (HOST_AT, host)
    p = bytearray([base.TABLE_FILL]) * 0x200
    put(p, 0x48, 8, c["p48"])
    regs["params"] = (P_AT, p)
    mo = bytearray([0x88]) * 0x40
    put(mo, 0x10, 8, c["ctr"])
    put(mo, 0x20, 8, DATA_AT)
    regs["memobj"] = (MEMOBJ_AT, mo)
    regs["data"] = (DATA_AT, bytearray(data))
    regs["stack"] = (STK_AT, bytearray(b"".join(w.to_bytes(32, "little") for w in c["stack"]) or bytes(32)))
    return regs


def kc_hash(data, mut):
    if "pad06" in mut:
        rate, st = 136, [0] * 25
        buf = bytearray(data) + b"\x06"
        buf += bytes((-len(buf)) % rate)
        buf[-1] |= 0x80
        for off in range(0, len(buf), rate):
            for i in range(rate // 8):
                st[i] ^= int.from_bytes(buf[off + 8 * i:off + 8 * i + 8], "little")
            st = keccak_f(st)
        return b"".join(x.to_bytes(8, "little") for x in st)[:32]
    return keccak256(data)


def kc_model(c, sim, k, mut=frozenset()):
    """0x29982d0 reconstructed: pop offset and length, charge words * per-word gas, expand memory, hash the slice."""
    ev = []
    gI = lambda off, n: sim.u(INTERP_AT + off, n)  # noqa: E731
    msg = k["msg"]
    n = gI(0x30, 8)
    if n < 2:
        return ("ret", 0x2c), ev
    off_w = sim.u(STK_AT + 32 * (n - 1), 32)
    len_w = sim.u(STK_AT + 32 * (n - 2), 32)
    sim.w(INTERP_AT + 0x30, 8, n - 1)
    slot = STK_AT + 32 * (n - 2)
    if "swap_off_len" in mut:
        off_w, len_w = len_w, off_w
    if len_w >> 64 and "len_limbs_ignored" not in mut:
        return ("ret", 0x24), ev
    ln = len_w & M64
    words = (ln >> 5) + (1 if ln & 31 else 0)
    if "cost_floor" in mut:
        words = ln >> 5
    cost = words * sim.u(P_AT + 0x48, 8)
    if cost >> 64:
        cost = M64

    def charge():
        gas = gI(0x188, 8)
        if gas < cost:
            return False
        sim.w(INTERP_AT + 0x188, 8, gas - cost)
        return True
    if not charge():
        return ("ret", 0x20), ev
    if ln == 0:
        sim.wr(slot, int.from_bytes(EMPTY_KECCAK, "big").to_bytes(32, "little"))
        return ("ret", 0), ev
    if off_w >> 64 and "off_limbs_ignored" not in mut:
        return ("ret", 0x24), ev
    off = off_w & M64
    end = off + ln
    end = end if end < (1 << 64) else M64
    mw = (end >> 5) + (1 if end & 31 else 0)
    if mw > gI(0x170, 8):
        ev.append(("resize", 0x170, 0, 0x250, mw))
        if c["resize_ret"]:
            return ("ret", c["resize_ret"]), ev
        sim.w(INTERP_AT + 0x170, 8, mw)
    try:
        if off + ln >> 64:
            raise Panic("ovf", msg["end"])
        ctr = sim.u(MEMOBJ_AT + 0x10, 8)
        sim.w(MEMOBJ_AT + 0x10, 8, ctr + 1)
        i18 = gI(0x18, 8)
        if off + i18 >> 64:
            raise Panic("ovf", msg["base"])
        if i18 + off + ln >> 64:
            raise Panic("ovf", msg["span"])
        ptr = (off + i18 + sim.u(MEMOBJ_AT + 0x20, 8)) & M64
        data = sim.rd(ptr, ln)
        if ln >= 0x88:
            ev.append(("absorb", ln, 0x88))
        rem = ln % 0x88 if ln >= 0x88 else ln
        if rem or ln < 0x88:  # a zero remainder jumps over the tail copy
            ev.append(("memcpy", rem))
        ev += [("memset", 0x88 - rem, 0), ("absorb", 0x88, 0x88), ("squeeze", 32, 0x88)]
        sim.w(MEMOBJ_AT + 0x10, 8, ctr)
        sim.wr(slot, int.from_bytes(kc_hash(data, mut), "big").to_bytes(32, "little"))
        return ("ret", 0), ev
    except Panic as p:
        return ("panic", p.role, p.msg), ev


# ---------------------------------------------------------------- machine harness
def wrmem(mc, at, data):
    for lo, hi, buf in mc.regions:
        if lo <= at and at + len(data) <= hi:
            buf[at - lo:at - lo + len(data)] = data
            return
    fail(f"stub write outside regions at {at:#x}")


def rdmem(mc, at, n):  # noqa: F811
    for lo, hi, buf in mc.regions:
        if lo <= at and at + n <= hi:
            return bytes(buf[at - lo:at - lo + n])
    fail(f"stub read outside regions at {at:#x}")


def make_stubs(c, k, events):
    st = {}
    for t in k["roles"].get("none", ()):
        st[t] = "none"
    for t in k["roles"].get("ovf", ()):
        st[t] = "ovf"

    def load(mc):
        out, tgt = mc.regs[7], rdmem(mc, mc.regs[1], 20)
        events.append(("load", tgt.hex(), mc.regs[8] & 0xff, mc.regs[6] - HOST_AT, mc.regs[2] - HOST_AT))
        mc.store(out, 8, ACCT_AT)
        mc.store(out + 0x38, 1, c["load_status"])
        clobber(mc)

    def grow(name):
        def f(mc):
            at = mc.regs[7]
            events.append((name, at - HOST_AT))
            mc.store(at, 8, mc.load(at, 8) + 4)
            clobber(mc)
        return f

    def transfer(mc):
        events.append(("transfer", mc.regs[7] - HOST_AT, rdmem(mc, mc.regs[2], 20).hex(), rdmem(mc, mc.regs[1], 32).hex()))
        clobber(mc)

    def burn(mc):
        events.append(("burn", mc.regs[7] - HOST_AT, rdmem(mc, mc.regs[2], 32).hex()))
        clobber(mc)

    def absorb(mc):
        state_p, data_p, n, rate = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1] & 0xffffffff
        new, rem = absorb_blocks(rdmem(mc, state_p, 200), rdmem(mc, data_p, n), rate)
        wrmem(mc, state_p, new)
        events.append(("absorb", n, rate))
        clobber(mc)
        mc.regs[0] = rem

    def memcpy(mc):
        dst, src, n = mc.regs[7], mc.regs[6], mc.regs[2]
        wrmem(mc, dst, rdmem(mc, src, n))
        events.append(("memcpy", n))
        clobber(mc)
        mc.regs[0] = dst

    def memset(mc):
        dst, byte, n = mc.regs[7], mc.regs[6] & 0xff, mc.regs[2]
        wrmem(mc, dst, bytes([byte]) * n)
        events.append(("memset", n, byte))
        clobber(mc)
        mc.regs[0] = dst

    def squeeze(mc):
        state_p, out_p, n, rate = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1] & 0xffffffff
        wrmem(mc, out_p, rdmem(mc, state_p, 200)[:n])
        events.append(("squeeze", n, rate))
        clobber(mc)

    def resize(mc):
        ip, ia, hp, words = mc.regs[7], mc.regs[6], mc.regs[2], mc.regs[1]
        events.append(("resize", ip - INTERP_AT, ia - INTERP_AT, hp - HOST_AT, words))
        if c["resize_ret"] == 0:
            mc.store(ip, 8, words)
        clobber(mc)
        mc.regs[0] = c["resize_ret"]
    table = {"load": load, "journal_grow": grow("journal_grow"), "list_grow": grow("list_grow"), "transfer": transfer,
             "burn": burn, "absorb": absorb, "memcpy": memcpy, "memset": memset, "squeeze": squeeze, "resize": resize}
    for role, fn in table.items():
        for t in k["roles"].get(role, ()):
            st[t] = fn
    return st


def run_machine(m, entry, c, regs, k):
    m.reset()
    m.regions[0][2][:] = bytes([STALE]) * len(m.regions[0][2])
    for base_, buf in regs.values():
        m.add_region(base_, len(buf), bytes(buf))
    m.add_region(m.image.word(SEED_GOT), 8, c["seed"].to_bytes(8, "little") if "seed" in c else bytes(8))
    events = []
    m.stubs = make_stubs(c, k, events)
    for r, v in zip((3, 12, 13, 14, 15, 5), base.SAVED):
        m.regs[r] = v
    m.regs[7], m.regs[6] = INTERP_AT, HOST_AT
    got = {"events": events}
    try:
        m.run(entry, limit=40000)
    except Boundary as b:
        got["ret"] = ("panic", b.kind, b.regs[7])
    else:
        got["ret"] = ("ret", m.regs[0] & 0xff)
        got["regs_ok"] = [m.regs[r] for r in (3, 12, 13, 14, 15, 5)] == base.SAVED and m.regs[4] == base.STACK_TOP - 0x100
    got["final"] = {lo: bytes(buf) for lo, hi, buf in m.regions if lo in {b for b, _ in regs.values()}}
    return got


def same(want, got, sim):
    if want[0] != got["ret"] or want[1] != got["events"]:
        return False
    if got["ret"][0] == "ret" and not got["regs_ok"]:
        return False
    return all(bytes(buf) == got["final"][b] for b, buf in sim.r.items())


DATA_BYTES = None


def data_bytes():
    global DATA_BYTES
    if DATA_BYTES is None:
        DATA_BYTES = Stream("kc-data").take(DATA_SIZE)
    return DATA_BYTES


def consts_for(image, start, kind):
    sites, msgs = (SD_SITES, SD_MSG) if kind == "sd" else (KC_SITES, KC_MSG)
    roles, msg = site_tables(image, start, sites, msgs)
    k = {"roles": roles, "msg": msg, "h_lo": image.read(0x4537f0, 16), "h_hi": image.read(0x452020, 16)}
    seen = [t for v in roles.values() for t in v]
    if len(seen) != len(set(seen)):
        fail("two call-site roles share a callee")
    return k


def run_case(m, image, c, k, mut=frozenset()):
    c = dict(c, consts=k)
    if c["kind"] == "sd":
        regs = sd_regions(c)
        sim = Sim(regs)
        want = sd_model(c, sim, k, mut)
    else:
        regs = kc_regions(c, data_bytes())
        sim = Sim(regs)
        want = kc_model(c, sim, k, mut)
    got = run_machine(m, c["copy"], c, regs, k)
    return want, got, sim, same(want, got, sim)


# ---------------------------------------------------------------- the case list
SD_PER_COPY, KC_PER_COPY = 4200, 1800


def twin_start(image):
    return KC_TWIN


KC_TWIN = None


def case_stream(image=None):
    """Deterministic cases: (case, copy label); SELFDESTRUCT copies alternate seeds, then KECCAK256."""
    for label, start in (("sd-a", SD_A), ("sd-b", SD_B)):
        s = Stream(label)
        for i in range(SD_PER_COPY):
            yield label, sd_case(s, i, start)
    for label, start in (("kc", KECCAK),) + ((("kc-twin", KC_TWIN),) if KC_TWIN else ()):
        s = Stream(label)
        for i in range(KC_PER_COPY):
            yield label, kc_case(s, i, start)


# ---------------------------------------------------------------- static evidence
def sweep(image, lo, hi):
    rows, va = [], lo
    while va < hi:
        if image.code(va, 1)[0] == 0xcc:
            va += 1
            continue
        form = decode(image.code(va, 16), va)
        rows.append((va, form))
        va += form["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


def handler_slots(image, starts):
    """RELATIVE relocations whose addend is a handler start: the opcode-table slots that dispatch to it."""
    out = {f"{s:#x}": [] for s in starts}
    for slot, target in sorted(image.relative.items()):
        if target in starts and slot not in image.imports:
            out[f"{target:#x}"].append(f"{slot:#x}")
    return out


def find_twin(image, start, size):
    """The other FDE of the same size whose instruction stream equals start's apart from rip/rel displacements."""
    import fde_extents
    _, fdes = fde_extents.eh_frame_records(image.data, image.secs)

    def shape(lo, hi):
        out = []
        for va, f in sweep(image, lo, hi):
            by = bytearray(f["bytes"])
            if f.get("rm") and f["rm"][0] == "m" and f["rm"][1] == "rip":
                by[-4:] = bytes(4)
            if "rel" in f:
                by = bytearray([f["op"] & 0xff, 0])
            out.append(bytes(by))
        return out
    ref = shape(start, start + size)
    found = []
    for f in fdes:
        if f["end"] - f["start"] != size or f["start"] == start or image.code(f["start"], 8) != image.code(start, 8):
            continue
        try:
            if shape(f["start"], f["end"]) == ref:
                found.append(f["start"])
        except ToolError:
            continue
    return found


def static_evidence(image, funcs):
    import fde_extents
    _, fdes = fde_extents.eh_frame_records(image.data, image.secs)
    rows = {f["start"]: f["end"] for f in fdes if f["start"] in funcs}
    info, decoded = {}, {}
    for f in funcs:
        if f not in rows:
            fail(f"no FDE starts at {f:#x}")
        lo, hi = f, rows[f]
        decoded[f] = sweep(image, lo, hi)
        k = consts_for(image, f, "sd" if f in (SD_A, SD_B) else "kc")
        info[f"{f:#x}"] = {
            "fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
            "instructions": len(decoded[f]),
            "call_roles": {r: sorted(f"{t:#x}" for t in ts) for r, ts in sorted(k["roles"].items())},
            "panic_strings": {n: f"{v:#x}" for n, v in sorted(k["msg"].items())}}
    return info, decoded


def got_names(image):
    out = {}
    for slot in (0x64df508, 0x64df750):
        out[f"{slot:#x}"] = image.import_name(slot)
    return out


# ---------------------------------------------------------------- controls
SD_BYTE_MUTANTS = [  # (offset in a SELFDESTRUCT copy, byte index, old, new, meaning)
    (0x11, 6, 0x00, 0x01, "static-call test: 0 -> 1"),
    (0x104, 3, 0x02, 0x03, "loader failure status 2 -> 3"),
    (0x12a, 3, 0x02, 0x03, "old-fork empty test bound: fork <= 2 -> <= 3"),
    (0x1a4, 1, 0x08, 0x04, "old-fork flag bit 8 -> 4"),
    (0x242, 3, 0x39, 0x38, "beneficiary h2 shift 57 -> 56"),
    (0x295, 3, 0xa8, 0xa0, "bucket stride 0xa8 -> 0xa0"),
    (0x5c1, 4, 0x0b, 0x0c, "EIP-6780 fork threshold 0x0b -> 0x0c"),
    (0x5fa, 2, 0x40, 0x20, "second-destruct bit 0x40 -> 0x20"),
    (0x74d, 1, 0x42, 0x40, "destruct flags |= 0x42 -> 0x40"),
    (0x8be, 4, 0x02, 0x03, "gas fork bound spec > 2 -> > 3"),
    (0x8d2, 3, 0xd8, 0xd0, "new-account cost +0xd8 -> +0xd0"),
    (0x92f, 3, 0x65, 0x66, "refund flag byte +0x265 -> +0x266"),
    (0x9d5, 1, 0x03, 0x04, "success result 3 -> 4"),
    (0x9d7, 3, 0x02, 0x01, "no-refund kind 2 -> 1"),
    (0x9e8, 3, 0xb8, 0xb0, "refund increment +0xb8 -> +0xb0")]
SD_B_PICK = (0, 6, 10, 12, 13, 14)
KC_BYTE_MUTANTS = [
    (0x15, 3, 0x02, 0x03, "needs 2 stack words -> 3"),
    (0x5e, 3, 0x50, 0x58, "per-word gas pointer +0x250 -> +0x258"),
    (0x7b, 3, 0x48, 0x40, "per-word gas field +0x48 -> +0x40"),
    (0xd4, 3, 0x70, 0x78, "memory size word +0x170 -> +0x178"),
    (0xf5, 3, 0x10, 0x18, "borrow counter +0x10 -> +0x18"),
    (0x16b, 3, 0x88, 0x80, "absorb threshold 0x88 -> 0x80"),
    (0x179, 1, 0x88, 0x80, "sponge rate 0x88 -> 0x80"),
    (0x1e8, 8, 0x01, 0x06, "padding byte 0x01 -> 0x06"),
    (0x1f1, 7, 0x80, 0x40, "padding closing bit 0x80 -> 0x40"),
    (0x2c6, 1, 0x24, 0x25, "invalid-argument result 0x24 -> 0x25"),
    (0x2ca, 1, 0x2c, 0x2d, "underflow result 0x2c -> 0x2d"),
    (0x2e5, 1, 0x20, 0x21, "out-of-gas result 0x20 -> 0x21")]
SD_MODEL_MUTANTS = ["static_eq1", "fork_le3", "nonce_ignored", "carry_drop", "ignore_bit80", "ignore_nz", "no_cold",
                    "touch_always", "list_ignore_flag"]
KC_MODEL_MUTANTS = ["pad06", "cost_floor", "off_limbs_ignored", "len_limbs_ignored", "swap_off_len"]
CTL_CASES = 700
ROW_EVERY = 2


def control_cases(image, kinds):
    """The first CTL_CASES cases of each label with the machine result (computed once, unmutated)."""
    out = {}
    for label, c in case_stream():
        out.setdefault(label, [])
        if len(out[label]) < CTL_CASES:
            out[label].append((c, KS[c["copy"]]))
    return out


def detects_model(image, entries, mut, m, cache):
    for idx, (c, k) in enumerate(entries):
        _, got, _, _ = cache[idx]
        cc = dict(c, consts=k)
        regs = sd_regions(cc) if c["kind"] == "sd" else kc_regions(cc, data_bytes())
        sim = Sim(regs)
        want = sd_model(cc, sim, k, mut) if c["kind"] == "sd" else kc_model(cc, sim, k, mut)
        if not same(want, got, sim):
            return True
    return False


def detects_code(image, entries, override):
    m = Machine(image, override)
    for c, k in entries:
        try:
            _, _, _, ok = run_case(m, image, c, k)
        except ToolError:
            return True
        if not ok:
            return True
    return False


def controls(image, per_label):
    rows = []
    caches = {}
    base_m = Machine(image)
    for label, entries in per_label.items():
        caches[label] = [run_case(base_m, image, c, k) for c, k in entries]
    for name in SD_MODEL_MUTANTS:
        hit = any(detects_model(image, per_label[lb], frozenset([name]), base_m, caches[lb]) for lb in ("sd-a", "sd-b"))
        rows.append(("model", f"SELFDESTRUCT {name}", int(hit)))
    for name in KC_MODEL_MUTANTS:
        hit = detects_model(image, per_label["kc"], frozenset([name]), base_m, caches["kc"])
        rows.append(("model", f"KECCAK256 {name}", int(hit)))
    for lb, start, picks in (("sd-a", SD_A, range(len(SD_BYTE_MUTANTS))), ("sd-b", SD_B, SD_B_PICK)):
        for i in picks:
            off, idx, old, new, what = SD_BYTE_MUTANTS[i]
            va = start + off + idx
            if image.code(va, 1)[0] != old:
                fail(f"byte mutant at {va:#x}: expected {old:#04x}")
            rows.append(("code", f"{va:#x}={new:#04x} {what}", int(detects_code(image, per_label[lb], {va: new}))))
    for lb, start in (("kc", KECCAK),) + ((("kc-twin", KC_TWIN),) if KC_TWIN else ()):
        for off, idx, old, new, what in KC_BYTE_MUTANTS:
            va = start + off + idx
            if image.code(va, 1)[0] != old:
                fail(f"byte mutant at {va:#x}: expected {old:#04x}")
            rows.append(("code", f"{va:#x}={new:#04x} {what}", int(detects_code(image, per_label[lb], {va: new}))))
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
    bad = bytes([EMPTY_KECCAK[0] ^ 1]) + EMPTY_KECCAK[1:]
    rows.append(("input", "wrong KECCAK_EMPTY constant", int(bad != image.read(0x4537f0, 16) + image.read(0x452020, 16))))
    return rows


# ---------------------------------------------------------------- output
KS = {}


def tag(x):
    return f"{x:#x}" if x < 1 << 20 else (f"2^{x.bit_length() - 1}" if x & (x - 1) == 0 else "w" + hashlib.sha256(
        x.to_bytes(32, "little")).hexdigest()[:6])


def describe(c):
    if c["kind"] == "sd":
        a = c["acct"]
        return (f"spec={c['spec']},hf={c['hf']},static={c['static']},n={c['n']},same={int(c['tgt'] == c['self'])},"
                f"load={c['load_status']},acct={a['hash']}/{int(a['bal'] != 0)}/{int(a['nonce'] != 0)}/{a['flags']:#04x},"
                f"nb={c['nb']},items={c['items']}/{len(c['ents'])},selffl={c['ents'].get(c['self'], {}).get('flags', 0) & 0xff:#04x},"
                f"gas={tag(c['gas'])},h265={c['h265'] & 1},h395={c['h395']},j={c['jlen']}/{c['jcap']},l={c['llen']}/{c['lcap']}")
    return (f"n={c['n']},off={tag(c['off'])},len={tag(c['len'])},i18={c['i18']},gas={tag(c['gas'])},p48={tag(c['p48'])},"
            f"i170={tag(c['i170'])},resize={c['resize_ret']:#x}")


def classify(c, want):
    res, ev = want
    names = sorted({e[0] for e in ev})
    if res[0] == "panic":
        head = f"panic-{res[1]}"
    else:
        head = f"ret-{res[1]:#04x}"
    return f"{c['kind']}/{head}/" + "+".join(names)


def final_digest(sim):
    h = hashlib.sha256()
    for b in sorted(sim.r):
        h.update(bytes(sim.r[b]))
    return h.hexdigest()[:12]


def generate(out):
    global KC_TWIN
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    twins = find_twin(image, KECCAK, KECCAK_SIZE)
    KC_TWIN = twins[0] if twins else None
    starts = [SD_A, SD_B, KECCAK] + ([KC_TWIN] if KC_TWIN else [])
    for st in starts:
        KS[st] = consts_for(image, st, "sd" if st in (SD_A, SD_B) else "kc")
    if (KS[SD_A]["h_lo"] + KS[SD_A]["h_hi"]) != EMPTY_KECCAK or keccak256(b"") != EMPTY_KECCAK:
        fail("KECCAK_EMPTY constants do not match the reconstructed Keccak-f")
    if keccak256(b"abc").hex() != "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45":
        fail("reconstructed Keccak-f fails the abc vector")
    info, decoded = static_evidence(image, starts)
    m = Machine(image)
    classes, bad, count = {}, 0, 0
    with open(out / "cases.tsv", "w") as fh:
        fh.write("case\tlabel\tinput\toutcome\tresult\tmatch\n")
        for label, c in case_stream():
            k = KS[c["copy"]]
            try:
                want, got, sim, ok = run_case(m, image, c, k)
                oc = classify(c, want)
                if got["ret"][0] == "panic":
                    res = f"panic:{got['ret'][1]}:{got['ret'][2]:#x}"
                else:
                    res = f"ret={got['ret'][1]:#04x}"
                res += f",ev={len(got['events'])},state={final_digest(sim)}"
            except ToolError as exc:
                oc, res, ok = "error", str(exc), False
            classes[oc] = classes.get(oc, 0) + 1
            bad += not ok
            if count % ROW_EVERY == 0 or not ok:  # every case is compared; the table lists every ROW_EVERY-th one
                fh.write(f"{count}\t{label}\t{describe(c)}\t{oc}\t{res}\t{'yes' if ok else 'NO'}\n")
            count += 1
    with open(out / "outcome-classes.tsv", "w") as fh:
        fh.write("outcome\tcases\n")
        for key in sorted(classes):
            fh.write(f"{key}\t{classes[key]}\n")
    covered = {}
    with open(out / "coverage.tsv", "w") as fh:
        fh.write("function\tinstructions\texecuted\n")
        for st in starts:
            hit = sum(1 for va, _ in decoded[st] if va in m.seen)
            covered[f"{st:#x}"] = [hit, len(decoded[st])]
            fh.write(f"{st:#x}\t{len(decoded[st])}\t{hit}\n")
    per_label = control_cases(image, None)
    ctl = controls(image, per_label)
    with open(out / "negative-controls.tsv", "w") as fh:
        fh.write("kind\tcontrol\tdetected\n")
        for r in ctl:
            fh.write("\t".join(str(x) for x in r) + "\n")
    consts = {"binary_sha256": SHA256, "functions": info, "opcode_table_slots": handler_slots(image, starts),
              "keccak_twin": f"{KC_TWIN:#x}" if KC_TWIN else None, "got_import_names": got_names(image),
              "keccak_empty": EMPTY_KECCAK.hex(), "keccak_empty_halves": {"0x4537f0": KS[SD_A]["h_lo"].hex(),
                                                                         "0x452020": KS[SD_A]["h_hi"].hex()},
              "interpreter": {"stack_ptr": "0x28", "stack_len": "0x30", "address": "0x78", "gas": "0x188",
                              "gas_aux": ["0x190", "0x198", "0x1a0"], "static": "0x1a8", "spec": "0x1a9",
                              "memory_object": "0x10", "memory_base": "0x18", "memory_words": "0x170"},
              "host": {"params": "0x250", "db": "0x270", "journal": ["0x288", "0x290", "0x298"],
                       "destruct_list": ["0x2a0", "0x2a8", "0x2b0"], "balance_map": ["0x338", "0x340", "0x350", "0x358"],
                       "fork_bytes": ["0x395", "0x396"], "refund_flag": "0x265", "loader_arg": "0x398"},
              "balance_bucket": {"stride": BUCKET, "key": "0x0", "balance": "0x40", "flags": "0xa4"},
              "journal_entry": {"stride": "0x58", "kinds": {"1": "destruct", "2": "touch", "4": "balance-only transfer"}},
              "results": {"success": 3, "static_call": 0x28, "underflow": 0x2c, "out_of_gas": 0x20, "invalid": 0x24}}
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    detected = sum(r[2] for r in ctl)
    summary = {"binary_sha256": SHA256, "cases": count, "mismatches": bad, "covered_instructions": covered,
               "outcome_classes": len(classes), "negative_controls": {"total": len(ctl), "detected": detected}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": count, "negative_controls": len(ctl),
                                                   "negative_detected": detected, "mismatches": bad},
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
    ctl = summary["negative_controls"]
    return 1 if summary["mismatches"] or ctl["detected"] != ctl["total"] else 0


if __name__ == "__main__":
    sys.exit(main())
