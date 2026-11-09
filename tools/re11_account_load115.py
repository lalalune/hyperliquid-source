#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM account-load-into-journal routines 0x4323870 and 0x5463980.

Both bodies ensure one account is present in the per-block account cache (a hashbrown map of
0xa8-byte entries at state+0xc8: 20-byte address key, 4 junk bytes, a 0x90-byte account whose
epoch word is at +0x88 and flag byte at +0x8c) and record a cold access.  They look the
address up through the rustc_entry call (occupied: bucket end pointer; vacant: map, hash, key),
refresh a stale occupied entry (epoch differs or flag 0x10 set) after the warm-set test
(callee 0x64ea6d8 on state+0x48; the access is refused with status 2 when the flag byte
argument is set and the address is cold), or on a vacant entry read the account from the
database callee and build it with the account constructor 0x64e7020, falling back to a default
account (Arc code object with a checked refcount increment, empty storage-map template, foldhash
seed taken from a TLS counter mixed with the stack address) when the database has no account.
Cold accesses append a 0x58-byte journal record (tag 0 + 20-byte address) to the Vec at
state+0x18.  The 0x4323870 form also handles the database error variants (drop through a vtable
call or a deallocation) and the 0x5463980 form is the plain-lookup twin with different callees.

The third body, 0x433c700, installs the account's code object: it returns when +0x70 is set,
shares the empty-code Arc (checked refcount increment, lazy-initialised cell) when the code hash
equals the empty-code constants, and otherwise asks the database code read (tag 5 carries the
Arc pointer; other tags are dropped through a vtable call or a deallocation) before falling back
to the empty-code Arc.

The tool reads every relocation, FDE extent and code byte from the ELF file, evaluates the real
machine code with the concrete x86-64 evaluator of tools/re11_access_list115.py (no external
programs, the binary is never executed) and compares every case with one pure-Python
reconstruction.  Callees are stubbed with explicit contracts shared by the evaluator and the
reconstruction.  Negative controls show that wrong reconstructions and corrupted code bytes are
detected.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_access_list115 as al  # noqa: E402
import fde_extents  # noqa: E402

BINARY, SHA256, M64 = al.BINARY, al.SHA256, al.M64
ToolError, Boundary, fail, Stream, put, u = al.ToolError, al.Boundary, al.fail, al.Stream, al.put, al.u
RETURN_MARK, STACK_TOP, FS_BASE = al.RETURN_MARK, al.STACK_TOP, al.FS_BASE

ORD, SPEC, PREP = 0x4323870, 0x5463980, 0x433c700
# per-variant constants: frame size, GOT slots of the callees
VARIANT = {
    ORD: dict(name="ord", sub=0x268, vec_grow_got=0x64e68e8, account_at=0xf0, ctor_len=0x54,
              tmpl=0x6484fa0, lookup=0x3ed7040, db=0x3d48970, flag40=0x43158c0, lazy=0x435059c),
    SPEC: dict(name="spec", sub=0x238, vec_grow_got=0x64e6cf0, account_at=0x150, ctor_len=0x58,
               tmpl=0x64a9948, lookup=0x4ef78b0, db=0x54419e0, flag40=0x5453850, lazy=0x5b084ff),
}
CODE_DB, ARC_SLOW_GOT = 0x3d48830, 0x64e4fa8
HASH_LOW, HASH_HIGH = 0x4537f0, 0x452020  # the two 16-byte halves of the empty-code hash
WARM_GOT, DEALLOC_GOT, CTOR_GOT, COPY_GOT, TOUCH_GOT = 0x64ea6d8, 0x64df4a0, 0x64e7020, 0x64df508, 0x64ea6e0
SEED_INIT_GOT, SEED_GOT, ARC_GOT = 0x64e22e8, 0x64dfa78, 0x64e6c78
LOOKUP_ORD, DB_ORD, FLAG40, LAZY_INIT = 0x3ed7040, 0x3d48970, 0x43158c0, 0x435059c
LOOKUP_SPEC, DB_SPEC, FLAG40_SPEC, LAZY_SPEC = 0x4ef78b0, 0x54419e0, 0x5453850, 0x5b084ff
ROD_EMPTY = 0x4585a0
C_TLS, C_SEED, TLS_OFF = 0x13198a2e03707344, 0xa4093822299f31d0, -0x578

STATE_AT, STATE_SIZE = 0x7d00_0000_0000, 0x130
JOURNAL_AT, JOURNAL_ROOM = 0x7d00_0010_0000, 8 * 0x58
MAP_AT, MAP_SIZE = 0x7d00_0020_0000, 0x3000
OUT_AT = 0x7d00_0030_0000
ADDR_AT = 0x7d00_0040_0000
DBREF_AT, DB_AT = 0x7d00_0050_0000, 0x7d00_0050_1000
ARC_AT, ARCCELL_AT = 0x7d00_0060_0000, 0x7d00_0060_1000
ACCT_AT = 0x7d00_0090_0000
HEAP_AT, HEAP_SIZE = 0x7d00_0070_0000, 0x4000
OBJ_AT, VT_AT = 0x7d00_0080_0000, 0x7d00_0080_1000
VCALL_FN = 0x7c00_00ff_0000
ENTRY_FRAME = STACK_TOP - 0x4000  # rsp at function entry (return address slot)
SAVED = [0x1111_0000_0000_0003 * (i + 1) & M64 for i in range(6)]  # rbx r12 r13 r14 r15 rbp
H_SALT = b"hl115-account-hash"


# ---------------------------------------------------------------- evaluator
class Mach(al.Machine):
    """Adds the lock prefix, the signed conditions and executed-address tracking."""

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
            if code[0] == 0xf0:
                form = al.decode(bytes(code[1:]) + b"\0", va + 1)
                form["len"] += 1
                form["lock"] = True
            else:
                form = al.decode(bytes(code), va)
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


class MemView:
    """Byte access shared by the evaluator stubs and the reconstruction."""

    def ld(self, at, n):
        raise NotImplementedError

    def st(self, at, data):
        raise NotImplementedError

    def u64(self, at):
        return int.from_bytes(self.ld(at, 8), "little")

    def u32(self, at):
        return int.from_bytes(self.ld(at, 4), "little")


class MachView(MemView):
    def __init__(self, m):
        self.m = m

    def ld(self, at, n):
        for lo, hi, buf in self.m.regions:
            if lo <= at and at + n <= hi:
                return bytes(buf[at - lo:at - lo + n])
        return self.m.image.read(at, n)

    def st(self, at, data):
        for lo, hi, buf in self.m.regions:
            if lo <= at and at + len(data) <= hi:
                buf[at - lo:at - lo + len(data)] = data
                return
        fail(f"stub write outside regions at {at:#x}")


class ModelView(MemView):
    def __init__(self, regions, image):
        self.regions, self.image = regions, image

    def ld(self, at, n):
        for lo, buf in self.regions:
            if lo <= at and at + n <= lo + len(buf):
                return bytes(buf[at - lo:at - lo + n])
        return self.image.read(at, n)

    def st(self, at, data):
        for lo, buf in self.regions:
            if lo <= at and at + len(data) <= lo + len(buf):
                buf[at - lo:at - lo + len(data)] = data
                return
        fail(f"model write outside regions at {at:#x}")


# ---------------------------------------------------------------- callee contracts (shared)
def key_hash(key):
    return int.from_bytes(hashlib.sha256(H_SALT + bytes(key)).digest()[:8], "little")


def ctor_bytes(inp):
    out = b""
    n = 0
    while len(out) < 0x90:
        out += hashlib.sha512(b"ctor" + n.to_bytes(1, "little") + inp).digest()
        n += 1
    return out[:0x90]


def map_slots(v, hdr):
    ctrl, mask = v.u64(hdr), v.u64(hdr + 8)
    return ctrl, mask


class Contracts:
    """The explicit contract of every callee that is not reconstructed here."""

    def __init__(self, v, c, events, heap, spec, mut=frozenset()):
        self.v, self.c, self.ev, self.heap, self.spec, self.mut = v, c, events, heap, spec, mut

    def lookup(self, a):
        out, hdr, keyp = a["rdi"], a["rsi"], a["rdx"]
        v = self.v
        key = v.ld(keyp, 20)
        ctrl, mask = map_slots(v, hdr)
        self.ev.append(("lookup", hdr - STATE_AT, key.hex()))
        for i in range(mask + 1):
            if v.ld(ctrl + i, 1)[0] < 0x80 and v.ld(ctrl - (i + 1) * 0xa8, 20) == key:
                v.st(out, struct.pack("<QQ", 0, ctrl - i * 0xa8))
                return None
        v.st(out, struct.pack("<QQ", hdr, key_hash(key)) + key)
        return None

    def warm(self, a):
        self.ev.append(("warm", a["rdi"] - STATE_AT, self.v.ld(a["rsi"], 20).hex()))
        return self.c["warm"]

    def db(self, a):
        raw = self.c["dbraw"]
        self.ev.append(("db", a["rsi"] - DB_AT, self.v.ld(a["rdx"], 20).hex()))
        self.v.st(a["rdi"], raw)
        return None

    def ctor(self, a):
        n = VARIANT[ORD if not self.spec else SPEC]["ctor_len"]
        inp = self.v.ld(a["rsi"], n)
        self.ev.append(("ctor", inp.hex()))
        self.v.st(a["rdi"], ctor_bytes(inp))
        return None

    def copy(self, a):
        self.ev.append(("copy", a["rdx"]))
        self.v.st(a["rdi"], self.v.ld(a["rsi"], a["rdx"]))
        return None

    def grow(self, a):
        v, hdr = self.v, a["rdi"]
        cap, ptr, ln = v.u64(hdr), v.u64(hdr + 8), v.u64(hdr + 16)
        self.ev.append(("grow", cap, ln))
        new_cap = max(cap * 2, 4)
        new = self.heap.alloc(new_cap * 0x58)
        v.st(new, v.ld(ptr, ln * 0x58))
        v.st(hdr, struct.pack("<QQ", new_cap, new))
        return None

    def touch(self, a):
        self.ev.append(("touch", a["rdi"] - MAP_AT))
        return None

    def flag40(self, a):
        self.ev.append(("flag40", a["rdi"] - MAP_AT))
        return None

    def lazy(self, a):
        self.ev.append(("lazy",))
        self.v.st(a["rdi"] + 8, b"\0" * 4)
        return None

    def seed_init(self, a):
        self.ev.append(("seed_init",))
        self.v.st(self.c["seed_at"] + 0x30, b"\x02")
        return None

    def code_db(self, a):
        self.ev.append(("code_db", a["rsi"] - DB_AT, self.v.ld(a["rdx"], 32).hex()))
        self.v.st(a["rdi"], self.c["dbraw"][:0x20])
        return None

    def vcall(self, a):
        self.ev.append(("vcall", a["rdi"] - OBJ_AT))
        return None

    def dealloc(self, a):
        self.ev.append(("free", a["rdi"], a["rsi"], a["rdx"]))
        return None


class Heap:
    def __init__(self):
        self.next = HEAP_AT

    def alloc(self, n):
        at = self.next
        self.next += (n + 15) & ~15
        if self.next > HEAP_AT + HEAP_SIZE:
            fail("synthetic heap exhausted")
        return at


# ---------------------------------------------------------------- case layout
def set_ctrl(ctrl, mask, i, value):
    ctrl[i] = value
    ctrl[((i - 16) & mask) + 16] = value


def insert_slot(ctrl, mask, h):
    pos, stride = h & mask, 0
    while True:
        bits = [i for i in range(16) if ctrl[pos + i] & 0x80]
        if bits:
            idx = (pos + bits[0]) & mask
            if ctrl[idx] & 0x80 == 0:
                idx = [i for i in range(16) if ctrl[i] & 0x80][0]
            return idx
        stride += 16
        pos = (pos + stride) & mask


def regions_for(c):
    """Initial memory of one case as (base, bytes) rows; the evaluator and the model both start here."""
    rows = []
    state = bytearray(STATE_SIZE)
    nb = c["buckets"]
    mask = nb - 1
    ctrl_at = MAP_AT + nb * 0xa8
    put(state, 0x18, 8, c["jcap"])
    put(state, 0x20, 8, JOURNAL_AT)
    put(state, 0x28, 8, c["jlen"])
    put(state, 0x48, 8, 0x4848)
    put(state, 0x70, 8, 0x7070)
    put(state, 0xc8, 8, ctrl_at)
    put(state, 0xd0, 8, mask)
    put(state, 0xd8, 8, c["growth"])
    put(state, 0xe0, 8, c["items"])
    put(state, 0x120, 4, c["epoch"])
    rows.append((STATE_AT, state))
    rows.append((JOURNAL_AT, bytearray(c["jbytes"].ljust(JOURNAL_ROOM, b"\x5c"))))
    mp = bytearray(MAP_SIZE)
    mp[:nb * 0xa8] = c["mapdata"]
    mp[nb * 0xa8:nb * 0xa8 + nb + 16] = c["ctrl"]
    rows.append((MAP_AT, mp))
    rows.append((OUT_AT, bytearray([0x33]) * 0x40))
    rows.append((ADDR_AT, bytearray(c["addr"] + b"\xa7" * 12)))
    rows.append((DBREF_AT, bytearray(struct.pack("<Q", DB_AT) + b"\0" * 0x38)))
    rows.append((DB_AT, bytearray(0x80)))
    cell = bytearray(0x10)
    put(cell, 0, 8, ARC_AT)
    put(cell, 8, 4, c["lazy_state"])
    rows.append((c["arc_cell"], cell))
    rows.append((ARC_AT, bytearray(struct.pack("<Q", c["refcnt"]) + b"\0" * 8)))
    rows.append((HEAP_AT, bytearray(HEAP_SIZE)))
    obj = bytearray(0x20)
    put(obj, 0, 8, VT_AT)
    rows.append((OBJ_AT, obj))
    vt = bytearray(0x20)
    put(vt, 0, 8, VCALL_FN)
    rows.append((VT_AT, vt))
    seed = bytearray(0x40)
    seed[0x30] = c["seed_state"]
    rows.append((c["seed_at"], seed))
    tls = bytearray(0x1000)
    put(tls, 0x1000 + TLS_OFF, 8, c["tls"])
    rows.append((FS_BASE - 0x1000, tls))
    return rows


def stack_fill():
    lo = ENTRY_FRAME - 0x800
    return lo, bytes(((a * 0x9d) ^ (a >> 5) ^ 0x3c) & 0xff for a in range(lo, ENTRY_FRAME))


STACK_LO, STACK_PATTERN = stack_fill()


def stack_byte(a):
    return STACK_PATTERN[a - STACK_LO]


def run_machine(m, spec, c):
    image = m.image
    var = VARIANT[SPEC if spec else ORD]
    m.reset()
    m.regions[0][2][STACK_LO - m.regions[0][0]:ENTRY_FRAME - m.regions[0][0]] = STACK_PATTERN
    bufs = {}
    for base, buf in regions_for(c):
        bufs[base] = m.add_region(base, len(buf), bytes(buf))
    events, heap = [], Heap()
    k = Contracts(MachView(m), c, events, heap, spec)
    clobber = [0xc10b_0000_0000_0000 + 0x101 * n for n in range(16)]

    def wrap(fn):
        def stub(mc):
            a = {"rdi": mc.regs[7], "rsi": mc.regs[6], "rdx": mc.regs[2], "rcx": mc.regs[1], "r8": mc.regs[8]}
            r = fn(a)
            for reg in (1, 2, 6, 7, 8, 9, 10, 11):
                mc.regs[reg] = clobber[reg]
            mc.regs[0] = clobber[0] if r is None else r
        return stub

    stubs = {
        image.word(WARM_GOT): wrap(k.warm), image.word(DEALLOC_GOT): wrap(k.dealloc),
        image.word(CTOR_GOT): wrap(k.ctor), image.word(COPY_GOT): wrap(k.copy),
        image.word(var["vec_grow_got"]): wrap(k.grow), image.word(TOUCH_GOT): wrap(k.touch),
        image.word(SEED_INIT_GOT): wrap(k.seed_init), VCALL_FN: wrap(k.vcall),
        var["lookup"]: wrap(k.lookup), var["db"]: wrap(k.db), var["flag40"]: wrap(k.flag40),
        var["lazy"]: wrap(k.lazy),
    }
    m.stubs = stubs
    f = ENTRY_FRAME - 8
    m.regs[4] = f
    m.store(f, 8, RETURN_MARK)
    for r, v in zip((3, 12, 13, 14, 15, 5), SAVED):
        m.regs[r] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = OUT_AT, STATE_AT, DBREF_AT, ADDR_AT, c["flag"]
    got = {"events": events, "status": "ret"}
    pc = SPEC if spec else ORD
    try:
        while pc != RETURN_MARK:
            m.steps += 1
            if m.steps > 400_000:
                fail("step limit")
            pc = m.step(pc)
    except ToolError as exc:
        if "ud2" not in str(exc):
            raise
        got["status"] = "ud2"
    got["regs_ok"] = got["status"] == "ud2" or (
        [m.regs[r] for r in (3, 12, 13, 14, 15, 5)] == SAVED and m.regs[4] == f + 8)
    got["rax"] = m.regs[0]
    got["mem"] = {base: bytes(b) for base, b in bufs.items()}
    got["steps"] = m.steps
    return got


# ---------------------------------------------------------------- the reconstruction
def img16(image, va):
    return image.word(va).to_bytes(8, "little") + image.word(va + 8).to_bytes(8, "little")


def reconstruct(image, spec, c, mut=frozenset()):
    """Pure-Python account load: returns the observable result the evaluator is compared with."""
    var = VARIANT[SPEC if spec else ORD]
    regs = [(base, bytearray(buf)) for base, buf in regions_for(c)]
    scratch = bytearray(0x40)
    v = ModelView(regs + [(OUT_AT + 0x1000, scratch)], image)
    events, heap = [], Heap()
    k = Contracts(v, c, events, heap, spec, mut)
    rsp0 = ENTRY_FRAME - 8 - 48 - var["sub"]
    res = {"events": events, "status": "ret", "rax": OUT_AT, "path": "vacant"}
    region = {lo: b for lo, b in regs}
    out = region[OUT_AT]
    epoch = v.u32(STATE_AT + 0x120)
    addr = v.ld(ADDR_AT, 20)
    flag = c["flag"] & 0xff

    def snapshot():
        res["mem"] = {base: bytes(b) for base, b in regs if base != OUT_AT + 0x1000}
        return res

    def finish(acct, status):
        put(out, 0, 8, acct)
        put(out, 8, 8, STATE_AT + 0x18)
        put(out, 0x10, 8, STATE_AT + 0x70)
        put(out, 0x18, 8, DBREF_AT)
        put(out, 0x20, 4, epoch)
        out[0x24:0x38] = addr
        out[0x38] = status & 0xff
        return snapshot()

    def refuse():
        out[0x38] = 2
        return snapshot()

    def journal_push():
        ln, cap = v.u64(STATE_AT + 0x28), v.u64(STATE_AT + 0x18)
        if ln == cap:
            k.grow({"rdi": STATE_AT + 0x18})
        v.st(v.u64(STATE_AT + 0x20) + ln * 0x58, b"\0" + addr)
        v.st(STATE_AT + 0x28, struct.pack("<Q", ln + 1))

    k.lookup({"rdi": OUT_AT + 0x1000, "rsi": STATE_AT + 0xc8, "rdx": ADDR_AT})
    tag = u(scratch, 0, 8)
    if tag == 0:  # occupied entry: end pointer of the bucket
        res["path"] = "occupied"
        end = u(scratch, 8, 8)
        acct = end - 0x90
        e_epoch, e_flags = v.u32(end - 8), v.ld(end - 4, 1)[0]
        stale = e_epoch != epoch or bool(e_flags & 0x10)
        if "no_epoch_check" in mut:
            stale = bool(e_flags & 0x10)
        if "ignore_10" in mut:
            stale = e_epoch != epoch
        if not stale:
            return finish(acct, 0)
        w = k.warm({"rdi": STATE_AT + 0x48, "rsi": ADDR_AT}) & 0xff
        test = ((flag ^ 1) | w) & 0xff
        bad = test == 0 if "occupied_nonzero" in mut else test != 1
        if bad:
            return refuse()
        v.st(end - 4, bytes([e_flags & 0xef]))
        v.st(end - 8, struct.pack("<I", epoch))
        if e_flags & 0x40:
            k.flag40({"rdi": acct})
            v.st(end - 4, bytes([v.ld(end - 4, 1)[0] & 0xbf]))
        k.touch({"rdi": acct})
        v.st(end - 4, bytes([v.ld(end - 4, 1)[0] & 0x7f]))
        journal_push()
        return finish(acct, w if "status_plain" in mut else w ^ 1)

    # vacant entry: (map, hash, key)
    hash_, key = u(scratch, 8, 8), bytes(scratch[0x10:0x24])
    w = k.warm({"rdi": STATE_AT + 0x48, "rsi": ADDR_AT}) & 0xff
    test = ((flag ^ 1) | w) & 0xff
    bad = (test != 1) if "vacant_ne1" in mut else (test == 0)
    if bad:
        return refuse()
    dbp = v.u64(DBREF_AT) + (0 if spec else 0x20)
    raw = c["dbraw"]
    events.append(("db", dbp - DB_AT, addr.hex()))
    rtag = u(raw, 0, 8)
    if spec:
        use_ctor = rtag == 1
    else:
        use_ctor = rtag != 2 and (rtag & 0xffffffff) == 1
        if "tag_cmp_64" in mut:
            use_ctor = rtag == 1
        if rtag == 2:
            kind = u(raw, 8, 8)
            if kind == 2:
                events.append(("vcall", u(raw, 0x10, 8) - OBJ_AT))
            elif kind >= 3 and u(raw, 0x10, 8) != 0:
                events.append(("free", u(raw, 0x18, 8), u(raw, 0x10, 8), 0))
    if use_ctor:
        inp = raw[8:0x60] if spec else raw[8:0x50] + b"\0" * 12
        events.append(("ctor", inp.hex()))
        co = bytearray(ctor_bytes(inp))
        junk4 = bytes(co[:4])
        put(co, 0x88, 4, epoch)
        account = bytes(co)
        events.append(("copy", 0x90 if "copy_len" not in mut else 0x8f))
    else:
        if v.u32(c["arc_cell"] + 8):
            k.lazy({"rdi": c["arc_cell"]})
        rc = c["refcnt"]
        new = (rc + 1) & M64
        taken = new == 0 or (new >> 63) != (1 if rc == 0x7fff_ffff_ffff_ffff else 0)
        if "refcnt_simple_overflow" in mut:
            taken = new == 0 or (new >> 63) == 1
        put(region[ARC_AT], 0, 8, new)
        if taken:
            res["status"] = "ud2"
            return res
        base = rsp0 + var["account_at"]
        tls = c["tls"]
        p1 = ((C_TLS ^ tls) * (0 if "tls_no_stack" in mut else base)) & ((1 << 128) - 1)
        ntls = (p1 & M64) ^ (p1 >> 64)
        put(region[FS_BASE - 0x1000], 0x1000 + TLS_OFF, 8, ntls)
        p2 = (ntls * C_SEED) & ((1 << 128) - 1)
        seed = (p2 & M64) ^ (p2 >> 64)
        if "seed_lo_only" in mut:
            seed = p2 & M64
        if c["seed_state"] != 2:
            k.seed_init({})
        acc = bytearray(0x90)
        acc[0:0x20] = img16(image, var["tmpl"]) + img16(image, var["tmpl"] + 16)
        put(acc, 0x20, 8, seed)
        acc[0x48:0x68] = img16(image, ROD_EMPTY) + img16(image, ROD_EMPTY + 16)
        put(acc, 0x70, 8, ARC_AT)
        acc[0x7c:0x80] = raw[0x54:0x58] if "residue_zero" not in mut else b"\0\0\0\0"
        put(acc, 0x88, 4, epoch)
        acc[0x8c] = 8
        acc[0x8d:0x90] = bytes(stack_byte(base + 0x8d + i) for i in range(3))
        account, junk4 = bytes(acc), b"\0\0\0\0"
    if (w == 0) != ("journal_when_warm" in mut):
        journal_push()
    events.append(("copy", 0x90))
    # hashbrown insertion at the vacant slot
    ctrl_at = v.u64(STATE_AT + 0xc8)
    mask = v.u64(STATE_AT + 0xd0)
    ctrl = bytearray(v.ld(ctrl_at, mask + 1 + 16))
    idx = insert_slot(ctrl, mask, hash_)
    old = ctrl[idx]
    top7 = hash_ >> 57
    if "top7_shift" in mut:
        top7 = (hash_ >> 56) & 0x7f
    v.st(ctrl_at + idx, bytes([top7]))
    v.st(ctrl_at + ((idx - 16) & mask) + 16, bytes([top7]))
    gl = v.u64(STATE_AT + 0xd8)
    v.st(STATE_AT + 0xd8, struct.pack("<Q", (gl - (1 if "growth_always" in mut else (old & 1))) & M64))
    end = ctrl_at - idx * 0xa8
    events.append(("copy", 0x94))
    v.st(end - 0xa8, key)
    v.st(end - 0x94, junk4 + account)
    v.st(STATE_AT + 0xe0, struct.pack("<Q", v.u64(STATE_AT + 0xe0) + 1))
    return finish(end - 0x90, w ^ 1)


def compare(want, got):
    if want["status"] != got["status"] or want["events"] != got["events"]:
        return False
    if got["status"] == "ud2":
        return True
    return got["regs_ok"] and (want["rax"] is None or got["rax"] == want["rax"]) and got["mem"] == want["mem"]


# ---------------------------------------------------------------- code-object preparation 0x433c700
def run_prep(m, c):
    image = m.image
    m.reset()
    m.regions[0][2][STACK_LO - m.regions[0][0]:ENTRY_FRAME - m.regions[0][0]] = STACK_PATTERN
    bufs = {}
    for base, buf in prep_regions(c):
        bufs[base] = m.add_region(base, len(buf), bytes(buf))
    events = []
    k = Contracts(MachView(m), c, events, Heap(), False)
    clobber = [0xc10b_0000_0000_0000 + 0x101 * n for n in range(16)]

    def wrap(fn):
        def stub(mc):
            a = {"rdi": mc.regs[7], "rsi": mc.regs[6], "rdx": mc.regs[2], "rcx": mc.regs[1], "r8": mc.regs[8]}
            r = fn(a)
            for reg in (1, 2, 6, 7, 8, 9, 10, 11):
                mc.regs[reg] = clobber[reg]
            mc.regs[0] = clobber[0] if r is None else r
        return stub

    m.stubs = {CODE_DB: wrap(k.code_db), image.word(DEALLOC_GOT): wrap(k.dealloc), VCALL_FN: wrap(k.vcall),
               LAZY_INIT: wrap(k.lazy), image.word(ARC_SLOW_GOT): wrap(lambda a: events.append(("arc_drop",)))}
    f = ENTRY_FRAME - 8
    m.regs[4] = f
    m.store(f, 8, RETURN_MARK)
    for r, v in zip((3, 14), (SAVED[0], SAVED[3])):
        m.regs[r] = v
    m.regs[7], m.regs[6] = ACCT_AT, DBREF_AT
    got = {"events": events, "status": "ret"}
    pc = PREP
    try:
        while pc != RETURN_MARK:
            m.steps += 1
            if m.steps > 100_000:
                fail("step limit")
            pc = m.step(pc)
    except ToolError as exc:
        if "ud2" not in str(exc):
            raise
        got["status"] = "ud2"
    got["regs_ok"] = got["status"] == "ud2" or (m.regs[3] == SAVED[0] and m.regs[14] == SAVED[3] and m.regs[4] == f + 8)
    got["rax"] = m.regs[0]
    got["mem"] = {base: bytes(b) for base, b in bufs.items()}
    got["steps"] = m.steps
    return got


def prep_regions(c):
    rows = [(ACCT_AT, bytearray(c["account"])), (DBREF_AT, bytearray(struct.pack("<Q", DB_AT) + b"\0" * 0x38)),
            (OBJ_AT, bytearray(struct.pack("<Q", VT_AT) + b"\0" * 0x18)),
            (VT_AT, bytearray(struct.pack("<Q", VCALL_FN) + b"\0" * 0x18))]
    cell = bytearray(0x10)
    put(cell, 0, 8, ARC_AT)
    put(cell, 8, 4, c["lazy_state"])
    rows.append((c["arc_cell"], cell))
    rows.append((ARC_AT, bytearray(struct.pack("<Q", c["refcnt"]) + b"\0" * 8)))
    return rows


def reconstruct_prep(image, c, mut=frozenset()):
    """Install the account's code object: keep it, take the database code, or share the empty-code Arc."""
    regs = [(base, bytearray(buf)) for base, buf in prep_regions(c)]
    v = ModelView(regs, image)
    events = []
    k = Contracts(v, c, events, Heap(), False, mut)
    region = {lo: b for lo, b in regs}
    res = {"events": events, "status": "ret", "rax": None, "path": "prep"}

    def snapshot(label):
        res["pclass"] = label
        res["mem"] = {base: bytes(b) for base, b in regs}
        return res

    if v.u64(ACCT_AT + 0x70) != 0:
        return snapshot("kept")
    h = v.ld(ACCT_AT + 0x48, 32)
    empty = h[:16] == img16(image, HASH_LOW) and h[16:] == img16(image, HASH_HIGH)
    if "empty_swapped" in mut:
        empty = h[:16] == img16(image, HASH_HIGH) and h[16:] == img16(image, HASH_LOW)
    install, label = None, "empty-hash"
    if not empty:
        events.append(("code_db", 0x928, h.hex()))
        raw = c["dbraw"]
        tag, w1, w2 = u(raw, 0, 8), u(raw, 8, 8), u(raw, 0x10, 8)
        label = "db-null"
        is_ok = (tag & 0xffffffff) == 5 if "tag_low32" in mut else tag == 5
        if is_ok:
            if w1:
                install, label = w1, "db-code"
        elif (tag & 0xffffffff) >= 2:
            if (tag & 0xffffffff) == 2:
                events.append(("vcall", w1 - OBJ_AT))
                label = "db-err-vcall"
            else:
                label = "db-err-free0"
                if w1 or "free_zero_size" in mut:
                    events.append(("free", w2, w1, 0))
                    label = "db-err-free"
        else:
            label = "db-none"
    if install is None:
        if v.u32(c["arc_cell"] + 8):
            k.lazy({"rdi": c["arc_cell"]})
        rc = c["refcnt"]
        new = (rc + 1) & M64
        put(region[ARC_AT], 0, 8, new)
        if new == 0 or (new >> 63) != (1 if rc == 0x7fff_ffff_ffff_ffff else 0):
            res["status"] = "ud2"
            return snapshot("default/ud2")
        install = ARC_AT
        label = "default/" + label
    put(region[ACCT_AT], 0x70, 8, install)
    return snapshot(label)


PREP_KINDS = ["kept", "empty", "low_bit", "high_bit", "db_ok", "db_null", "db_none", "err_vcall", "err_free",
              "err_free0", "tag_high", "arc_edge", "db_ok_wide"]


def make_prep_case(image, i):
    s = Stream(f"prep-{i}")
    kind = PREP_KINDS[i % len(PREP_KINDS)]
    acct = bytearray(s.take(0xa0))
    put(acct, 0x70, 8, 0 if kind != "kept" else (s.below(1 << 48) | 1))
    empty = img16(image, HASH_LOW) + img16(image, HASH_HIGH)
    h = bytearray(empty if kind in ("empty", "kept") and s.below(2) else s.take(32))
    if kind == "empty":
        h = bytearray(empty)
    if kind in ("low_bit", "high_bit"):
        h = bytearray(empty)
        h[s.below(16) + (0 if kind == "low_bit" else 16)] ^= 1 << s.below(8)
    acct[0x48:0x68] = h
    raw = bytearray(s.take(0x20))
    tag = {"db_ok": 5, "db_ok_wide": 5, "db_null": 5, "err_vcall": 2, "err_free": s.pick([3, 4, 6, 0xff]),
           "err_free0": 3, "db_none": s.pick([0, 1, 4, 6]), "tag_high": s.pick([0x1_0000_0005, 0x1_0000_0002, 0x1_0000_0003, 0x8000_0000_0000_0005])}.get(kind, s.pick([5, 0, 2, 3]))
    put(raw, 0, 8, tag)
    if kind in ("db_ok", "db_ok_wide"):
        put(raw, 8, 8, s.below(1 << 47) | 1)
    elif kind == "db_null":
        put(raw, 8, 8, 0)
    elif kind == "err_vcall":
        put(raw, 8, 8, OBJ_AT)
    elif kind == "err_free0":
        put(raw, 8, 8, 0)
    elif kind == "err_free":
        put(raw, 8, 8, s.pick([1, 0x40, 0x1000]))
    elif tag & 0xffffffff == 2:
        put(raw, 8, 8, OBJ_AT)
    return {"spec": "prep", "i": i, "kind": kind, "account": bytes(acct), "dbraw": bytes(raw),
            "lazy_state": 0 if s.below(3) else s.pick([1, 0x80000000, 0xff]),
            "refcnt": s.pick(REFCNTS) if kind == "arc_edge" else s.pick(REFCNTS[:3]),
            "arc_cell": image.word(ARC_GOT), "flag": 0, "warm": 0, "buckets": 0, "epoch": 0, "jcap": 0, "jlen": 0}


def prep_cases(image, n=2600):
    return (make_prep_case(image, i) for i in range(n))


# ---------------------------------------------------------------- cases
KINDS = ["occ_fresh", "occ_stale", "occ_reverted", "occ_stale_refuse", "vac_some", "vac_none", "vac_err",
         "vac_refuse", "vac_arc_edge", "vac_odd_tag", "vac_dense", "vac_probe"]
FLAGS_OK = [0, 1, 2, 3, 0x80, 0xff, 0x100 | 1]
WARM_VALUES = [0, 1, 0x100, 0x101, 0xfffffff0, 0xffffff01, 2, 0x80]
REFCNTS = [1, 2, 0x1234, 0x7fff_ffff_ffff_fffe, 0x7fff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x8000_0000_0000_0000,
           0xffff_ffff_ffff_fffe, 0]


def rand_addr(s):
    return s.take(20)


def build_table(s, nb, fill):
    mask = nb - 1
    ctrl = bytearray(b"\xff" * (nb + 16))
    data = bytearray(nb * 0xa8)
    keys = []
    target = min(fill, nb - 1)
    for _ in range(target):
        key = rand_addr(s)
        idx = insert_slot(ctrl, mask, key_hash(key))
        set_ctrl(ctrl, mask, idx, key_hash(key) >> 57)
        end = nb * 0xa8 - idx * 0xa8
        data[end - 0xa8:end - 0xa8 + 20] = key
        data[end - 0x94:end - 0x94 + 4] = s.take(4)
        acc = bytearray(s.take(0x90))
        data[end - 0x90:end] = acc
        keys.append((idx, key))
    return ctrl, data, keys


def make_case(image, spec, i):
    s = Stream(f"acct-{int(spec)}-{i}")
    kind = KINDS[i % len(KINDS)]
    nb = s.pick([4, 8, 16, 16, 32, 32, 64])
    if kind == "vac_dense":
        nb = s.pick([32, 64])
    cap = nb if nb < 8 else nb // 8 * 7
    fill = s.below(nb) if kind != "vac_dense" else nb - 1 - s.below(3)
    if kind.startswith("occ"):
        fill = max(1, fill)
    mask = nb - 1
    pre_key = None
    if kind == "vac_probe":
        # every control byte full except a few holes placed on later probe groups of one chosen key
        nb = s.pick([32, 64])
        mask = nb - 1
        cap = nb // 8 * 7
        pre_key = rand_addr(s)
        pos = key_hash(pre_key) & mask
        ctrl = bytearray(b"\xff" * (nb + 16))
        for k in range(nb):
            set_ctrl(ctrl, mask, k, s.below(0x80))
        data, keys = bytearray(s.take(nb * 0xa8)), []
        stride, pos2 = 0, pos
        for _ in range(s.pick([1, 1, 2])):  # which later group holds the holes
            stride += 16
            pos2 = (pos2 + stride) & mask
        first = s.below(3)
        for h in (first, first + 1 + s.below(4)):
            set_ctrl(ctrl, mask, (pos2 + h) & mask, 0xff)
    else:
        ctrl, data, keys = build_table(s, nb, fill)
    epoch = s.below(1 << 32)
    if s.below(4) == 0:
        epoch = s.pick([0, 1, 0xffffffff, 0x7fffffff])
    tomb = 0
    for idx, key in list(keys):
        if s.below(6) == 0 and not kind.startswith("occ") and kind not in ("vac_dense", "vac_probe"):
            set_ctrl(ctrl, mask, idx, 0x80)
            tomb += 1
    items = sum(1 for k in range(nb) if ctrl[k] < 0x80)
    growth = max(0, cap - items - tomb)
    if s.below(8) == 0:
        growth = s.pick([0, 1, 5, cap])
    c = {"spec": spec, "i": i, "kind": kind, "buckets": nb, "epoch": epoch, "ctrl": bytes(ctrl),
         "mapdata": bytes(data), "growth": growth, "items": items, "tls": int.from_bytes(s.take(8), "little"),
         "seed_state": 2 if s.below(5) else s.pick([0, 1, 3, 0xff]), "lazy_state": 0 if s.below(3) else s.pick([1, 0x80000000, 0xff]),
         "refcnt": s.pick(REFCNTS) if kind == "vac_arc_edge" else s.pick(REFCNTS[:3]),
         "arc_cell": image.word(ARC_GOT), "seed_at": image.word(SEED_GOT)}
    jcap = s.pick([0, 1, 2, 3, 4, 8])
    jlen = jcap if s.below(2) else s.below(jcap + 1)
    c["jcap"], c["jlen"] = jcap, jlen
    c["jbytes"] = b"".join(b"\0" + s.take(20) + s.take(0x58 - 21) for _ in range(jlen))
    occupied = [(idx, key) for idx, key in keys if ctrl[idx] < 0x80]
    flag = s.pick(FLAGS_OK)
    warm = s.pick(WARM_VALUES)
    if kind == "occ_fresh":
        idx, key = s.pick(occupied)
        end = nb * 0xa8 - idx * 0xa8
        data = bytearray(c["mapdata"])
        put(data, end - 8, 4, epoch)
        data[end - 4] = s.below(256) & ~0x10
        c["mapdata"], c["addr"] = bytes(data), key
    elif kind.startswith("occ"):
        idx, key = s.pick(occupied)
        end = nb * 0xa8 - idx * 0xa8
        data = bytearray(c["mapdata"])
        if kind == "occ_reverted":
            put(data, end - 8, 4, epoch)
            data[end - 4] = s.below(256) | 0x10
        else:
            put(data, end - 8, 4, (epoch + 1 + s.below(3)) & 0xffffffff)
            data[end - 4] = s.below(256)
        c["mapdata"], c["addr"] = bytes(data), key
        if kind == "occ_stale_refuse":
            flag, warm = s.pick([1, 3, 0x81, 0xff]), s.pick([0, 0x100, 0xfffffff0])
        elif s.below(2):
            flag, warm = s.pick([0, 2, 3]), s.pick(WARM_VALUES)
    else:
        key = pre_key or rand_addr(s)
        while any(key == k2 for _, k2 in occupied):
            key = rand_addr(s)
        c["addr"] = key
        if kind == "vac_refuse":
            flag, warm = s.pick([1, 3, 0x81, 0xff]), s.pick([0, 0x100, 0xfffffff0])
        elif kind == "vac_odd_tag" or s.below(3) == 0:
            flag = s.pick([0, 1, 2, 3, 0xfe])
    c["flag"], c["warm"] = flag, warm
    raw = bytearray(s.take(0xa0))
    tag = 1 if kind in ("vac_some", "occ_fresh", "occ_stale", "occ_reverted") or (kind == "vac_arc_edge" and s.below(3) == 0) else 0
    if kind == "vac_err" and not spec:
        tag = 2
    elif kind == "vac_err":
        tag = s.pick([2, 5, 0])
    if kind == "vac_odd_tag":
        tag = s.pick([0x1_0000_0001, 0x1_0000_0002, 0xffff_ffff_0000_0001, 3, 0x1_0000_0000, 0x8000_0000_0000_0001]
                     if i % 2 else [1, 0, 2, 0xdead])
    put(raw, 0, 8, tag)
    if tag == 2 and not spec:
        kd = s.pick([0, 1, 2, 3, 5, 0xffff_ffff_ffff_ffff])
        put(raw, 8, 8, kd)
        put(raw, 0x10, 8, OBJ_AT if kd == 2 else s.pick([0, 0x40, 0x1000]))
    c["dbraw"] = bytes(raw)
    return c


def all_cases(image, per_variant=6000):
    for i in range(per_variant):
        for spec in (False, True):
            yield make_case(image, spec, i)


# ---------------------------------------------------------------- evaluation
def new_machines(image, override=None):
    return {False: Mach(image, override), True: Mach(image, override), "prep": Mach(image, override)}


def want_of(image, c, mut):
    if c["spec"] == "prep":
        return reconstruct_prep(image, c, mut)
    return reconstruct(image, c["spec"], c, mut)


def got_of(machines, c):
    if c["spec"] == "prep":
        return run_prep(machines["prep"], c)
    return run_machine(machines[c["spec"]], c["spec"], c)


def run_stream(image, mut=frozenset(), machines=None, cases=None, stop_on_first=False):
    """Generator form of evaluate(): one case at a time, nothing accumulated."""
    machines = machines or new_machines(image)
    for c in (cases if cases is not None else all_cases(image)):
        want = want_of(image, c, mut)
        try:
            got = got_of(machines, c)
            ok = compare(want, got)
        except (ToolError, Boundary, IndexError, KeyError, ValueError) as exc:
            got, ok = {"error": str(exc), "steps": 0, "status": "error", "events": []}, False
        yield c, want, got, ok
        if stop_on_first and not ok:
            return


def detects(image, override=None, mut=frozenset(), cases=None):
    machines = new_machines(image, override)
    for c, want, got, ok in run_stream(image, mut, machines, cases, True):
        if not ok:
            return True
    return False


# ---------------------------------------------------------------- static evidence
def sweep_rows(image, lo, hi):
    rows, va = [], lo
    while va < hi:
        code = image.code(va, 16)
        if code[0] == 0xcc:
            rows.append((va, None))
            va += 1
            continue
        if code[0] == 0xf0:
            form = al.decode(code[1:] + b"\0", va + 1)
            form["len"] += 1
            form["lock"] = True
        else:
            form = al.decode(code, va)
        rows.append((va, form))
        va += form["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


CONTRACT_NAMES = {}


def contract_names(image):
    names = {("prep", CODE_DB): "code database read (tag 5 = code Arc pointer)",
             ("prep", LAZY_INIT): "lazy initialiser of the code-object Arc cell",
             ("prep", image.word(DEALLOC_GOT)): "deallocate (ptr, size, 0)",
             ("prep", image.word(ARC_SLOW_GOT)): "Arc slow drop"}
    for spec, var in ((False, VARIANT[ORD]), (True, VARIANT[SPEC])):
        names[(spec, var["lookup"])] = "entry lookup (occupied: tag 0 + bucket end; vacant: map, hash, key)"
        names[(spec, var["db"])] = "database account read (tag, payload)"
        names[(spec, var["flag40"])] = "flag 0x40 callback on the account"
        names[(spec, var["lazy"])] = "lazy initialiser of the code-object Arc cell"
        for slot, nm in ((WARM_GOT, "warm-set test (state+0x48, address) -> al"), (DEALLOC_GOT, "deallocate (ptr, size, 0)"),
                         (CTOR_GOT, "account constructor from the database payload"), (COPY_GOT, "memcpy"),
                         (var["vec_grow_got"], "journal Vec grow-one"), (TOUCH_GOT, "account touch callback"),
                         (SEED_INIT_GOT, "global hash-seed block initialiser")):
            names[(spec, image.word(slot))] = nm
    return names


def static_evidence(image):
    rows = al.fde_rows(image, [ORD, SPEC, PREP])
    funcs, calls, decoded = {}, [], {}
    names = contract_names(image)
    for spec, start in ((False, ORD), (True, SPEC), ("prep", PREP)):
        lo, hi = rows[start]
        decoded[start] = sweep_rows(image, lo, hi)
        body = image.code(lo, hi - lo)
        funcs[f"{start:#x}"] = {"fde_end": f"{hi:#x}", "fde_bytes": hi - lo, "sha256": hashlib.sha256(body).hexdigest(),
                                "instructions": sum(1 for _, f in decoded[start] if f is not None),
                                "frame_sub": VARIANT[start]["sub"] if start != PREP else 0x68}
        for va, f in decoded[start]:
            if f is None:
                continue
            if f["op"] == 0xe8:
                calls.append((start, va, "direct", f"{f['target']:#x}", names.get((spec, f["target"]), "unwind or cold helper")))
            elif f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip":
                slot = (va + f["len"] + f["rm"][4]) & M64
                tgt = image.word(slot)
                shown = f"import {image.import_name(slot)}" if slot in image.imports else f"{tgt:#x}"
                calls.append((start, va, f"got {slot:#x}", shown, names.get((spec, tgt), "unwind or cold helper")))
    checks = {}
    for va, want in ((0x4323b5b, b"\x48\xb8" + C_TLS.to_bytes(8, "little")),
                     (0x4323b7d, b"\x48\xb9" + C_SEED.to_bytes(8, "little")),
                     (0x4323b65, b"\x64\x48\x33\x04\x25" + (TLS_OFF & 0xffffffff).to_bytes(4, "little")),
                     (0x4323ce9, b"\x49\xc1\xe9\x39"), (0x4323d0b, b"\x49\x69\xd2\xa8\x00\x00\x00"[:0] + b""),
                     (0x5463ee0 - 0x560 + 0x560, b"")):
        pass
    for va, want in ((0x4323b5b, b"\x48\xb8" + C_TLS.to_bytes(8, "little")),
                     (0x4323b7d, b"\x48\xb9" + C_SEED.to_bytes(8, "little")),
                     (0x4323b65, b"\x64\x48\x33\x04\x25" + (TLS_OFF & 0xffffffff).to_bytes(4, "little")),
                     (0x4323ce9, b"\x49\xc1\xe9\x39"), (0x4323b97, b"\x0f\xb6\x40\x30\x3c\x02")):
        if image.code(va, len(want)) != want:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = want.hex()
    consts = {
        "binary_sha256": SHA256, "functions": funcs, "checked_bytes": checks,
        "got_slots": {f"{s:#x}": {"relocation": "GLOB_DAT" if s in image.imports else "RELATIVE", "target": f"{image.word(s):#x}"}
                      for s in (WARM_GOT, DEALLOC_GOT, CTOR_GOT, COPY_GOT, TOUCH_GOT, SEED_INIT_GOT, SEED_GOT, ARC_GOT,
                                0x64e68e8, 0x64e6cf0)},
        "default_account_templates": {
            "ord": [f"{image.word(VARIANT[ORD]['tmpl'] + 8 * k):#x}" for k in range(4)],
            "spec": [f"{image.word(VARIANT[SPEC]['tmpl'] + 8 * k):#x}" for k in range(4)],
            "rodata_4585a0": [f"{image.word(ROD_EMPTY + 8 * k):#x}" for k in range(4)]},
        "tls": {"fs_offset": f"{TLS_OFF:#x}", "mix": f"{C_TLS:#x}", "seed_multiplier": f"{C_SEED:#x}"},
        "layout": {"state": {"journal_cap": "0x18", "journal_ptr": "0x20", "journal_len": "0x28", "warm_set": "0x48",
                             "account_map": "0xc8", "epoch": "0x120"},
                   "entry": {"size": "0xa8", "key": "-0xa8", "value": "-0x94", "account": "-0x90", "epoch": "-0x8",
                             "flags": "-0x4"},
                   "journal_record": {"size": "0x58", "tag": 0, "address_at": 1},
                   "output": {"account": "0x0", "journal": "0x8", "state70": "0x10", "db": "0x18", "epoch": "0x20",
                              "address": "0x24", "status": "0x38"}},
    }
    return consts, decoded, calls


# ---------------------------------------------------------------- reporting
def classify(c, want):
    if want["path"] == "prep":
        return "prep/" + want["pclass"] if want["status"] != "ud2" else "prep/default/ud2"
    if want["status"] == "ud2":
        return "default/ud2"
    ev = [e[0] for e in want["events"]]
    out = want["mem"][OUT_AT]
    status = out[0x38]
    if status == 2:
        return "refused/" + want["path"]
    if "lookup" in ev and "warm" not in ev:
        return "hit/fresh"
    if "db" not in ev:
        return f"hit/refreshed/cold{status & 1}" if status in (0, 1) else "hit/refreshed/odd"
    if "ctor" in ev:
        return "load/ctor"
    err = [e for e in ev if e in ("vcall", "free")]
    return "load/default" + ("+err-" + err[0] if err else "")


def variant_name(c):
    return "prep" if c["spec"] == "prep" else ("spec" if c["spec"] else "ord")


def case_line(c, want, got, ok):
    ev = ",".join(e[0] for e in want["events"])
    if want["status"] == "ud2":
        res = "ud2"
    elif want["path"] == "prep":
        res = f"code_ptr={u(want['mem'][ACCT_AT], 0x70, 8):#x},arc_refcnt={u(want['mem'][ARC_AT], 0, 8):#x}"
    else:
        out = want["mem"][OUT_AT]
        state = want["mem"][STATE_AT]
        res = (f"status={out[0x38]},items={u(state, 0xe0, 8)},journal={u(state, 0x28, 8)},"
               f"growth={u(state, 0xd8, 8):#x}")
    inp = (f"flag={c['flag'] & 0xff:#x},warm={c['warm']:#x},buckets={c['buckets']},epoch={c['epoch']:#x},"
           f"jcap={c['jcap']},jlen={c['jlen']},refcnt={c['refcnt']:#x},tag={u(c['dbraw'], 0, 8):#x}")
    if c["spec"] == "prep":
        inp = f"code={u(c['account'], 0x70, 8):#x},refcnt={c['refcnt']:#x},tag={u(c['dbraw'], 0, 8):#x},lazy={c['lazy_state']:#x}"
    return "\t".join((variant_name(c), str(c["i"]), c["kind"], inp, classify(c, want), ev, res,
                      str(got.get("steps", 0)), "yes" if ok else "NO"))


PREP_MUTANTS = ["empty_swapped", "tag_low32", "free_zero_size"]
MODEL_MUTANTS = ["no_epoch_check", "ignore_10", "occupied_nonzero", "status_plain", "vacant_ne1", "tag_cmp_64",
                 "refcnt_simple_overflow", "tls_no_stack", "seed_lo_only", "residue_zero", "journal_when_warm",
                 "top7_shift", "growth_always", "copy_len"]


def code_candidates(image, decoded):
    cands = []
    for start, rows in decoded.items():
        for pos, (va, f) in enumerate(rows):
            if f is None:
                continue
            op = f["op"]
            nxt = rows[pos + 1][1] if pos + 1 < len(rows) else None
            if op in (0x83, 0x81, 0x3d) and nxt is not None and nxt["op"] == 0x85 and "imm" in f:
                continue  # compare whose flags are overwritten by the next test: an equivalent mutant
            if 0x70 <= op <= 0x7f:
                cands.append((start, va, "jcc-invert", va, f["bytes"][0] ^ 1))
            elif 0x0f80 <= op <= 0x0f8f:
                cands.append((start, va, "jcc-invert", va + (2 if f.get("lock") else 1), f["bytes"][1] ^ 1))
            elif "imm" in f and op not in (0xe8, 0xe9, 0xeb) and not (0x70 <= op <= 0x7f):
                if 0xb8 <= op <= 0xbf:
                    size = 8 if f["rex"] & 8 else 4
                elif op in (0x81, 0xc7, 0x69, 0x3d, 0xf7):
                    size = 4
                else:
                    size = 1
                at = va + f["len"] - size  # lowest immediate byte, bit 0 flipped
                cands.append((start, va, "imm-flip", at, f["bytes"][len(f["bytes"]) - size] ^ 1))
    return cands


def controls(image, decoded, seen, n_probe=800):
    rows = []
    sample = {sp: [make_case(image, sp, i) for i in range(n_probe)] for sp in (False, True)}
    sample["prep"] = [make_prep_case(image, i) for i in range(n_probe)]
    for name in MODEL_MUTANTS:
        cases = [x for pair in zip(sample[False], sample[True]) for x in pair]
        rows.append(("model", name, 1 if detects(image, None, frozenset([name]), cases) else 0, "-"))
    for name in PREP_MUTANTS:
        rows.append(("model", "prep-" + name, 1 if detects(image, None, frozenset([name]), sample["prep"]) else 0, "-"))
    unexecuted = []
    for start, va, kind, at, newb in code_candidates(image, decoded):
        spec = {ORD: False, SPEC: True, PREP: "prep"}[start]
        if va not in seen[spec]:
            unexecuted.append((start, va, kind))
            continue
        hit = detects(image, {at: newb}, frozenset(), sample[spec])
        if not hit:
            hit = detects(image, {at: newb}, frozenset(),
                          (make_case(image, spec, i) if spec != "prep" else make_prep_case(image, i)
                           for i in range(n_probe, 6000 if spec != "prep" else 2600)))
        rows.append(("code", f"{start:#x}+{va - start:#x}/{kind}", 1 if hit else 0, "-"))
    # bytes that must not be accepted: wrong binary, address outside .text, wrong variant entry
    try:
        Image_bad = al.Image(bytes(image.data[:-1]) + bytes([image.data[-1] ^ 1]))
        rows.append(("input", "last-byte-flipped-binary", 0, "-"))
    except ToolError:
        rows.append(("input", "last-byte-flipped-binary", 1, "-"))
    try:
        image.code(0x10, 4)
        rows.append(("input", "address-outside-text", 0, "-"))
    except ToolError:
        rows.append(("input", "address-outside-text", 1, "-"))
    machines = new_machines(image)
    wrong = 0
    for i in range(40):
        c = make_case(image, False, i)
        want = reconstruct(image, False, c)
        try:
            ok = compare(want, run_machine(machines[True], True, c))
        except (ToolError, Boundary, IndexError, KeyError, ValueError):
            ok = False
        wrong += 0 if ok else 1
    rows.append(("input", "ord-case-on-spec-entry", 1 if wrong else 0, "-"))
    return rows, unexecuted


def generate(out, per_variant=6000, probe=800):
    image = al.Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    consts, decoded, calls = static_evidence(image)
    machines = new_machines(image)
    classes, steps_total, n, bad = {}, 0, 0, 0
    with open(out / "cases.tsv", "w") as fh:
        fh.write("variant\tcase\tkind\tinput\tclass\tcallee_events\tresult\tsteps\tmatch\n")
        every = (c for src in (all_cases(image, per_variant), prep_cases(image)) for c in src)
        for c, want, got, ok in run_stream(image, machines=machines, cases=every):
            n += 1
            bad += 0 if ok else 1
            steps_total += got.get("steps", 0)
            cl = classify(c, want)
            tagname = f"{variant_name(c)}:{cl}"
            classes[tagname] = classes.get(tagname, 0) + 1
            fh.write(case_line(c, want, got, ok) + "\n")
    seen = {key: machines[key].seen for key in (False, True, "prep")}
    (out / "outcome-classes.tsv").write_text("class\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    lines = ["function\taddress\tlength\tbytes\topcode\texecuted"]
    covered = {}
    for start, rows in sorted(decoded.items()):
        hit = total = 0
        for va, f in rows:
            if f is None:
                lines.append(f"{start:#x}\t{va:#x}\t1\tcc\tpadding\t0")
                continue
            run = va in seen[{ORD: False, SPEC: True, PREP: "prep"}[start]]
            hit += run
            total += 1
            lines.append(f"{start:#x}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}\t{int(run)}")
        covered[f"{start:#x}"] = [hit, total]
    (out / "decoded-instructions.tsv").write_text("\n".join(lines) + "\n")
    (out / "callee-sites.tsv").write_text(
        "function\tsite\tkind\ttarget\tcontract\n" + "".join(f"{s:#x}\t{v:#x}\t{k}\t{t}\t{nm}\n" for s, v, k, t, nm in calls))
    ctl, unexecuted = controls(image, decoded, seen, probe)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join(f"{a}\t{b}\t{d}\n" for a, b, d, _ in ctl))
    (out / "unexecuted-mutants.tsv").write_text(
        "function\tsite\tkind\n" + "".join(f"{s:#x}\t{v:#x}\t{k}\n" for s, v, k in unexecuted))
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    detected = sum(r[2] for r in ctl)
    summary = {"binary_sha256": SHA256, "cases": n, "mismatches": bad, "machine_steps": steps_total,
               "covered_instructions": covered, "outcome_classes": classes,
               "negative_controls": {"total": len(ctl), "detected": detected},
               "unexecuted_mutant_sites": len(unexecuted)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps(
        {"cases": n, "negative_controls": len(ctl), "negative_detected": detected, "mismatches": bad}, sort_keys=True) + "\n")
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
