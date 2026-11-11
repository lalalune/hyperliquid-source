"""Reconstruct the node #115 abci state-serialization front ends (state.rs timed save bodies).

Three bodies are covered: 0x26A2C80 (save to a path: "/dev/null" skip, output format chosen by
the file extension of the normalised path, "rmp" -> MessagePack writer, anything else -> pretty
JSON with a two space indent, file prepare + write, then a timed log record) and the two plain
twins 0x4E4A960 / 0x4E4AC70 (one serializer call, then the same timed log record). The shared
extension test 0x159FCA0 (ASCII case-insensitive equality) is run for real against its own
reconstruction. Each body's real instruction bytes run in the shared evaluator of
tools/decimal_scaled_u64.py (extended here with the scalar-double instructions the timing code
uses) with every callee replaced by a logging stub; the ordered callee log (arguments included)
is compared with independently written Python reconstructions. Every conditional jump is
flipped and must be caught, and deliberately wrong reconstructions are negative controls. The
target is read, never executed. Every number in the output comes from ELF bytes or from these runs.
"""
import argparse
import copy
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as cpu  # noqa: E402  shared #115 evaluator (Image, decode, Machine)

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
U64 = (1 << 64) - 1
NONE_CAP = 1 << 63
OK_TAG = NONE_CAP + 4
ENTRY_SP = cpu.STACK - 0x800
STEP_LIMIT = 4000
ONCE_FLAG = 0x64F01A8
RMP_EXT = b"rmp"

# body -> role -> callee address (direct call) ; slot roles are resolved from relocated slots
FULL, PLAIN_A, PLAIN_B = 0x26A2C80, 0x4E4A960, 0x4E4AC70
DIRECT = {
    FULL: {"now": 0x5C842E0, "dur": 0x5C84210, "ser_rmp": 0x22EBDC0, "ser_json": 0x22EBC70,
           "err_a": 0x26A6AF0, "err_b": 0x26A6BC0, "eq": 0x159FCA0},
    PLAIN_A: {"now": 0x5C842E0, "dur": 0x5C84210, "ser": 0x50DD9D0},
    PLAIN_B: {"now": 0x5C842E0, "dur": 0x5C84210, "ser": 0x50DEB30},
}
SLOTS = {  # role -> GOT slot (the relocated target is read from .rela.dyn)
    "norm": 0x64E0938, "prep": 0x64E0028, "write": 0x64E09E8, "utcnow": 0x64E0990,
    "malloc": 0x64DF480, "free": 0x64DF4A0, "log": 0x64E0AE8, "unwrap": 0x64DF6A0,
    "once": 0x64DF9F0, "oom": 0x64DF498,
}
USED_SLOTS = {
    FULL: ("norm", "prep", "write", "utcnow", "malloc", "free", "log", "unwrap", "once", "oom"),
    PLAIN_A: ("utcnow", "free", "log", "unwrap", "once"),
    PLAIN_B: ("utcnow", "free", "log", "unwrap", "once"),
}
# stack layout of the timed log record, offsets from the body's own rsp
LAYOUT = {
    FULL: {"msg": 0x0, "f64": 0xE0, "tsa": 0xA8, "tsb": 0xAC, "tsc": 0xB4, "fmt": 0x88},
    PLAIN_A: {"msg": 0x8, "f64": 0x78, "tsa": 0xD0, "tsb": 0xD4, "tsc": 0xDC, "fmt": 0xB0},
    PLAIN_B: {"msg": 0x8, "f64": 0x78, "tsa": 0xD0, "tsb": 0xD4, "tsc": 0xDC, "fmt": 0xB0},
}
OBJ_ADDR, PATH_ADDR, TRIPLE, NORM_ADDR, BUF, SOBJ, OUTREC = (cpu.INPUT + i * 0x1000 for i in range(7))
EQ_A, EQ_B = cpu.INPUT + 0x10000, cpu.INPUT + 0x11000
START_SECS = 0x1122_3344_5566
END_SECS = 0x7788_99AA_BBCC
OBJ_VALUE = 0x5E5E_0001
SER_ERR_WORDS = (0x6000_AAAA, 0x6000_BBBB)
JSON_ERR = 0x6000_CCCC
PREP_ERR = 0x6000_DDDD
WRITE_ERR = 0x6000_EEEE
ERR_A_RET, ERR_B_RET = 0x6100_0001, 0x6100_0002


class Fail(Exception):
    pass


def load_image():
    data = TARGET.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise Fail(f"target digest {digest} != {SHA256}")
    return cpu.Image(data)


# ---------------------------------------------------------------- static facts from bytes

def body_insns(image, start):
    lo, hi = image.fde_of(start)
    if lo != start:
        raise Fail(f"{start:#x} is not an FDE start")
    out, va = [], lo
    while va < hi:
        insn = image.fetch(va)
        out.append(insn)
        if insn.key == 0xCC:
            break
        va += insn.size
    return lo, hi, out


def slot_of(image, insn):
    if insn.modrm is None:
        return None
    modrm = image.data[insn.modrm]
    if modrm & 0xC7 != 0x05:
        return None
    return insn.va + insn.size + struct.unpack_from("<i", image.data, insn.modrm + 1)[0]


def call_rows(image, start):
    rows = []
    for insn in body_insns(image, start)[2]:
        if insn.key == 0xE8:
            rows.append((insn.va, "call", insn.target, ""))
        elif insn.key == 0xFF and (image.data[insn.modrm] >> 3) & 7 == 2:
            slot = slot_of(image, insn)
            if slot is not None:
                rows.append((insn.va, "slot_call", image.slots.get(slot, 0), f"slot={slot:#x}"))
    return rows


def rip_leas(image, start):
    """Targets of every rip-relative lea in byte order."""
    return [slot_of(image, i) for i in body_insns(image, start)[2]
            if i.key == 0x8D and slot_of(image, i) is not None]


def jcc_sites(image, start):
    rows = []
    for insn in body_insns(image, start)[2]:
        if isinstance(insn.key, int) and 0x70 <= insn.key <= 0x7F:
            rows.append((insn.va, insn.off + insn.size - 2))
        elif isinstance(insn.key, tuple) and len(insn.key) == 2 and 0x80 <= insn.key[1] <= 0x8F:
            rows.append((insn.va, insn.off + insn.size - 5))
    return rows


def rodata_bytes(image, va, n):
    off = image.file_offset(va)
    return bytes(image.data[off:off + n])


def roles_for(image, start):
    roles = {v: k for k, v in DIRECT[start].items()}
    for name in USED_SLOTS[start]:
        roles[image.slots[SLOTS[name]]] = name
    return roles


# ---------------------------------------------------------------- evaluator with stubs

def f64_bits(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def eq_ignore_ascii_case(a, b):
    return len(a) == len(b) and all((x | 0x20 if 0x41 <= x <= 0x5A else x) == (y | 0x20 if 0x41 <= y <= 0x5A else y)
                                    for x, y in zip(a, b))


class Machine(cpu.Machine):
    """Evaluator with logging callee stubs and the scalar double instructions of the timing code."""

    def __init__(self, image, case, start):
        super().__init__(image)
        self.case, self.start, self.log = case, start, []
        self.roles = roles_for(image, start)
        self.layout = LAYOUT.get(start)

    # -- scalar double instructions: movsd, cvtsi2sd, unpcklps, subpd, unpckhpd, addsd, divsd, ucomisd
    def step(self):
        insn = self.image.fetch(self.pc)
        key, data = insn.key, self.image.data
        if key == 0x98 and insn.rex & 8:          # cdqe
            self.pc = insn.va + insn.size
            v = self.get(cpu.RAX, 32)
            self.put(cpu.RAX, 64, None if v is None else (v - (1 << 32) if v >> 31 else v) & U64)
            return
        if isinstance(key, tuple) and key[0] == 0x0F and insn.modrm is not None and self.sse(insn, key[1], data):
            return
        super().step()

    def xlow(self, reg):
        x = self.xmm[reg]
        return None if x is None else struct.unpack_from("<Q", x)[0]

    def sse(self, insn, two, data):
        reg = ((data[insn.modrm] >> 3) & 7) | ((insn.rex & 4) << 1)
        scalar, packed66 = insn.rep == 0xF2, insn.wide16
        if two in (0x10, 0x11) and scalar:            # movsd
            operand = self.operand(insn)
            self.pc = insn.va + insn.size
            if two == 0x10:
                value = self.xlow(operand[1]) if operand[0] == "r" else self.load(self.address(operand), 8)
                old = self.xmm[reg]
                high = bytes(8) if operand[0] == "m" else (old[8:] if old else bytes(8))
                self.xmm[reg] = None if value is None else struct.pack("<Q", value) + high
            else:
                value = self.xlow(reg)
                if operand[0] == "r":
                    self.xmm[operand[1]] = None if value is None else struct.pack("<Q", value) + bytes(8)
                else:
                    self.store(self.address(operand), 8, value)
            return True
        if two == 0x2A and scalar:                    # cvtsi2sd xmm, r/m32
            self.pc = insn.va + insn.size
            v = self.read(self.operand(insn), 64 if insn.rex & 8 else 32)
            if v is None:
                cpu.fail("cvtsi2sd of unknown value")
            bits = 64 if insn.rex & 8 else 32
            v = v - (1 << bits) if v >> (bits - 1) else v
            old = self.xmm[reg] or bytes(16)
            self.xmm[reg] = struct.pack("<d", float(v)) + old[8:]
            return True
        if two in (0x14, 0x15, 0x5C, 0x58, 0x5E, 0x2E):
            operand = self.operand(insn)
            self.pc = insn.va + insn.size
            if operand[0] == "r":
                src = self.xmm[operand[1]]
            else:
                at = self.address(operand)
                size = 8 if (scalar or two == 0x2E) else 16
                lo = self.load(at, 8)
                hi = self.load(at + 8, 8) if size == 16 else 0
                src = None if lo is None or hi is None else struct.pack("<QQ", lo, hi)
            dst = self.xmm[reg]
            if src is None or dst is None:
                cpu.fail(f"scalar double operand unknown at {insn.va:#x}")
            d0, d1 = struct.unpack("<dd", dst)
            s0, s1 = struct.unpack("<dd", src)
            if two == 0x14:                           # unpcklps: dwords d0 s0 d1 s1
                dw, sw = struct.unpack("<4I", dst), struct.unpack("<4I", src)
                self.xmm[reg] = struct.pack("<4I", dw[0], sw[0], dw[1], sw[1])
            elif two == 0x15:                         # unpckhpd (66): high of dst, high of src
                self.xmm[reg] = dst[8:] + src[8:]
            elif two == 0x5C:                         # subpd (66)
                self.xmm[reg] = struct.pack("<dd", d0 - s0, d1 - s1)
            elif two == 0x58:                         # addsd
                self.xmm[reg] = struct.pack("<d", d0 + s0) + dst[8:]
            elif two == 0x5E:                         # divsd
                self.xmm[reg] = struct.pack("<d", d0 / s0) + dst[8:]
            else:                                     # ucomisd: ZF set when equal or unordered
                unordered = d0 != d0 or s0 != s0
                self.flags = [d0 < s0 or unordered, d0 == s0 or unordered, False, False]
            return True
        return False

    def bytes_at(self, at, n):
        return bytes(self.load(at + i, 1) for i in range(n))

    def frame(self):
        return self.get(cpu.RSP, 64)

    def rel(self, value):
        """Stack addresses are logged as offsets from the entry stack pointer."""
        if value is not None and cpu.STACK - 0x10000 <= value <= cpu.STACK:
            return ("sp", value - ENTRY_SP)
        return value

    def call(self, target, where):
        role = self.roles.get(target)
        if role is None:
            raise cpu.Done(f"unexpected call {target:#x}", where)
        a = [self.get(r, 64) for r in (cpu.RDI, cpu.RSI, cpu.RDX, cpu.RCX, cpu.R8, cpu.R9)]
        ret = getattr(self, "stub_" + role)(a)
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        for reg, value in (ret or {}).items():
            self.set_reg(reg, value)
        self.flags = [None, None, None, None]
        self.pc = where + self.image.fetch(where).size

    # timing
    def stub_now(self, a):
        n = sum(1 for row in self.log if row[0] == "now")
        self.log.append(("now",))
        return {cpu.RAX: START_SECS if n == 0 else END_SECS, cpu.RDX: 0x1000 + n}

    def stub_dur(self, a):
        end = (self.load(a[1], 8), self.load(a[1] + 8, 4))
        start = (self.load(a[2], 8), self.load(a[2] + 8, 4))
        self.log.append(("dur", end, start))
        d = self.case["dur"]
        self.store(a[0], 1, 0 if d is not None else 1)
        if d is not None:
            self.store(a[0] + 8, 8, d[0])
            self.store(a[0] + 16, 4, d[1])

    def stub_utcnow(self, a):
        self.log.append(("utcnow", self.rel(a[0])))
        for i, w in enumerate(self.case["ts"]):
            self.store(a[0] + 4 * i, 4, w)

    def stub_once(self, a):
        self.log.append(("once", a[0], a[1], self.load(a[2], 8) is not None))

    def stub_log(self, a):
        sp, lay = self.frame(), self.layout
        self.log.append(("log", a[0], self.load(sp + lay["msg"], 8), self.load(sp + lay["msg"] + 8, 8),
                         self.load(sp + lay["f64"], 8), self.load(sp + lay["tsa"], 4),
                         self.load(sp + lay["tsb"], 8), self.load(sp + lay["tsc"], 4),
                         self.load(sp + lay["fmt"], 8), self.load(sp + lay["fmt"] + 8, 8),
                         self.load(sp + lay["fmt"] + 16, 8), self.load(sp + lay["fmt"] + 24, 8)))

    def stub_free(self, a):
        self.log.append(("free", a[0], a[1], a[2]))

    def stub_unwrap(self, a):
        err = self.load(a[2], 8)
        self.log.append(("unwrap", a[0], a[1], err, a[3], a[4]))
        raise cpu.Done("unwrap", self.pc)

    def stub_oom(self, a):
        self.log.append(("oom", a[0], a[1]))
        raise cpu.Done("oom", self.pc)

    # plain twins
    def stub_ser(self, a):
        self.log.append(("ser", self.rel(a[0]), self.load(a[0], 8), self.load(a[0] - 8, 8), a[1], a[2], a[3]))
        return {cpu.RAX: self.case["ser_err"]}

    # full body
    def stub_norm(self, a):
        self.log.append(("norm", self.load(a[1], 8), self.load(a[1] + 8, 8), self.load(a[1] + 0x10, 1),
                         self.load(a[1] + 0x38, 2), self.load(a[1] + 0x3A, 1)))
        norm = self.case["norm"]
        if norm is None:
            self.store(a[0], 1, 5)
        else:
            self.store(a[0], 1, 9)
            self.store(a[0] + 8, 8, NORM_ADDR)
            self.store(a[0] + 16, 8, len(norm))

    def stub_eq(self, a):
        self.log.append(("eq", self.bytes_at(a[0], a[1]), a[2], a[3]))
        return {cpu.RAX: int(eq_ignore_ascii_case(self.bytes_at(a[0], a[1]), self.bytes_at(a[2], a[3])))}

    def stub_ser_rmp(self, a):
        sp = self.frame()
        cfg = a[2]
        self.log.append(("ser_rmp", self.load(a[1], 8), self.load(a[1] + 8, 8), self.load(a[1] + 16, 8),
                         self.load(a[1] + 24, 8), self.rel(self.load(cfg, 8)), self.load(cfg + 8, 4),
                         self.load(cfg + 12, 1), self.load(self.load(cfg, 8), 8), self.load(self.load(cfg, 8) + 8, 8),
                         self.load(self.load(cfg, 8) + 16, 8)))
        c = self.case
        vec = self.load(cfg, 8)
        if c["fmt_err"]:
            self.store(a[0], 8, NONE_CAP + 1)
            self.store(a[0] + 8, 8, SER_ERR_WORDS[0])
            self.store(a[0] + 16, 8, SER_ERR_WORDS[1])
            self.store(vec, 8, c["cap"])
        else:
            self.store(a[0], 8, OK_TAG)
            self.store(vec, 8, c["cap"])
            self.store(vec + 8, 8, BUF)
            self.store(vec + 16, 8, c["len"])

    def stub_ser_json(self, a):
        w = a[1]
        self.log.append(("ser_json", self.load(a[0], 8), self.load(a[0] + 8, 8), self.load(a[0] + 16, 8),
                         self.load(a[0] + 24, 8), self.rel(self.load(w, 8)), self.load(w + 8, 8), self.load(w + 16, 8),
                         self.load(w + 24, 8), self.load(w + 32, 1)))
        c = self.case
        if c["fmt_err"]:
            return {cpu.RAX: JSON_ERR}
        vec = self.load(w, 8)
        self.store(vec, 8, c["cap"])
        self.store(vec + 8, 8, BUF)
        self.store(vec + 16, 8, c["len"])
        return {cpu.RAX: 0}

    def stub_malloc(self, a):
        self.log.append(("malloc", a[0]))
        return {cpu.RAX: 0 if self.case["oom"] else BUF + 0x400}

    def stub_err_a(self, a):
        self.log.append(("err_a", self.rel(a[0]), a[1]))
        return {cpu.RAX: ERR_A_RET}

    def stub_err_b(self, a):
        self.log.append(("err_b", self.rel(a[0]), self.load(a[1], 8), self.load(a[1] + 8, 8), self.load(a[1] + 16, 8)))
        return {cpu.RAX: ERR_B_RET}

    def stub_prep(self, a):
        self.log.append(("prep", a[0], a[1]))
        return {cpu.RAX: PREP_ERR if self.case["prep_err"] else 0}

    def stub_write(self, a):
        self.log.append(("write", a[0], a[1], a[2], a[3], a[4]))
        return {cpu.RAX: WRITE_ERR if self.case["write_err"] else 0}


# ---------------------------------------------------------------- running a body

def setup(m, case, start):
    for reg in range(16):
        m.set_reg(reg, 0x0BAD_0000 + reg * 0x100)
    path = case["path"]
    m.set_reg(cpu.RDI, TRIPLE)
    m.set_reg(cpu.RSP, ENTRY_SP)
    m.store(ENTRY_SP, 8, cpu.RETURN_MARK)
    m.store(TRIPLE, 8, OBJ_ADDR)
    m.store(TRIPLE + 8, 8, PATH_ADDR)
    m.store(TRIPLE + 16, 8, len(path))
    m.store(OBJ_ADDR, 8, SOBJ)
    m.store(SOBJ + 0x28, 8, OBJ_VALUE)
    for i, b in enumerate(path):
        m.store(PATH_ADDR + i, 1, b)
    if start == FULL and case["norm"] is not None:
        for i, b in enumerate(case["norm"]):
            m.store(NORM_ADDR + i, 1, b)
    m.store(ONCE_FLAG, 4, case["once"])


def run_body(image, start, case, seen=None):
    m = Machine(image, case, start)
    setup(m, case, start)
    kind = "ret"
    try:
        m.pc = start
        while True:
            m.steps += 1
            if m.steps > STEP_LIMIT:
                return ("limit",)
            m.step()
    except cpu.Done as done:
        if done.how not in ("ret", "unwrap", "oom"):
            return ("stop", done.how)
        kind = done.how
    except cpu.ToolError as err:
        return ("error", str(err))
    finally:
        if seen is not None:
            seen |= m.seen
    return (kind, tuple(m.log))


def run_eq(image, a, b, seen=None):
    """Run the real 0x159FCA0 on two byte strings (lengths below 16 or unequal lengths)."""
    m = Machine(image, {"dur": None, "ts": (0, 0, 0)}, FULL)
    for reg in range(16):
        m.set_reg(reg, 0x0BAD_0000 + reg * 0x100)
    for i, x in enumerate(a):
        m.store(EQ_A + i, 1, x)
    for i, x in enumerate(b):
        m.store(EQ_B + i, 1, x)
    m.set_reg(cpu.RDI, EQ_A)
    m.set_reg(cpu.RSI, len(a))
    m.set_reg(cpu.RDX, EQ_B)
    m.set_reg(cpu.RCX, len(b))
    m.set_reg(cpu.RSP, ENTRY_SP)
    m.store(ENTRY_SP, 8, cpu.RETURN_MARK)
    try:
        m.pc = 0x159FCA0
        while True:
            m.steps += 1
            if m.steps > STEP_LIMIT:
                return ("limit",)
            m.step()
    except cpu.Done as done:
        if done.how != "ret":
            return ("stop", done.how)
    except cpu.ToolError as err:
        return ("error", str(err))
    finally:
        if seen is not None:
            seen |= m.seen
    return ("ret", m.get(cpu.RAX, 8))


# ---------------------------------------------------------------- the reconstructions

def duration_seconds(dur, variant=None):
    """What the timed log record reports: whole seconds plus nanoseconds / 1e9 (0.0 on an Err)."""
    if dur is None:
        return 0.0
    secs, nanos = dur
    if variant == "unsigned_nanos":
        pass
    elif nanos >> 31:
        nanos -= 1 << 32
    value = float(nanos) / 1e9 + float(secs)
    if variant == "no_nanos":
        value = float(secs)
    if variant == "truncate":
        value = float(int(value))
    return 0.0 if value == 0 else value


def tail_rows(case, consts, frame_ts, variant=None):
    c = consts
    rows = [("now",), ("dur", (END_SECS, 0x1001), (START_SECS, 0x1000)), ("utcnow", ("sp", frame_ts))]
    if case["once"] or variant == "once_always":
        rows.append(("once", ONCE_FLAG, 1, True))
    ts = case["ts"]
    tsb = ts[1] | (ts[2] << 32)
    rows.append(("log", c["target"], c["msg"], 0x2B, f64_bits(duration_seconds(case["dur"], variant)), 1,
                 tsb, ts[0], c["fmt"], 0x16, 8, 0))
    return rows


def last_dot(name):
    """Index of the last '.' scanning down to index 0, or None."""
    for i in range(len(name) - 1, -1, -1):
        if name[i] == 0x2E:
            return i
    return None


def extension_of(name, variant=None):
    """The extension the body hands to the comparison, or None when it falls back to the default."""
    if len(name) == 2 and name == b".." and variant != "dotdot_allowed":
        return None
    i = last_dot(name)
    if variant == "first_dot":
        i = name.find(b".") if b"." in name else None
    if i is None:
        return None
    if i == 0 and variant != "dot0_allowed":
        return None
    return name[i + 1:]


def full_consts(image):
    L = rip_leas(image, FULL)
    return {"rmp": L[0], "indent": L[1], "write_loc": L[2], "fmt": L[3], "msg": L[4], "target": L[10],
            "uw_msg": L[11], "uw_vt": L[12], "uw_loc": L[13]}


def plain_consts(image, start):
    L = rip_leas(image, start)
    return {"ser_vt": L[0], "fmt": L[1], "msg": L[2], "target": L[8], "uw_msg": L[9], "uw_vt": L[10],
            "uw_loc": L[11]}


def model_full(case, c, variant=None):
    F = -0x128
    path, log = case["path"], [("now",)]
    null = path == b"/dev/null"
    if variant == "devnull_prefix":
        null = path[:8] == b"/dev/nul"
    if variant == "no_devnull":
        null = False
    tail = lambda: ("ret", tuple(log + tail_rows(case, c, F + 0x10, variant)))
    if null:
        return tail()
    absf = 1 if path[:1] == b"/" else 0
    if variant == "abs_always":
        absf = 1
    log.append(("norm", PATH_ADDR, len(path), 6, 0x201, absf))
    use_rmp = False
    if case["norm"] is not None:
        ext = extension_of(case["norm"], variant)
        if ext is not None:
            log.append(("eq", ext, c["rmp"], 3))
            if variant == "case_sensitive":
                use_rmp = ext == RMP_EXT
            elif variant == "prefix_only":
                use_rmp = ext[:3].lower() == RMP_EXT
            else:
                use_rmp = eq_ignore_ascii_case(ext, RMP_EXT)
    cap, ln, ptr = case["cap"], case["len"], BUF
    unwrap = lambda err: ("unwrap", tuple(log + [("unwrap", c["uw_msg"], 0x2B, err, c["uw_vt"], c["uw_loc"])]))
    if use_rmp:
        log.append(("ser_rmp", SOBJ, PATH_ADDR, len(path), OBJ_VALUE, ("sp", F + 0x68), 0x1000400, 0, 0, 1, 0))
        if case["fmt_err"]:
            if cap:
                log.append(("free", 1, cap, 0))
            log.append(("err_b", ("sp", F + 0xC8), NONE_CAP + 1, SER_ERR_WORDS[0], SER_ERR_WORDS[1]))
            return unwrap(ERR_B_RET)
    else:
        log.append(("malloc", 0x80))
        if case["oom"] and variant != "oom_ignored":
            log.append(("oom", 1, 0x80))
            return ("oom", tuple(log))
        log.append(("ser_json", SOBJ, PATH_ADDR, len(path), OBJ_VALUE, ("sp", F + 0x68), c["indent"], 2, 0, 0))
        if case["fmt_err"]:
            log.append(("free", BUF + 0x400, 0x80, 0))
            log.append(("err_a", ("sp", F + 0xC8), JSON_ERR))
            return unwrap(ERR_A_RET)
        if cap == NONE_CAP and variant != "cap_marker_ignored":
            log.append(("err_a", ("sp", F + 0xC8), BUF))
            return unwrap(ERR_A_RET)
    log.append(("prep", PATH_ADDR, len(path)))
    if variant == "write_first":
        log.pop()
    free = [("free", ptr, cap, 0)] if (cap or variant == "free_always") else []
    if case["prep_err"]:
        log.extend(free)
        return unwrap(PREP_ERR)
    log.append(("write", ptr, ln, PATH_ADDR, len(path), c["write_loc"]))
    log.extend(free)
    if case["write_err"]:
        return unwrap(WRITE_ERR)
    return tail()


def model_plain(case, c, variant=None):
    F = -0x118
    log = [("now",), ("ser", ("sp", F + 0x70), SOBJ, OBJ_VALUE, PATH_ADDR, len(case["path"]), c["ser_vt"])]
    if case["ser_err"]:
        return ("unwrap", tuple(log + [("unwrap", c["uw_msg"], 0x2B, case["ser_err"], c["uw_vt"], c["uw_loc"])]))
    return ("ret", tuple(log + tail_rows(case, c, F + 0x18, variant)))


def model_eq(a, b, variant=None):
    if len(a) != len(b):
        return 0
    fold = (lambda x: x) if variant == "case_sensitive" else (lambda x: x | 0x20 if 0x41 <= x <= 0x5A else x)
    if variant == "alpha_range_wide":
        fold = lambda x: x | 0x20 if 0x40 <= x <= 0x5B else x
    return int(all(fold(x) == fold(y) for x, y in zip(a, b)))


def reconstruct(image, start, case, variant=None):
    if start == FULL:
        return model_full(case, full_consts(image), variant)
    return model_plain(case, plain_consts(image, start), variant)


# ---------------------------------------------------------------- cases

DURS = (None, (0, 0), (1, 0), (5, 999_999_999), (1 << 32, 500_000_000), ((1 << 53) + 1, 1),
        (1 << 63, 0x7FFF_FFFF), (3, 0xFFFF_FFFF), (U64, 0x8000_0000))
STAMPS = ((0, 0, 0), (0x7E6, 0x15180, 0x3B9A_C9FF), (0xFFFF_FFFF, 1, 2))
TAILS = [(d, t, o) for d in DURS for t in STAMPS for o in (0, 1)]
PATHS = (b"", b"/", b"a", b"/s/a", b"/dev/nul", b"/dev/nullx", b"/dev/nulL")
NORMS = (b"a.rmp", b"a.RMP", b"a.RmP", b"a.json", b".rmp", b"..", b"a.", b"rmp", b"a.rmp.bak", b"a.b.rmp",
         b"x.rm", b"x.rmpp", b"", b"/", b".", b"...", b"d/.rmp", b"a.rmp ")


def base_case(path, norm=None, **kw):
    case = {"kind": "full", "path": path, "norm": norm, "fmt_err": 0, "cap": 0x40, "len": 7, "oom": 0,
            "prep_err": 0, "write_err": 0, "dur": None, "ts": (0, 0, 0), "once": 0, "ser_err": 0}
    case.update(kw)
    return case


def routes(path, norm):
    """Every distinct downstream route of the full body for one (path, normalised path)."""
    ext = extension_of(norm) if norm is not None else None
    rmp = ext is not None and eq_ignore_ascii_case(ext, RMP_EXT)
    out = []
    if rmp:
        out.append(base_case(path, norm, fmt_err=1, cap=0))
        out.append(base_case(path, norm, fmt_err=1, cap=0x40))
        caps = (0, 0x40, NONE_CAP)
    else:
        out.append(base_case(path, norm, oom=1))
        out.append(base_case(path, norm, fmt_err=1))
        caps = (0, 0x40, NONE_CAP)
    for cap in caps:
        for prep_err in (0, 1):
            for write_err in (0, 1):
                for ln in ((0, 7) if rmp else (7,)):
                    out.append(base_case(path, norm, cap=cap, len=ln, prep_err=prep_err, write_err=write_err))
    return out


def full_cases():
    out, k = [], 0
    for tail in TAILS:
        out.append(base_case(b"/dev/null", None, dur=tail[0], ts=tail[1], once=tail[2]))
    for path in PATHS:
        for norm in (None,) + NORMS:
            for case in routes(path, norm):
                for j in range(5):
                    d, t, o = TAILS[(k * 5 + j) % len(TAILS)]
                    c = dict(case)
                    c.update(dur=d, ts=t, once=o)
                    out.append(c)
                k += 1
    return out


def plain_cases():
    out = []
    for path in (b"", b"a/b.rmp", b"x"):
        for tail in TAILS:
            out.append(dict(base_case(path, None, dur=tail[0], ts=tail[1], once=tail[2], ser_err=0), kind="plain"))
        for err in (0x7777, U64):
            out.append(dict(base_case(path, None, ser_err=err), kind="plain"))
    return out


def eq_cases():
    out = []
    words = [b"", b"rmp", b"RMP", b"rMp", b"rmq", b"rm", b"rmpp", b"json", b"JSON", b"a@z", b"A`Z", b"a[z", b"A{Z",
             b"@", b"`", b"[", b"{", b"Z", b"z", b"A", b"a", b"0123456789", b"abcdefghijklmno", b"ABCDEFGHIJKLMNO",
             b"ABCDEFGHIJKLMNP", b"\xc1\xe1", b"\xe1\xe1", b"mp", b"\x00", b"\x00\x00"]
    for a in words:
        for b in words:
            out.append((a, b))
    for n in range(0, 16):
        base = bytes((0x41 + i * 3) % 0x7F or 0x41 for i in range(n))
        out.append((base, base.lower()))
        out.append((base, base.upper()))
        for i in range(n):
            flipped = bytearray(base)
            flipped[i] ^= 0x20
            out.append((base, bytes(flipped)))
            off = bytearray(base)
            off[i] ^= 0x01
            out.append((base, bytes(off)))
    for la in (0, 1, 3, 15, 16, 40):
        for lb in (0, 2, 3, 17):
            if la != lb:
                out.append((b"a" * la, b"a" * lb))
    return out


FULL_VARIANTS = ("devnull_prefix", "no_devnull", "abs_always", "case_sensitive", "prefix_only", "first_dot",
                 "dot0_allowed", "dotdot_allowed", "oom_ignored", "cap_marker_ignored", "free_always",
                 "write_first", "unsigned_nanos", "no_nanos", "truncate", "once_always")
PLAIN_VARIANTS = ("unsigned_nanos", "no_nanos", "truncate", "once_always")
EQ_VARIANTS = ("case_sensitive", "alpha_range_wide")


def outcome(result):
    if result[0] not in ("ret", "unwrap", "oom"):
        return result[0]
    return result[0] + "/" + ",".join(row[0] for row in result[1])


def describe(case):
    if case["kind"] == "plain":
        return f"plain\t{case['path'].decode()}\tdur={case['dur']}\tser_err={case['ser_err']:#x}"
    return "\t".join(["full", case["path"].decode(), "norm=" + ("err" if case["norm"] is None else case["norm"].decode()),
                      f"fmt_err={case['fmt_err']}", f"cap={case['cap']:#x}", f"oom={case['oom']}",
                      f"prep_err={case['prep_err']}", f"write_err={case['write_err']}", f"dur={case['dur']}",
                      f"once={case['once']}"])


def flipped(image, off):
    data = bytearray(image.data)
    data[off] ^= 1
    mutant = copy.copy(image)
    mutant.data = bytes(data)
    mutant.cache = {}
    return mutant


def generate(out_dir):
    image = load_image()
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    groups = {FULL: full_cases(), PLAIN_A: plain_cases(), PLAIN_B: plain_cases()}
    summary = {"target_sha256": SHA256, "bodies": {}}
    total = mismatches = 0
    sample_lines = ["#\tbody\tkind\tpath\tdetail\toutcome\tverdict"]
    reached, kept = {}, {}
    for start, cases in groups.items():
        lo, hi, insns = body_insns(image, start)
        counts, digest, seen, picked_src = {}, hashlib.sha256(), set(), []
        first_seen = set()
        for i, case in enumerate(cases):
            got = run_body(image, start, case, seen)
            ok = got == reconstruct(image, start, case)
            mismatches += not ok
            total += 1
            key = outcome(got)
            counts[key] = counts.get(key, 0) + 1
            digest.update(key.encode() + b"\n")
            sig = (key, case["dur"], case["once"], case["norm"], case["path"][:1])
            if sig not in first_seen:
                first_seen.add(sig)
                picked_src.append((i, case, got))
        kept[start] = picked_src
        reached[start] = seen
        for i, case, got in picked_src[:160]:
            sample_lines.append(f"{i}\t{start:#x}\t" + describe(case) + "\t" + outcome(got) + "\tmatch")
        summary["bodies"][f"{start:#x}"] = {
            "fde": [f"{lo:#x}", f"{hi:#x}"], "instructions": len(insns), "cases": len(cases),
            "direct_callees": {k: f"{v:#x}" for k, v in sorted(DIRECT[start].items())},
            "slot_callees": {k: f"{image.slots[SLOTS[k]]:#x}" for k in USED_SLOTS[start]},
            "outcomes": len(counts), "outcome_counts": dict(sorted(counts.items())),
            "result_digest": digest.hexdigest(),
            "instructions_reached": sum(1 for insn in insns if insn.va in seen)}
    # the shared extension test, run for real
    eq_total = eq_bad = eq_true = 0
    eq_seen = set()
    for a, b in eq_cases():
        got = run_eq(image, a, b, eq_seen)
        eq_total += 1
        eq_bad += got != ("ret", model_eq(a, b))
        eq_true += got == ("ret", 1)
    total += eq_total
    mismatches += eq_bad
    lo, hi, insns = body_insns(image, 0x159FCA0)
    summary["eq_ignore_ascii_case"] = {"fde": [f"{lo:#x}", f"{hi:#x}"], "cases": eq_total, "equal_results": eq_true,
                                       "mismatches": eq_bad, "scalar_instructions_reached": len(eq_seen),
                                       "instructions": len(insns)}
    summary["twins_agree"] = (summary["bodies"][f"{PLAIN_A:#x}"]["result_digest"]
                              == summary["bodies"][f"{PLAIN_B:#x}"]["result_digest"])
    summary["cases"] = total
    summary["mismatches"] = mismatches
    controls = detected = 0
    variant_rows = {}
    for start, names in ((FULL, FULL_VARIANTS), (PLAIN_A, PLAIN_VARIANTS)):
        for name in names:
            caught, first = 0, None
            for i, case in enumerate(groups[start]):
                if reconstruct(image, start, case, name) != run_body(image, start, case):
                    caught += 1
                    first = i if first is None else first
                    if caught >= 3:
                        break
            variant_rows[f"{start:#x}/{name}"] = {"caught_cases": caught, "first_case": first}
            controls += 1
            detected += caught > 0
    for name in EQ_VARIANTS:
        caught = sum(1 for a, b in eq_cases() if model_eq(a, b, name) != run_eq(image, a, b)[1])
        variant_rows[f"0x159fca0/{name}"] = {"caught_cases": caught, "first_case": None}
        controls += 1
        detected += caught > 0
    summary["negative_controls"] = variant_rows
    mut_lines = ["body\tjcc_va\tfile_offset_flipped\tverdict\tfirst_killing_case"]
    killed = survived = unreached = 0
    for start in groups:
        picked = kept[start]
        for va, op_off in jcc_sites(image, start):
            mutant = flipped(image, op_off)
            killer = None
            for i, case, got in picked:
                if run_body(mutant, start, case) != got:
                    killer = i
                    break
            verdict = "killed" if killer is not None else "unreached" if va not in reached[start] else "survived"
            mut_lines.append(f"{start:#x}\t{va:#x}\t{op_off:#x}\t{verdict}\t{'-' if killer is None else killer}")
            killed += verdict == "killed"
            survived += verdict == "survived"
            unreached += verdict == "unreached"
    summary["mutants"] = {"killed": killed, "survived": survived, "unreached": unreached}
    controls += killed + survived
    detected += killed
    call_lines = ["body\tsite\tkind\ttarget\tnote"]
    for start in groups:
        for va, kind, target, note in call_rows(image, start):
            call_lines.append(f"{start:#x}\t{va:#x}\t{kind}\t{target:#x}\t{note}")
    consts = full_consts(image)
    summary["rodata"] = {
        "extension_literal": rodata_bytes(image, consts["rmp"], 3).decode(),
        "indent_literal_len2": rodata_bytes(image, consts["indent"], 2).decode(),
        "timestamp_format": rodata_bytes(image, consts["fmt"], 0x16).decode(),
        "message_prefix": rodata_bytes(image, consts["msg"], 21).decode(),
        "unwrap_text": rodata_bytes(image, consts["uw_msg"], 0x2B).decode(),
        "hex_message_length": 0x2B}
    measure = {"cases": total, "negative_controls": controls, "negative_detected": detected}
    files = {"cases.tsv": "\n".join(sample_lines) + "\n", "mutants.tsv": "\n".join(mut_lines) + "\n",
             "calls.tsv": "\n".join(call_lines) + "\n",
             "summary.json": json.dumps(summary, indent=1, sort_keys=True) + "\n",
             "measure.json": json.dumps(measure, indent=1, sort_keys=True) + "\n"}
    for name, text in files.items():
        (out_dir / name).write_text(text)
    summary["measure"] = measure
    return summary


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        s = generate(args.out)
    except Fail as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    print(json.dumps({"mismatches": s["mismatches"], "mutants": s["mutants"], "measure": s["measure"]}))
    good = (s["mismatches"] == 0 and s["mutants"]["survived"] == 0
            and s["measure"]["negative_controls"] == s["measure"]["negative_detected"])
    return 0 if good else 2


if __name__ == "__main__":
    sys.exit(main())
