"""Reconstruct the node #115 generic abci state save (state.rs) and its two file helpers.

Four bodies are covered. 0x50DD9D0 and 0x50DEB30 are the two instantiations of the generic "save a
value to a path" function: "/dev/null" is skipped, the output format is chosen from the extension of
the *normalised* path ("rmp" in any ASCII case -> MessagePack writer, everything else -> pretty JSON
with a two space indent), the parent directory is prepared, the bytes are written, and the buffer is
freed; every failure hands its error word back to the caller instead of unwrapping. 0x15020F0 is the
parent-directory preparation (0x1FF recursive create when the directory is missing) and 0x15024A0 is
the atomic writer (temporary sibling name, write, create the parent when missing, rename).
Each body's real instruction bytes run in the shared evaluator of tools/decimal_scaled_u64.py with
every callee replaced by a logging stub (the ASCII case-insensitive comparison 0x159FCA0 runs for
real); the ordered callee log and the returned word are compared with independently written Python
reconstructions. Every conditional jump is flipped and must be caught, and deliberately wrong
reconstructions are negative controls. The target is read, never executed. Every number in the
output comes from ELF bytes or from these runs.
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
RMP_EXT = b"rmp"

SAVE_A, SAVE_B, PREP, WRITE = 0x50DD9D0, 0x50DEB30, 0x15020F0, 0x15024A0
BODIES = (SAVE_A, SAVE_B, PREP, WRITE)
FRAME = {SAVE_A: -0xC8, SAVE_B: -0xC8, PREP: -0x88, WRITE: -0xD8}   # rsp after the prologue, from entry rsp
DIRECT = {
    SAVE_A: {"eq": 0x159FCA0, "ser_rmp": 0x5480950, "ser_json": 0x5482640, "err_a": 0x50DF4C0, "err_b": 0x50DF400},
    SAVE_B: {"eq": 0x159FCA0, "ser_rmp": 0x5481900, "ser_json": 0x5481690, "err_a": 0x50DF4C0, "err_b": 0x50DF400},
    PREP: {"err": 0x1500B90},
    WRITE: {"err1": 0x1500B90, "err2": 0x15026E0},
}
SLOTS = {  # role -> GOT slot (the relocated target is read from .rela.dyn)
    "norm": 0x64E0938, "prep": 0x64E0028, "write": 0x64E09E8, "malloc": 0x64DF480, "free": 0x64DF4A0,
    "oom": 0x64DF498, "parent": 0x64E09B0, "to_parent": 0x64DFCA8, "isdir": 0x64E0928, "mkdir": 0x64E0940,
    "tmpname": 0x64E0978, "fmt": 0x64DF6E8, "push": 0x64E09F0, "open_write": 0x64E09F8, "rename": 0x64E0A00,
}
USED_SLOTS = {
    SAVE_A: ("norm", "prep", "write", "malloc", "free", "oom"),
    SAVE_B: ("norm", "prep", "write", "malloc", "free", "oom"),
    PREP: ("norm", "parent", "to_parent", "isdir", "mkdir"),
    WRITE: ("norm", "parent", "to_parent", "isdir", "mkdir", "tmpname", "fmt", "push", "open_write", "rename", "free"),
}
OBJ, PATH_ADDR, NORM_ADDR, BUF, PAR_ADDR, TMP_ADDR, JOIN_ADDR, FMT_ADDR, DATA_ADDR = (
    cpu.INPUT + i * 0x1000 for i in range(9))
EQ_A, EQ_B = cpu.INPUT + 0x10000, cpu.INPUT + 0x11000
ARG4 = 0x5E5E_0004
SER_ERR_WORDS = (0x6000_AAAA, 0x6000_BBBB)
JSON_ERR = 0x6000_CCCC
ERR_A_RET, ERR_B_RET, ERR_RET, ERR1_RET, ERR2_RET = 0x6100_0001, 0x6100_0002, 0x6100_0003, 0x6100_0004, 0x6100_0005
PREP_ERRS = (0x6200_0001, 0x6200_0002, U64)
WRITE_ERRS = (0x6300_0001, 0x6300_0002, U64)
PAR_LEN, TMP_LEN, JOIN_LEN, FMT_LEN, DATA_LEN = 5, 9, 14, 11, 33
FMT_PIECES, FMT_FN = 0x44B7F0, 0x14FCB40


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


def eq_ignore_ascii_case(a, b):
    return len(a) == len(b) and all((x | 0x20 if 0x41 <= x <= 0x5A else x) == (y | 0x20 if 0x41 <= y <= 0x5A else y)
                                    for x, y in zip(a, b))


# ---------------------------------------------------------------- evaluator with stubs

class Machine(cpu.Machine):
    """Evaluator with logging callee stubs."""

    def __init__(self, image, case, start):
        super().__init__(image)
        self.case, self.start, self.log = case, start, []
        self.roles = roles_for(image, start)

    def bytes_at(self, at, n):
        return bytes(self.load(at + i, 1) for i in range(n))

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

    # -- shared by the save bodies
    def stub_eq(self, a):
        self.log.append(("eq", self.bytes_at(a[0], a[1]), a[2], a[3]))
        return {cpu.RAX: int(eq_ignore_ascii_case(self.bytes_at(a[0], a[1]), self.bytes_at(a[2], a[3])))}

    def stub_free(self, a):
        self.log.append(("free", a[0], a[1], a[2]))

    def stub_oom(self, a):
        self.log.append(("oom", a[0], a[1]))
        raise cpu.Done("oom", self.pc)

    def stub_malloc(self, a):
        self.log.append(("malloc", a[0]))
        return {cpu.RAX: 0 if self.case["oom"] else BUF + 0x400}

    def stub_norm(self, a):
        if self.start in (SAVE_A, SAVE_B):
            self.log.append(("norm", self.rel(a[0]), self.load(a[1], 8), self.load(a[1] + 8, 8),
                             self.load(a[1] + 0x10, 1), self.load(a[1] + 0x38, 2), self.load(a[1] + 0x3A, 1)))
            norm = self.case["norm"]
            if norm is None:
                self.store(a[0], 1, 5)
            else:
                self.store(a[0], 1, 9)
                self.store(a[0] + 8, 8, NORM_ADDR)
                self.store(a[0] + 16, 8, len(norm))
            return
        self.log.append(("norm", self.rel(a[0]), self.load(a[1], 8), self.load(a[1] + 8, 8),
                         self.load(a[1] + 0x10, 1), self.load(a[1] + 0x38, 2), self.load(a[1] + 0x3A, 1)))
        self.store(a[0], 1, self.case["tag"])

    def stub_ser_rmp(self, a):
        cfg = a[2]
        vec = self.load(cfg, 8)
        self.log.append(("ser_rmp", self.rel(a[0]), a[1], self.rel(vec), self.load(cfg + 8, 4), self.load(cfg + 12, 1),
                         self.load(vec, 8), self.load(vec + 8, 8), self.load(vec + 16, 8)))
        c = self.case
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
        vec = self.load(w, 8)
        self.log.append(("ser_json", a[0], self.rel(vec), self.load(w + 8, 8), self.load(w + 16, 8),
                         self.load(w + 24, 8), self.load(w + 32, 1), self.load(vec, 8), self.load(vec + 8, 8),
                         self.load(vec + 16, 8)))
        c = self.case
        if c["fmt_err"]:
            return {cpu.RAX: JSON_ERR}
        self.store(vec, 8, c["cap"])
        self.store(vec + 8, 8, BUF)
        self.store(vec + 16, 8, c["len"])
        return {cpu.RAX: 0}

    def stub_err_a(self, a):
        self.log.append(("err_a", self.rel(a[0]), self.load(a[0], 8), self.load(a[0] + 8, 8), a[1]))
        return {cpu.RAX: ERR_A_RET}

    def stub_err_b(self, a):
        self.log.append(("err_b", self.rel(a[0]), self.load(a[0], 8), self.load(a[0] + 8, 8), self.load(a[1], 8),
                         self.load(a[1] + 8, 8), self.load(a[1] + 16, 8)))
        return {cpu.RAX: ERR_B_RET}

    def stub_prep(self, a):
        self.log.append(("prep", a[0], a[1]))
        return {cpu.RAX: self.case["prep_err"]}

    def stub_write(self, a):
        self.log.append(("write", a[0], a[1], a[2], a[3], a[4]))
        return {cpu.RAX: self.case["write_err"]}

    # -- shared by the two file helpers
    def stub_parent(self, a):
        self.log.append(("parent", self.rel(a[0])))
        return {cpu.RAX: self.case["parent"]}

    def stub_to_parent(self, a):
        self.log.append(("to_parent", self.rel(a[0]), a[1]))
        self.store(a[0], 4, self.case["tp_kind"])
        self.store(a[0] + 8, 8, PAR_ADDR)
        self.store(a[0] + 16, 8, PAR_LEN)

    def stub_isdir(self, a):
        self.log.append(("isdir", a[0], a[1]))
        return {cpu.RAX: self.case["isdir"]}

    def stub_mkdir(self, a):
        self.log.append(("mkdir", self.rel(a[0]), self.load(a[0], 4), self.load(a[0] + 4, 1), a[1], a[2]))
        return {cpu.RAX: self.case["mkdir_err"]}

    def stub_err(self, a):
        self.log.append(("err", self.rel(a[0]), a[1]))
        return {cpu.RAX: ERR_RET}

    # -- the atomic writer only
    def stub_tmpname(self, a):
        self.log.append(("tmpname", self.rel(a[0])))
        self.store(a[0], 8, self.case["tmp_cap"])
        self.store(a[0] + 8, 8, TMP_ADDR)
        self.store(a[0] + 16, 8, TMP_LEN)

    def stub_fmt(self, a):
        self.log.append(("fmt", self.rel(a[0]), a[1], self.rel(self.load(a[2], 8)), self.load(a[2] + 8, 8)))
        self.store(a[0], 8, self.case["fmt_cap"])
        self.store(a[0] + 8, 8, FMT_ADDR)
        self.store(a[0] + 16, 8, FMT_LEN)

    def stub_push(self, a):
        self.log.append(("push", self.rel(a[0]), a[1], a[2]))
        self.store(a[0], 8, self.case["join_cap"])
        self.store(a[0] + 8, 8, JOIN_ADDR)
        self.store(a[0] + 16, 8, JOIN_LEN)

    def stub_open_write(self, a):
        self.log.append(("open_write", a[0], a[1], a[2], a[3]))
        return {cpu.RAX: self.case["open_err"]}

    def stub_err1(self, a):
        self.log.append(("err1", self.rel(a[0]), a[1]))
        return {cpu.RAX: ERR1_RET}

    def stub_err2(self, a):
        self.log.append(("err2", self.rel(a[0]), self.rel(a[1]), self.load(a[1], 8), self.load(a[1] + 8, 8), a[2]))
        return {cpu.RAX: ERR2_RET}

    def stub_rename(self, a):
        self.log.append(("rename", a[0], a[1], a[2], a[3]))
        return {cpu.RAX: self.case["rename_err"]}


# ---------------------------------------------------------------- running a body

def setup(m, case, start):
    for reg in range(16):
        m.set_reg(reg, 0x0BAD_0000 + reg * 0x100)
    path = case["path"]
    m.set_reg(cpu.RSP, ENTRY_SP)
    m.store(ENTRY_SP, 8, cpu.RETURN_MARK)
    if start == WRITE:
        m.set_reg(cpu.RDI, DATA_ADDR)
        m.set_reg(cpu.RSI, DATA_LEN)
        m.set_reg(cpu.RDX, PATH_ADDR)
        m.set_reg(cpu.RCX, len(path))
    elif start == PREP:
        m.set_reg(cpu.RDI, PATH_ADDR)
        m.set_reg(cpu.RSI, len(path))
    else:
        m.set_reg(cpu.RDI, OBJ)
        m.set_reg(cpu.RSI, PATH_ADDR)
        m.set_reg(cpu.RDX, len(path))
        m.set_reg(cpu.RCX, ARG4)
    for i, b in enumerate(path):
        m.store(PATH_ADDR + i, 1, b)
    if start in (SAVE_A, SAVE_B) and case["norm"] is not None:
        for i, b in enumerate(case["norm"]):
            m.store(NORM_ADDR + i, 1, b)


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
        if done.how not in ("ret", "oom"):
            return ("stop", done.how)
        kind = done.how
    except cpu.ToolError as err:
        return ("error", str(err))
    finally:
        if seen is not None:
            seen |= m.seen
    rax = m.get(cpu.RAX, 64) if kind == "ret" else None
    return (kind, tuple(m.log), rax)


def run_eq(image, a, b, seen=None):
    """Run the real 0x159FCA0 on two byte strings (lengths below 16 or unequal lengths)."""
    m = Machine(image, {}, SAVE_A)
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


def save_consts(image, start):
    L = rip_leas(image, start)
    return {"rmp": L[0], "indent": L[1]}


def request_row(start, off, path, variant=None):
    """The normaliser request: (pointer, length, tag 6, u16 0x0201, absolute flag)."""
    absf = 1 if path[:1] == b"/" else 0
    if variant == "abs_always":
        absf = 1
    return ("norm", ("sp", FRAME[start] + off), PATH_ADDR, len(path), 6, 0x201, absf)


def model_save(start, case, c, variant=None):
    F = FRAME[start]
    path, log = case["path"], []
    null = path == b"/dev/null"
    if variant == "devnull_prefix":
        null = path[:8] == b"/dev/nul"
    if variant == "no_devnull":
        null = False
    if null:
        return ("ret", (), 0)
    log.append(request_row(start, 0, path, variant))
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
    if use_rmp:
        log.append(("ser_rmp", ("sp", F + 0x38), OBJ, ("sp", F), 0x1000400, 0, 0, 1, 0))
        if case["fmt_err"]:
            if cap:
                log.append(("free", 1, cap, 0))
            log.append(("err_b", ("sp", F + 0x78), PATH_ADDR, len(path), NONE_CAP + 1, *SER_ERR_WORDS))
            return ("ret", tuple(log), ERR_B_RET)
    else:
        log.append(("malloc", 0x80))
        if case["oom"] and variant != "oom_ignored":
            log.append(("oom", 1, 0x80))
            return ("oom", tuple(log), None)
        log.append(("ser_json", OBJ, ("sp", F), c["indent"], 2, 0, 0, 0x80, BUF + 0x400, 0)[:10])
        if case["fmt_err"]:
            log.append(("free", BUF + 0x400, 0x80, 0))
            log.append(("err_a", ("sp", F + 0x78), PATH_ADDR, len(path), JSON_ERR))
            return ("ret", tuple(log), ERR_A_RET)
        if cap == NONE_CAP and variant != "cap_marker_ignored":
            log.append(("err_a", ("sp", F + 0x78), PATH_ADDR, len(path), BUF))
            return ("ret", tuple(log), ERR_A_RET)
    log.append(("prep", PATH_ADDR, len(path)))
    prep_err = case["prep_err"]
    if variant == "write_first":
        log.pop()
    free = [("free", ptr, cap, 0)] if (cap or variant == "free_always") else []
    if prep_err and variant != "write_after_prep_err":
        log.extend(free)
        return ("ret", tuple(log), prep_err)
    log.append(("write", ptr, ln, PATH_ADDR, len(path), ARG4))
    rax = case["write_err"]
    if variant == "write_result_dropped":
        rax = 0
    if variant == "write_after_prep_err" and prep_err:
        rax = prep_err
    log.extend(free)
    return ("ret", tuple(log), rax)


def parent_choice(case, tags=(7, 8, 9), variant=None):
    """True when the helper replaces the path by the parent handed back by the path library."""
    return case["tag"] in tags and case["parent"] != 0 and case["tp_kind"] != 1


def model_prep(case, variant=None):
    F = FRAME[PREP]
    path = case["path"]
    log = [("norm", ("sp", F + 0x40), PATH_ADDR, len(path), 6, 0x201, 1 if path[:1] == b"/" else 0)]
    ptr, ln = PATH_ADDR, len(path)
    tags = (7, 8, 9, 10) if variant == "tag_range_wide" else (7, 8, 9)
    if case["tag"] in tags:
        log.append(("parent", ("sp", F)))
        if case["parent"] != 0 or variant == "no_parent_skip":
            log.append(("to_parent", ("sp", F), case["parent"]))
            if (case["tp_kind"] == 1) == (variant == "parent_fallback_inverted"):
                ptr, ln = PAR_ADDR, PAR_LEN
    isdir = case["isdir"] & 0xFF
    if variant == "isdir_full_word":
        isdir = 1 if case["isdir"] else 0
    log.append(("isdir", ptr, ln))
    if isdir and variant != "always_mkdir":
        return ("ret", tuple(log), 0)
    mode = 0x1FF if variant != "mode_0o755" else 0x1ED
    log.append(("mkdir", ("sp", F + 0x40), mode, 1, ptr, ln))
    if case["mkdir_err"] == 0:
        return ("ret", tuple(log), 0)
    log.append(("err", ("sp", F), case["mkdir_err"]))
    return ("ret", tuple(log), ERR_RET)


def model_write(case, variant=None):
    F = FRAME[WRITE]
    path, n = case["path"], len(case["path"])
    log = [("tmpname", ("sp", F + 0x20)), ("fmt", ("sp", F + 0x70), FMT_PIECES, ("sp", F + 0x20), FMT_FN)]
    if case["tmp_cap"]:
        log.append(("free", TMP_ADDR, case["tmp_cap"], 0))
    log.append(("push", ("sp", F + 8), FMT_ADDR, FMT_LEN))
    if case["fmt_cap"]:
        log.append(("free", FMT_ADDR, case["fmt_cap"], 0))
    log.append(("open_write", JOIN_ADDR, JOIN_LEN, DATA_ADDR, DATA_LEN))
    cleanup = [("free", JOIN_ADDR, case["join_cap"], 0)] if case["join_cap"] else []
    if variant == "no_cleanup":
        cleanup = []
    if case["open_err"] and variant != "open_err_ignored":
        log.append(("err2", ("sp", F + 8), ("sp", F + 0x60), PATH_ADDR, n, case["open_err"]))
        return ("ret", tuple(log + cleanup), ERR2_RET)
    log.append(("norm", ("sp", F + 0x70), PATH_ADDR, n, 6, 0x201, 1 if path[:1] == b"/" else 0))
    ptr, ln = PATH_ADDR, n
    if case["tag"] in (7, 8, 9):
        log.append(("parent", ("sp", F + 0x20)))
        if case["parent"] != 0:
            log.append(("to_parent", ("sp", F + 0x20), case["parent"]))
            if case["tp_kind"] != 1:
                ptr, ln = PAR_ADDR, PAR_LEN
    log.append(("isdir", ptr, ln))
    if not case["isdir"] & 0xFF:
        mode = 0x1FF if variant != "mode_0o755" else 0x1ED
        log.append(("mkdir", ("sp", F + 0x70), mode, 1, ptr, ln))
        if case["mkdir_err"]:
            log.append(("err1", ("sp", F + 0x20), case["mkdir_err"]))
            return ("ret", tuple(log + cleanup), ERR1_RET)
    log.append(("rename", JOIN_ADDR, JOIN_LEN, PATH_ADDR, n))
    if variant == "rename_target_parent":
        log[-1] = ("rename", JOIN_ADDR, JOIN_LEN, ptr, ln)
    return ("ret", tuple(log + cleanup), case["rename_err"])


def model_eq(a, b, variant=None):
    if len(a) != len(b):
        return 0
    fold = (lambda x: x) if variant == "case_sensitive" else (lambda x: x | 0x20 if 0x41 <= x <= 0x5A else x)
    if variant == "alpha_range_wide":
        fold = lambda x: x | 0x20 if 0x40 <= x <= 0x5B else x
    return int(all(fold(x) == fold(y) for x, y in zip(a, b)))


def reconstruct(image, start, case, variant=None):
    if start in (SAVE_A, SAVE_B):
        return model_save(start, case, save_consts(image, start), variant)
    if start == PREP:
        return model_prep(case, variant)
    return model_write(case, variant)


# ---------------------------------------------------------------- cases

PATHS = (b"", b"/", b"a", b"/s/a", b"/dev/nul", b"/dev/nullx", b"/dev/nulL", b"/dev/null")
NORMS = (b"a.rmp", b"a.RMP", b"a.RmP", b"a.json", b".rmp", b"..", b"a.", b"rmp", b"a.rmp.bak", b"a.b.rmp",
         b"x.rm", b"x.rmpp", b"", b"/", b".", b"...", b"d/.rmp", b"a.rmp ")
FS_PATHS = (b"", b"/", b"a", b"/s/a.rmp", b"x/y/z")


def save_case(path, norm=None, **kw):
    case = {"kind": "save", "path": path, "norm": norm, "fmt_err": 0, "cap": 0x40, "len": 7, "oom": 0,
            "prep_err": 0, "write_err": 0}
    case.update(kw)
    return case


def routes(path, norm):
    """Every distinct downstream route of the save body for one (path, normalised path)."""
    ext = extension_of(norm) if norm is not None else None
    rmp = ext is not None and eq_ignore_ascii_case(ext, RMP_EXT)
    out = []
    if rmp:
        out.append(save_case(path, norm, fmt_err=1, cap=0))
        out.append(save_case(path, norm, fmt_err=1, cap=0x40))
    else:
        out.append(save_case(path, norm, oom=1))
        out.append(save_case(path, norm, fmt_err=1))
    for cap in (0, 0x40, NONE_CAP):
        for prep_err in (0, PREP_ERRS[0]):
            for write_err in (0, WRITE_ERRS[0]):
                for ln in ((0, 7) if rmp else (7,)):
                    out.append(save_case(path, norm, cap=cap, len=ln, prep_err=prep_err, write_err=write_err))
    return out


def save_cases():
    out, k = [], 0
    for path in PATHS:
        for norm in (None,) + NORMS:
            for case in routes(path, norm):
                for j in range(4):
                    c = dict(case)
                    if c["prep_err"]:
                        c["prep_err"] = PREP_ERRS[(k + j) % len(PREP_ERRS)]
                    if c["write_err"]:
                        c["write_err"] = WRITE_ERRS[(k + j) % len(WRITE_ERRS)]
                    out.append(c)
                k += 1
    return out


def fs_case(path, **kw):
    case = {"kind": "fs", "path": path, "tag": 9, "parent": 0, "tp_kind": 0, "isdir": 0, "mkdir_err": 0,
            "tmp_cap": 0, "fmt_cap": 0, "join_cap": 0, "open_err": 0, "rename_err": 0}
    case.update(kw)
    return case


TAGS = (0, 5, 6, 7, 8, 9, 10, 0xF9, 0xFF)


def prep_cases():
    out = []
    for path in FS_PATHS:
        for tag in TAGS:
            for parent in (0, 0x7000_0001):
                for tp_kind in (0, 1, 2):
                    for isdir in (0, 1, 0x100, 0x1FF):
                        for mkdir_err in (0, 0x6400_0001, U64):
                            out.append(fs_case(path, tag=tag, parent=parent, tp_kind=tp_kind, isdir=isdir,
                                               mkdir_err=mkdir_err))
    return out


def write_cases():
    out = []
    for path in FS_PATHS:
        for tag in TAGS:
            for parent in (0, 0x7000_0001):
                for tp_kind in (0, 1):
                    for isdir in (0, 1, 0x100):
                        for mkdir_err in (0, 0x6400_0001):
                            for open_err in (0, 0x6500_0001):
                                for rename_err in (0, 0x6600_0001):
                                    caps = (0, 0x20)
                                    k = len(out)
                                    out.append(fs_case(path, tag=tag, parent=parent, tp_kind=tp_kind, isdir=isdir,
                                                       mkdir_err=mkdir_err, open_err=open_err, rename_err=rename_err,
                                                       tmp_cap=caps[k % 2], fmt_cap=caps[(k // 2) % 2],
                                                       join_cap=caps[(k // 4) % 2]))
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


SAVE_VARIANTS = ("devnull_prefix", "no_devnull", "abs_always", "case_sensitive", "prefix_only", "first_dot",
                 "dot0_allowed", "dotdot_allowed", "oom_ignored", "cap_marker_ignored", "free_always",
                 "write_first", "write_after_prep_err", "write_result_dropped")
PREP_VARIANTS = ("tag_range_wide", "no_parent_skip", "parent_fallback_inverted", "isdir_full_word", "always_mkdir",
                 "mode_0o755")
WRITE_VARIANTS = ("no_cleanup", "open_err_ignored", "mode_0o755", "rename_target_parent")
EQ_VARIANTS = ("case_sensitive", "alpha_range_wide")
VARIANTS = {SAVE_A: SAVE_VARIANTS, SAVE_B: SAVE_VARIANTS, PREP: PREP_VARIANTS, WRITE: WRITE_VARIANTS}


def outcome(result):
    if result[0] not in ("ret", "oom"):
        return result[0]
    return result[0] + "/" + ",".join(row[0] for row in result[1])


def describe(case):
    if case["kind"] == "fs":
        return "\t".join(["fs", case["path"].decode(), f"tag={case['tag']}", f"parent={case['parent']:#x}",
                          f"tp_kind={case['tp_kind']}", f"isdir={case['isdir']:#x}", f"mkdir_err={case['mkdir_err']:#x}",
                          f"open_err={case['open_err']:#x}", f"rename_err={case['rename_err']:#x}",
                          f"caps={case['tmp_cap']:#x}/{case['fmt_cap']:#x}/{case['join_cap']:#x}"])
    return "\t".join(["save", case["path"].decode(), "norm=" + ("err" if case["norm"] is None else case["norm"].decode()),
                      f"fmt_err={case['fmt_err']}", f"cap={case['cap']:#x}", f"len={case['len']}", f"oom={case['oom']}",
                      f"prep_err={case['prep_err']:#x}", f"write_err={case['write_err']:#x}"])


def signature(case, key):
    if case["kind"] == "fs":
        return (key, case["tag"], case["parent"] != 0, case["tp_kind"], case["isdir"] & 0xFF, case["mkdir_err"] != 0,
                case["open_err"] != 0, case["rename_err"] != 0, case["tmp_cap"] != 0, case["fmt_cap"] != 0,
                case["join_cap"] != 0)
    return (key, case["norm"], case["path"][:1], case["prep_err"] != 0, case["write_err"] != 0, case["cap"], case["len"])


def flipped(image, off):
    data = bytearray(image.data)
    data[off] ^= 1
    mutant = copy.copy(image)
    mutant.data = bytes(data)
    mutant.cache = {}
    return mutant


def case_groups():
    return {SAVE_A: save_cases(), SAVE_B: save_cases(), PREP: prep_cases(), WRITE: write_cases()}


def generate(out_dir):
    image = load_image()
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    groups = case_groups()
    summary = {"target_sha256": SHA256, "bodies": {}}
    total = mismatches = 0
    sample_lines = ["#\tbody\tkind\tpath\tdetail\toutcome\tverdict"]
    reached, kept = {}, {}
    for start, cases in groups.items():
        lo, hi, insns = body_insns(image, start)
        counts, digest, seen, picked = {}, hashlib.sha256(), set(), []
        first_seen = set()
        for i, case in enumerate(cases):
            got = run_body(image, start, case, seen)
            ok = got == reconstruct(image, start, case)
            mismatches += not ok
            total += 1
            key = outcome(got)
            counts[key] = counts.get(key, 0) + 1
            digest.update(key.encode() + b"\n" + repr(got[-1]).encode() + b"\n")
            sig = signature(case, key)
            if sig not in first_seen:
                first_seen.add(sig)
                picked.append((i, case, got))
        kept[start] = picked
        reached[start] = seen
        for i, case, got in picked[:120]:
            sample_lines.append(f"{i}\t{start:#x}\t" + describe(case) + "\t" + outcome(got) + "\tmatch")
        summary["bodies"][f"{start:#x}"] = {
            "fde": [f"{lo:#x}", f"{hi:#x}"], "instructions": len(insns), "cases": len(cases),
            "direct_callees": {k: f"{v:#x}" for k, v in sorted(DIRECT[start].items())},
            "slot_callees": {k: f"{image.slots[SLOTS[k]]:#x}" for k in USED_SLOTS[start]},
            "outcomes": len(counts), "outcome_counts": dict(sorted(counts.items())),
            "result_digest": digest.hexdigest(),
            "instructions_reached": sum(1 for insn in insns if insn.va in seen)}
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
    summary["save_twins_agree"] = (summary["bodies"][f"{SAVE_A:#x}"]["result_digest"]
                                   == summary["bodies"][f"{SAVE_B:#x}"]["result_digest"])
    summary["cases"] = total
    summary["mismatches"] = mismatches
    controls = detected = 0
    variant_rows = {}
    for start, names in VARIANTS.items():
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
        for va, op_off in jcc_sites(image, start):
            mutant = flipped(image, op_off)
            killer = None
            for i, case, got in kept[start]:
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
    consts = save_consts(image, SAVE_A)
    summary["rodata"] = {
        "extension_literal": rodata_bytes(image, consts["rmp"], 3).decode(),
        "indent_literal_len2": rodata_bytes(image, consts["indent"], 2).decode(),
        "twin_literals_equal": save_consts(image, SAVE_B) == consts
        or rodata_bytes(image, save_consts(image, SAVE_B)["rmp"], 3) == RMP_EXT}
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
