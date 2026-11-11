#!/usr/bin/env python3
"""Node #115 state-export output router, rebuilt and checked against the code bytes.

Ten monomorphised copies (0x2e4 bytes each) of one generic routine write a
serialised state value to a path: ``/dev/null`` is skipped, a file whose
extension is ``rmp`` (ASCII case-insensitive) is written as MessagePack,
anything else as pretty JSON, and the result is handed to the parent-directory
check and the file writer.  ``route_model`` is the executable reconstruction.
Every case runs the real bytes of a copy in the repository's x86 evaluator
with each callee replaced by a recorded stub, and the call trace plus the
return value must equal the model's.

Usage: python3 tools/state_export_route115.py --out research/work-items/<dir>
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as base  # noqa: E402  (shared ELF image and x86 evaluator)

NODE_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
NODE_PATH = ROOT / "artifacts" / "node" / "115" / "hl-node"
WORK_DIR = "RE-009-state-export-route-115"
U64 = (1 << 64) - 1

COPIES = (0x422ed40, 0x422f030, 0x50dd6e0, 0x50dd9d0, 0x50de010,
          0x50deb30, 0x50dee20, 0x50df110, 0x26a4e10, 0x26a55a0)
COPY_SIZE = 0x2e4
PROLOGUE = bytes.fromhex("5541574156415541545348 81ec98000000".replace(" ", ""))
PUSH_BYTES = 6 * 8
FRAME = 0x98
ROLES = ("components", "ext_eq", "rmp_serialize", "alloc", "json_serialize", "parent_check",
         "file_write", "free_after_write", "free_json_err", "drop_json_err", "free_rmp_err",
         "drop_rmp_err", "alloc_error", "free_unwind", "resume_unwind")
SHARED_TARGETS = {"components": 0x5cab560, "ext_eq": 0x159fca0, "alloc": 0x6355830,
                  "parent_check": 0x15020f0, "file_write": 0x15024a0, "free_after_write": 0x635de30,
                  "free_json_err": 0x635de30, "free_rmp_err": 0x635de30, "alloc_error": 0x141e264,
                  "free_unwind": 0x635de30, "resume_unwind": 0x63f0a50}
DEVNULL = b"/dev/null"
RMP_OK_TAG = 0x8000000000000004
INT_MIN = 0x8000000000000000

OUT = 0x7200_0000     # first argument: the value to serialise
EXTRA = 0x7300_0000   # fifth write argument (the caller's Location)
NAME = 0x7400_0000    # buffer behind the component name the stub returns
VEC = 0x7500_0000     # buffers the serialiser stubs claim to have filled
STACK_TOP = base.STACK + 0x10000
FRAME_BASE = STACK_TOP - PUSH_BYTES - FRAME

NAMES = (b"state", b"state.rmp", b"state.RMP", b"a.Rmp", b".rmp", b"rmp", b"x.json", b"a.b.rmp",
         b"a.rmp.", b"f.", b"f..", b"..", b".", b"", b".hidden", b"a.rmpx", b"a.rm", b"a.rmp.bak",
         b"abc.rmP", b"..rmp", b"a..rmp", b"A.RMP", b"\xc4.rmp", b"a.\xd2mp", b"a.rm\xf0")
PREFIXES = (b"", b"/", b"./", b"../", b"a/", b"/a/b/", b"//")
CASES_PER_COPY = 2500
PROBE_CASES = 800
SAMPLE_ROWS = 70


class ToolError(Exception):
    pass


def fail(message):
    raise ToolError(message)


# ---------------------------------------------------------------- case inputs

def make_paths():
    paths = [p + n for p in PREFIXES for n in NAMES[:15]]
    paths += [DEVNULL, DEVNULL, b"", b"/", b"//", b"/dev/nul", b"/dev/nullx", b"/dev/NULL", b"dev/null", b"//dev/null",
              b"/dev/null/", b"x/dev/null", b"/dev/null.rmp", b"a/b.rmp"]
    for pos in range(9):
        for rep in (b"X", b"\x00", DEVNULL[pos:pos + 1].upper()):
            if rep != DEVNULL[pos:pos + 1]:
                paths.append(DEVNULL[:pos] + rep + DEVNULL[pos + 1:])
    return paths


def lcg(state):
    return (state * 6364136223846793005 + 1442695040888963407) & U64


class Rolls:
    def __init__(self, seed):
        self.state = lcg(seed * 2654435761 + 12345)

    def below(self, n):
        self.state = lcg(self.state)
        return (self.state >> 33) % n


def tail_segment(path):
    segments = [s for s in path.split(b"/") if s]
    return segments[-1] if segments else None


def make_rep(path, rolls):
    """Stub answers for one case, as plain data so model and evaluator share them."""
    kind = rolls.below(6)
    if kind == 0:
        comp = ("N", NAMES[rolls.below(len(NAMES))])
    elif kind == 1:
        comp = ("N", b"..")
    elif kind == 2:
        comp = ("X", (0, 3, 5, 6, 7, 8, 10)[rolls.below(7)])
    else:
        seg = tail_segment(path)
        comp = ("X", 7) if seg is None else ("X", 8) if seg == b".." else ("N", seg)
    pick = rolls.below(8)
    rmp = ("ok", (0, 0x40, 0x1000)[rolls.below(3)], VEC + 0x100, rolls.below(5000)) if pick < 5 else \
        ("err", (RMP_OK_TAG + 1, 3, 0x8000000000000000)[rolls.below(3)], 0x11 + rolls.below(9), 0x21,
         (0, 0x30)[rolls.below(2)], VEC + 0x200, 0x1111 + rolls.below(9))
    pick = rolls.below(10)
    if pick < 6:
        js = ("ok", (0x80, 0x400, 0x80, 0x400, 0, INT_MIN)[rolls.below(6)], VEC + 0x300, rolls.below(5000))
    else:
        js = ("err", 0xE000 + rolls.below(50), (0, 0x80)[rolls.below(2)], VEC + 0x400, 0x2222 + rolls.below(9))
    return {"comp": comp, "rmp": rmp, "alloc": 0 if rolls.below(14) == 0 else VEC + 0x500, "json": js,
            "chk": 0 if rolls.below(3) else 0x5000 + rolls.below(9), "write": 0x6000 + rolls.below(9),
            "drop": 0x7000 + rolls.below(9)}


# ---------------------------------------------------------------- the model

def sym_args(*items):
    return tuple(items)


def route_model(path, rep, mut=frozenset()):
    """Reconstruction of one copy: returns (call trace, return value, branch labels)."""
    tr, labels = [], []
    n = len(path)
    dev_len = 8 if "dev_len" in mut else 9
    dev_text = b"/dev/nulI" if "dev_text" in mut else DEVNULL
    if n == dev_len and path[:9] == dev_text[:9]:
        return tr, 0, ["devnull"]
    if "abs_any" in mut:
        absf = 1 if n else 0
    else:
        absf = 1 if n and path[0] == 0x2f else 0
    if "abs_flip" in mut:
        absf ^= 1
    tr.append(("components", "F+0x0", "F+0x38",
               ("P", n, 6, 1, 2, 0 if "abs_drop" in mut else absf)))
    tag, comp = rep["comp"]
    normal = 9 if tag == "N" else 8 if "tag_eight" in mut else rep["comp"][1]
    is_normal = (tag == "N") and "tag_eight" not in mut
    ext = None
    if is_normal:
        name = comp
        if len(name) == 2 and name == b".." and "dotdot_off" not in mut:
            labels.append("dotdot")
        else:
            idx = name.find(b".") if "first_dot" in mut else name.rfind(b".")
            if idx < 0:
                labels.append("noext")
            elif idx == 0 and "dot0_off" not in mut:
                labels.append("dot0")
            else:
                ext = name[idx + 1:]
                labels.append("ext")
    else:
        labels.append("comp_other")
    use_rmp = False
    if ext is not None:
        pat = b"rma" if "pat" in mut else b"rmp"
        tr.append(("ext_eq", ext, pat))
        same = (ext == pat) if "case_sensitive" in mut else (len(ext) == len(pat) and ext.lower() == pat.lower())
        use_rmp = same
        labels.append("ext_rmp" if same else "ext_other")
    if use_rmp:
        labels.append("rmp")
        init = (0, 0, 0) if "vec_init" in mut else (0, 1, 0)
        tr.append(("rmp_serialize", "F+0x38", "O", "F+0x88", init,
                   ("F+0x0", 0x1000401 if "cfg" in mut else 0x1000400, 0)))
        r = rep["rmp"]
        if r[0] == "ok":
            cap, vptr, vlen = r[1], r[2], r[3]
        else:
            labels.append("rmp_err")
            _, tagword, e1, e2, vcap, vptr, _ = r
            if vcap != 0:
                tr.append(("free_rmp_err", vptr, vcap, 0))
            tr.append(("drop_rmp_err", "F+0x78", "F+0x38", ("P", n), (tagword, e1, e2)))
            return tr, rep["drop"], labels
    else:
        labels.append("json")
        tr.append(("alloc", 0x100 if "alloc_size" in mut else 0x80))
        if rep["alloc"] == 0:
            tr.append(("alloc_error", 1, 0x80))
            return tr, "noreturn", labels + ["alloc_fail"]
        tr.append(("json_serialize", "O", "F+0x38", (0x80, rep["alloc"], 0),
                   ("F+0x0", b"\t" if "indent" in mut else b"  ", 2, 0, 0)))
        j = rep["json"]
        if j[0] == "err":
            labels.append("json_err")
            _, code, vcap, vptr, _ = j
            first = ("drop_json_err", "F+0x78", code, ("P", n))
            if vcap != 0:
                free = ("free_json_err", vptr, vcap, 0)
                tr.extend((first, free) if "err_order" in mut else (free, first))
            else:
                tr.append(first)
            return tr, rep["drop"], labels
        cap, vptr, vlen = j[1], j[2], j[3]
        if cap == INT_MIN and "jo_off" not in mut:
            labels.append("jo")
            tr.append(("drop_json_err", "F+0x78", vptr, ("P", n)))
            return tr, rep["drop"], labels
    tr.append(("parent_check", "P", n))
    rv = rep["chk"]
    if (rv == 0) != ("write_inv" in mut):
        labels.append("write")
        tr.append(("file_write", vptr, vlen, "P", n, "X"))
        rv = rep["write"]
    else:
        labels.append("chk_nonzero")
    if cap != 0 or "free_always" in mut:
        labels.append("free_after")
        tr.append(("free_after_write", vptr, cap, 0))
        if "rv_lost" in mut:
            rv = 0
    return tr, rv, labels


# ---------------------------------------------------------------- the evaluator side

class Binary:
    def __init__(self):
        raw = NODE_PATH.read_bytes()
        if hashlib.sha256(raw).hexdigest() != NODE_SHA256:
            fail("node #115 digest mismatch")
        self.data = bytearray(raw)
        self.image = base.Image(self.data)
        self.copy_info = {}

    def patch(self, va, new):
        off = va - self.image.text_va + self.image.text_off
        old = bytes(self.data[off:off + len(new)])
        self.data[off:off + len(new)] = new
        self.image.cache.clear()
        return old

    def text_bytes(self, va, size):
        off = va - self.image.text_va + self.image.text_off
        return bytes(self.data[off:off + size])

    def call_sites(self, start):
        """Direct and slot calls in the copy, in address order: (offset, kind, target)."""
        img = self.image
        lo, hi = img.fde_of(start)
        if lo != start:
            fail(f"{start:#x} is not an FDE start")
        found, va = [], lo
        while va < hi:
            insn = img.fetch(va)
            data = self.data
            if insn.key == 0xe8:
                found.append((va - lo, "direct", insn.target))
            elif data[insn.off:insn.off + 2] == b"\xff\x15":
                rel = struct.unpack_from("<i", data, insn.off + 2)[0]
                slot = va + 6 + rel
                if slot not in img.slots:
                    fail(f"call through unknown slot {slot:#x}")
                found.append((va - lo, "slot", img.slots[slot]))
            va += insn.size
        if hi - lo != COPY_SIZE:
            fail(f"copy {start:#x} has size {hi - lo:#x}")
        if self.text_bytes(start, len(PROLOGUE)) != PROLOGUE:
            fail(f"copy {start:#x} prologue differs")
        return found

    def inspect(self, start):
        if start not in self.copy_info:
            self.copy_info[start] = self.call_sites(start)
        return self.copy_info[start]


class StubMachine(base.Machine):
    """Runs real copy bytes; every call is answered from the case's stub data."""

    def __init__(self, binary, start, path, rep):
        super().__init__(binary.image)
        self.start, self.path, self.rep = start, path, rep
        self.trace = []
        self.sites = {off: ROLES[i] for i, (off, _, _) in enumerate(binary.inspect(start))}
        self.fb = FRAME_BASE
        self.ret = None

    def sym(self, v):
        if v == base.INPUT:
            return "P"
        if v == OUT:
            return "O"
        if v == EXTRA:
            return "X"
        if self.fb <= v < self.fb + FRAME:
            return f"F+{v - self.fb:#x}"
        return v

    def arg(self, reg):
        v = self.get(reg, 64)
        if v is None:
            fail(f"unknown argument register at {self.pc:#x}")
        return v

    def q(self, at):
        return self.load(at, 8)

    def raw(self, at, n):
        return bytes(self.load(at + i, 1) for i in range(n))

    def put_q(self, at, value):
        self.store(at, 8, value)

    def call(self, target, where):
        role = self.sites.get(where - self.start)
        if role is None:
            fail(f"call at {where:#x} is outside the call-site table")
        a = [self.get(r, 64) for r in (base.RDI, base.RSI, base.RDX, base.RCX, base.R8)]
        fb, rep = self.fb, self.rep
        rax = 0
        if role == "components":
            snap = (self.sym(self.q(fb + 0x38)), self.q(fb + 0x40), self.load(fb + 0x48, 1),
                    self.load(fb + 0x70, 1), self.load(fb + 0x71, 1), self.load(fb + 0x72, 1))
            self.trace.append((role, self.sym(a[0]), self.sym(a[1]), snap))
            tag, comp = rep["comp"]
            if tag == "N":
                for i, b in enumerate(comp):
                    self.mem[NAME + i] = b
                self.store(a[0], 1, 9)
                self.put_q(a[0] + 8, NAME)
                self.put_q(a[0] + 0x10, len(comp))
            else:
                self.store(a[0], 1, comp)
        elif role == "ext_eq":
            ext, pat = self.raw(a[0], a[1]), self.raw(a[2], a[3])
            self.trace.append((role, ext, pat))
            rax = 1 if len(ext) == len(pat) and ext.lower() == pat.lower() else 0
        elif role == "rmp_serialize":
            vec = (self.q(fb), self.q(fb + 8), self.q(fb + 0x10))
            cfg = (self.sym(self.q(fb + 0x88)), self.load(fb + 0x90, 4), self.load(fb + 0x94, 1))
            self.trace.append((role, self.sym(a[0]), self.sym(a[1]), self.sym(a[2]), vec, cfg))
            r = rep["rmp"]
            if r[0] == "ok":
                self.put_q(a[0], RMP_OK_TAG)
                self.put_q(fb, r[1])
                self.put_q(fb + 8, r[2])
                self.put_q(fb + 0x10, r[3])
            else:
                self.put_q(a[0], r[1])
                self.put_q(a[0] + 8, r[2])
                self.put_q(a[0] + 0x10, r[3])
                self.put_q(fb, r[4])
                self.put_q(fb + 8, r[5])
        elif role == "alloc":
            self.trace.append((role, a[0]))
            rax = rep["alloc"]
        elif role == "json_serialize":
            vec = (self.q(fb), self.q(fb + 8), self.q(fb + 0x10))
            ptr, ln = self.q(fb + 0x40), self.q(fb + 0x48)
            fmt = (self.sym(self.q(fb + 0x38)), self.raw(ptr, ln), ln, self.q(fb + 0x50), self.load(fb + 0x58, 1))
            self.trace.append((role, self.sym(a[0]), self.sym(a[1]), vec, fmt))
            j = rep["json"]
            if j[0] == "ok":
                self.put_q(fb, j[1])
                self.put_q(fb + 8, j[2])
                self.put_q(fb + 0x10, j[3])
                rax = 0
            else:
                self.put_q(fb, j[2])
                self.put_q(fb + 8, j[3])
                rax = j[1]
        elif role == "parent_check":
            self.trace.append((role, self.sym(a[0]), a[1]))
            rax = rep["chk"]
        elif role == "file_write":
            self.trace.append((role, a[0], a[1], self.sym(a[2]), a[3], self.sym(a[4])))
            rax = rep["write"]
        elif role in ("free_after_write", "free_json_err", "free_rmp_err"):
            self.trace.append((role, a[0], a[1], a[2]))
        elif role == "drop_json_err":
            self.trace.append((role, self.sym(a[0]), a[1], (self.sym(self.q(a[0])), self.q(a[0] + 8))))
            rax = rep["drop"]
        elif role == "drop_rmp_err":
            self.trace.append((role, self.sym(a[0]), self.sym(a[1]), (self.sym(self.q(a[0])), self.q(a[0] + 8)),
                               (self.q(a[1]), self.q(a[1] + 8), self.q(a[1] + 0x10))))
            rax = rep["drop"]
        elif role == "alloc_error":
            self.trace.append((role, a[0], a[1]))
            raise base.Done("noreturn", where)
        else:
            fail(f"unreachable callee {role} reached at {where:#x}")
        for reg in base.CALLER_SAVED:
            self.put(reg, 64, None)
        self.set_reg(base.RAX, rax)
        self.flags = [None, None, None, None]


def run_copy(binary, start, path, rep, extra=EXTRA):
    if len(path) > 0x400:
        raise ValueError("path longer than the case buffer")
    m = StubMachine(binary, start, path, rep)
    for i, b in enumerate(path):
        m.mem[base.INPUT + i] = b
    sp = STACK_TOP
    m.set_reg(base.RSP, sp)
    m.store(sp, 8, base.RETURN_MARK)
    m.set_reg(base.RDI, OUT)
    m.set_reg(base.RSI, base.INPUT)
    m.set_reg(base.RDX, len(path))
    m.set_reg(base.RCX, extra)
    try:
        m.run(start)
    except base.Done as done:
        if done.how == "noreturn":
            return m.trace, "noreturn"
        return m.trace, m.get(base.RAX, 64)
    raise ToolError("evaluator stopped without returning")


def normalise(trace):
    out = []
    for item in trace:
        out.append(tuple(item))
    return out


def model_trace(path, rep, mut=frozenset()):
    tr, rv, labels = route_model(path, rep, mut)
    return normalise(tr), rv, labels


def agree(binary, start, path, rep, mut=frozenset()):
    got_tr, got_rv = run_copy(binary, start, path, rep)
    want_tr, want_rv, labels = model_trace(path, rep, mut)
    return got_tr == normalise(want_tr) and got_rv == want_rv, labels, got_tr, got_rv


# ---------------------------------------------------------------- evidence

def case_stream(copy_index):
    paths = make_paths()
    rolls = Rolls(copy_index + 1)
    for i in range(CASES_PER_COPY):
        path = paths[(i * 7 + copy_index) % len(paths)] if i % 3 else paths[i % len(paths)]
        yield i, path, make_rep(path, rolls)


def trace_text(trace, rv):
    return repr((trace, rv))


def role_rows(binary):
    rows = ["copy\toffset\tindex\trole\tkind\ttarget"]
    for start in COPIES:
        for i, (off, kind, target) in enumerate(binary.inspect(start)):
            rows.append(f"{start:#x}\t{off:#x}\t{i}\t{ROLES[i]}\t{kind}\t{target:#x}")
    return rows


def check_role_table(binary):
    reference = None
    for start in COPIES:
        sites = binary.inspect(start)
        if len(sites) != len(ROLES):
            fail(f"copy {start:#x} has {len(sites)} call sites")
        offsets = [s[0] for s in sites]
        if reference is None:
            reference = offsets
        elif offsets != reference:
            fail(f"copy {start:#x} call-site offsets differ")
        for i, (_, _, target) in enumerate(sites):
            want = SHARED_TARGETS.get(ROLES[i])
            if want is not None and target != want:
                fail(f"copy {start:#x} role {ROLES[i]} targets {target:#x}")


def mutant_models():
    return ("dev_len", "dev_text", "abs_any", "abs_flip", "abs_drop", "tag_eight", "dotdot_off", "first_dot",
            "dot0_off", "pat", "case_sensitive", "vec_init", "cfg", "alloc_size", "indent", "err_order",
            "jo_off", "write_inv", "free_always", "rv_lost")


def find_unique(binary, start, pattern):
    blob = binary.text_bytes(start, COPY_SIZE)
    if blob.count(pattern) != 1:
        fail(f"pattern {pattern.hex()} occurs {blob.count(pattern)} times in {start:#x}")
    return start + blob.index(pattern)


def build_patch_set(binary, start):
    """(name, address, replacement) triples found by byte pattern inside one copy."""
    patches = []
    blob = binary.text_bytes(start, COPY_SIZE)

    def at(pattern, delta, new, name):
        if blob.count(pattern) != 1:
            fail(f"patch {name}: pattern count {blob.count(pattern)}")
        patches.append((name, start + blob.index(pattern) + delta, bytes([new])))

    at(bytes.fromhex("4883fa09"), 3, 0x08, "length_nine")
    at(bytes.fromhex("48b82f6465762f6e756c"), 2, 0x2e, "devnull_first_byte")
    at(bytes.fromhex("41803f2f"), 3, 0x2e, "root_slash")
    at(bytes.fromhex("6681392e2e"), 3, 0x2d, "dotdot_word")
    at(bytes.fromhex("8079fe2e"), 3, 0x2d, "dot_scan")
    at(bytes.fromhex("b903000000"), 1, 0x04, "ext_len")
    at(bytes.fromhex("c784249000000000040001"), 7, 0x02, "rmp_config")
    at(bytes.fromhex("bf80000000"), 1, 0x81, "alloc_size")
    at(bytes.fromhex("48f7d8"), 2, 0xd0, "negate")
    at(bytes.fromhex("488d7424384c89ef"), 4, 0x39, "components_slot")
    at(bytes.fromhex("4883c804"), 3, 0x05, "ok_tag")
    at(bytes.fromhex("0f94c0"), 1, 0x95, "root_sense")
    at(bytes.fromhex("48c744240801000000"), 5, 0x02, "vec_dangling")
    return patches


def run_stream(binary, emit_rows=None):
    """Run every case; returns summary counters and the probe traces of the first copy."""
    stats = {"cases": 0, "labels": {}, "copy_labels": {}, "roles": {}, "per_copy": {}, "returns": {}}
    probes = []
    digest = hashlib.sha256()
    for ci, start in enumerate(COPIES):
        copy_digest = hashlib.sha256()
        ok = 0
        for i, path, rep in case_stream(ci):
            good, labels, trace, rv = agree(binary, start, path, rep)
            if not good:
                fail(f"copy {start:#x} case {i} path {path!r}: model and bytes disagree")
            ok += 1
            text = trace_text(trace, rv)
            copy_digest.update(text.encode() + b"\n")
            for label in labels:
                stats["labels"][label] = stats["labels"].get(label, 0) + 1
                by_copy = stats["copy_labels"].setdefault(start, {})
                by_copy[label] = by_copy.get(label, 0) + 1
            for item in trace:
                stats["roles"][item[0]] = stats["roles"].get(item[0], 0) + 1
            if ci == 3 and i < PROBE_CASES:
                probes.append((path, rep, trace, rv))
            if emit_rows is not None and i < SAMPLE_ROWS:
                emit_rows.append(f"{start:#x}\t{i}\t{path.hex()}\t{rv if isinstance(rv, str) else hex(rv)}\t"
                                 f"{','.join(item[0] for item in trace) or '-'}\t{','.join(labels)}")
        stats["cases"] += ok
        stats["per_copy"][start] = (ok, copy_digest.hexdigest())
        digest.update(copy_digest.digest())
    stats["digest"] = digest.hexdigest()
    return stats, probes


def mutant_detected(probes, mut):
    for path, rep, trace, rv in probes:
        want_tr, want_rv, _ = model_trace(path, rep, frozenset((mut,)))
        if want_tr != normalise(trace) or want_rv != rv:
            return True
    return False


def patch_detected(binary, start, patch):
    name, va, new = patch
    old = binary.patch(va, new)
    try:
        for i, path, rep in case_stream(3):
            if i >= PROBE_CASES:
                break
            try:
                good = agree(binary, start, path, rep)[0]
            except Exception:
                return True
            if not good:
                return True
        return False
    finally:
        binary.patch(va, old)


def environment_controls(binary):
    results = []
    try:
        binary.call_sites(COPIES[3] + 1)
        results.append(("not_fde_start", False))
    except ToolError:
        results.append(("not_fde_start", True))
    try:
        binary.call_sites(COPIES[3] - 0x10)
        results.append(("neighbour_function", False))
    except ToolError:
        results.append(("neighbour_function", True))
    try:
        run_copy(binary, COPIES[3], b"x" * 0x401, make_rep(b"x", Rolls(1)))
        results.append(("oversize_path", False))
    except ValueError:
        results.append(("oversize_path", True))
    saved = bytes(binary.text_bytes(COPIES[3], len(PROLOGUE)))
    old = binary.patch(COPIES[3], b"\x90")
    try:
        binary.copy_info.pop(COPIES[3], None)
        binary.call_sites(COPIES[3])
        results.append(("prologue_damage", False))
    except ToolError:
        results.append(("prologue_damage", True))
    finally:
        binary.patch(COPIES[3], old)
        binary.copy_info.pop(COPIES[3], None)
    assert saved == binary.text_bytes(COPIES[3], len(PROLOGUE))
    return results


def generate(out_dir):
    binary = Binary()
    check_role_table(binary)
    rows = ["copy\tcase\tpath_hex\treturn\tcalls\tlabels"]
    stats, probes = run_stream(binary, rows)
    controls = []
    for mut in mutant_models():
        controls.append((f"model:{mut}", mutant_detected(probes, mut)))
    for patch in build_patch_set(binary, COPIES[3]):
        controls.append((f"bytes:{patch[0]}", patch_detected(binary, COPIES[3], patch)))
    controls.extend((f"input:{n}", d) for n, d in environment_controls(binary))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    def write(name, lines):
        (out / name).write_text("\n".join(lines) + "\n")

    write("roles.tsv", role_rows(binary))
    write("sample_cases.tsv", rows)
    write("coverage.tsv", ["item\tcount"] + [f"label:{k}\t{v}" for k, v in sorted(stats["labels"].items())]
          + [f"role:{k}\t{v}" for k, v in sorted(stats["roles"].items())]
          + [f"copy:{k:#x}\t{v[0]}\t{v[1]}" for k, v in stats["per_copy"].items()]
          + [f"copy_label:{k:#x}:{lab}\t{n}" for k, labs in stats["copy_labels"].items()
             for lab, n in sorted(labs.items())]
          + [f"stream_digest\t{stats['digest']}"])
    write("controls.tsv", ["control\tdetected"] + [f"{n}\t{int(d)}" for n, d in controls])
    detected = sum(1 for _, d in controls if d)
    measure = {"cases": stats["cases"], "negative_controls": len(controls), "negative_detected": detected,
               "copies": len(COPIES), "cases_per_copy": CASES_PER_COPY, "probe_cases": PROBE_CASES}
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    return measure


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    print(json.dumps(generate(args.out), sort_keys=True))


if __name__ == "__main__":
    main()
