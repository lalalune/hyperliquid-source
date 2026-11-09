"""Node #115 state-export output routers 0x422f320, 0x50ddcc0 and 0x4773b90.

Each body takes (value, path, path_len, extra) and writes the serialized value
to the path: "/dev/null" is a no-op, a last path component whose extension is
"rmp" (ASCII case-insensitive) selects the rmp serializer, anything else the
pretty JSON writer; the parent-directory check and the atomic file writer are
reached through two GOT slots.  The three bodies differ in the value they carry
and in how they drive the serializers:

  0x422f320  value behind a pointer, rmp via one call, JSON via a slice-returning
             writer that is copied into a 0x80-byte buffer (grown when longer)
  0x50ddcc0  one-byte enum with four variants, rmp = variant-name call picked by
             a jump table, JSON via a serializer struct
  0x4773b90  value behind a pointer, rmp = header + optional field + body calls,
             JSON via a serializer struct

The tool runs the real code bytes of each body in the shared concrete evaluator
(tools/decimal_scaled_u64.py) with every callee replaced by a recording stub, and
compares the recorded call log and return value with an independent Python model.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as cpu  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

PATH, NAME, VALUE, CTX, HEAP = cpu.INPUT, cpu.INPUT + 0x800, cpu.INPUT + 0x1000, cpu.INPUT + 0x1100, cpu.INPUT + 0x10000
MEMCPY = 0x7fff0001
DOT_NULL = b"/dev/null"
U64 = cpu.U64
NEG = 1 << 63

# call targets (resolved GOT slots / direct calls) shared by all three bodies
COMP, EQ, ALLOC, DEALLOC, ALLOC_ERR, PARENT, WRITE, UNWIND = (
    0x5cab560, 0x159fca0, 0x6355830, 0x635de30, 0x141e264, 0x15020f0, 0x15024a0, 0x63f0a50)
EXT_LIT = 0x4659e5
BODIES = {
    "A": dict(entry=0x422f320, size=834, rmp=0x3d517e0, json=0x4301950, grow=0x43bd910, conv=0x422f740, pan=0x422f670),
    "B": dict(entry=0x50ddcc0, size=840, unit=0x57cf860, json=0x56183d0, conv=0x50df400, pan=0x50df4c0),
    "C": dict(entry=0x4773b90, size=862, hdr=0x477be60, field=0x4778560, body=0x47789c0, json=0x4783f20,
              conv=0x4773fc0, pan=0x4773ef0),
}
SLOT_MEMCPY = 0x64df508


class ToolError(Exception):
    pass


def load_image():
    data = TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ToolError("node #115 binary digest mismatch")
    image = cpu.Image(data)
    image.slots.setdefault(SLOT_MEMCPY, MEMCPY)
    return image


# --------------------------------------------------------------------------- environment shared by model and stubs
class Env:
    """Recording callee environment; the case decides what every callee returns."""

    def __init__(self, case):
        self.case = case
        self.log = []
        self.next_heap = HEAP
        self.mem = {}
        self.blobs = {}
        self.queue = list(case.get("rmp_calls", ()))
        self.put(PATH, case["path"])
        self.put(NAME, case["name"])
        self.put(VALUE, bytes([case["tag"]]) + b"\0" * 7)
        self.put(CTX, struct.pack("<Q", VALUE))

    def put(self, at, data):
        for i, b in enumerate(data):
            self.mem[at + i] = b

    def read(self, at, n):
        return bytes(self.mem.get(at + i, 0) for i in range(n))

    def alloc(self, data):
        ptr = self.next_heap
        self.next_heap += (len(data) + 0x20) & ~0xf
        self.put(ptr, data)
        self.blobs[ptr] = data
        return ptr

    def comp(self, ptr, n, absolute):
        self.log.append(("comp", ptr, n, absolute))
        return self.case["ctag"], NAME, len(self.case["name"])

    def eq(self, ptr, n):
        self.log.append(("eq", ptr, n))
        return self.read(ptr, n).lower() == b"rmp"

    def rmp(self, name):
        """One rmp-side callee: (rax, rdx, vec) where vec = (cap, ptr, len)."""
        self.log.append(("rmp", name))
        c = self.case
        rax, rdx = self.queue.pop(0)
        if rax == 2 and not self.queue:
            return rax, rdx, (c["cap"], self.alloc(c["data"]), len(c["data"]))
        if rax != 2 and c["precap"]:
            return rax, rdx, (c["precap"], self.alloc(b"p" * 5), 3)
        return rax, rdx, (0, 1, 0)

    def jsonw(self, name):
        """JSON writer: (error pointer or 0, result pointer, bytes)."""
        self.log.append(("json", name))
        c = self.case
        if c["jerr"]:
            return c["jerr"], None, None
        return 0, self.alloc(c["data"]), c["data"]

    def alloc_buf(self):
        self.log.append(("alloc", 0x80))
        if not self.case["alloc_ok"]:
            return 0
        return self.alloc(b"\0" * 0x80)

    def grow(self, oldcap, n):
        self.log.append(("grow", oldcap, n))
        cap = self.case["gcap"] or max(n, 0x100)
        return cap, self.alloc(b"\0" * max(n, 0x100))

    def memcpy(self, dst, src, n):
        self.log.append(("memcpy", dst, n))

    def dealloc(self, ptr, cap):
        self.log.append(("dealloc", ptr, cap))

    def errs(self, ptr, n, a, b, c):
        self.log.append(("errs", ptr, n, a, b, c))
        return self.case["conv_rc"]

    def errp(self, ptr, n, e):
        self.log.append(("errp", ptr, n, e))
        return self.case["conv_rc"]

    def parent(self, ptr, n):
        self.log.append(("parent", ptr, n))
        return self.case["parent_rc"]

    def write(self, buf, n, data, path, plen, extra):
        self.log.append(("write", buf, n, data, path, plen, extra))
        return self.case["write_rc"]


# --------------------------------------------------------------------------- python models (control flow only)
def selector(env, plen, mut=None):
    """Shared front: None for /dev/null, else True when the last component carries the rmp extension."""
    if plen == 9 and env.read(PATH, 9) == DOT_NULL and mut != "no-null":
        return None
    if mut == "null-prefix" and plen >= 9 and env.read(PATH, 9) == DOT_NULL:
        return None
    absolute = int(plen != 0 and env.read(PATH, 1) == b"/")
    if mut == "abs-flag":
        absolute ^= 1
    tag, ptr, n = env.comp(PATH, plen, absolute)
    if tag != 9 and mut != "ignore-tag":
        return False
    name = env.read(ptr, n)
    if n == 2 and name == b".." and mut != "dotdot":
        return False
    i = n
    while i != 0:
        i -= 1
        if name[i] == 0x2e:
            break
    else:
        return False
    if i == 0 and mut != "dot-zero":
        return False
    if mut == "ext-off":
        return env.eq(ptr + i, n - i)
    got = env.eq(ptr + i + 1, n - i - 1)
    if mut == "case-sensitive":
        return got and env.read(ptr + i + 1, n - i - 1) == b"rmp"
    return got


def finish(env, ptr, n, cap, plen, extra, mut):
    """Parent check, atomic write, buffer release (identical tail of all three bodies)."""
    rc = env.parent(PATH, plen)
    if mut == "write-first":
        env.write(ptr, n, env.read(ptr, n), PATH, plen, extra)
    if rc == 0 or mut == "write-despite-parent":
        rc = env.write(ptr, n, env.read(ptr, n), PATH, plen, extra)
    if (cap != 0) != (mut == "free-always" and cap == 0) and mut != "leak":
        env.dealloc(ptr, cap)
    return rc


def model(body, env, mut=None):
    plen, extra = len(env.case["path"]), env.case["extra"]
    use = selector(env, plen, mut)
    if use is None:
        return 0
    if mut == "always-json":
        use = False
    if mut == "always-rmp":
        use = True
    return {"A": model_a, "B": model_b, "C": model_c}[body](env, use, plen, extra, mut)


def rmp_failed(env, plen, vec, rax, rdx, mut=None):
    if vec[0] and mut != "keep-vec":
        env.dealloc(vec[1], vec[0])
    return env.errs(PATH, plen, NEG, rax, rdx)


def model_a(env, rmp, plen, extra, mut):
    if rmp:
        rax, rdx, vec = env.rmp("A")
        if rax != 2:
            return rmp_failed(env, plen, vec, rax, rdx, mut)
        return finish(env, vec[1], vec[2], vec[0], plen, extra, mut)
    buf = env.alloc_buf()
    if not buf:
        return "alloc-error"
    _, src, data = env.jsonw("A")
    n = len(data)
    if n >= (0x80 if mut == "grow-early" else 0x81):
        cap, ptr = env.grow(0x80, n)
        env.memcpy(ptr, src, n)
        env.put(ptr, data)
        if cap == NEG and mut != "no-overflow":
            return env.errp(PATH, plen, ptr)
    else:
        cap, ptr = 0x80, buf
        if n:
            env.memcpy(ptr, src, n)
            env.put(ptr, data)
    return finish(env, ptr, n, cap, plen, extra, mut)


def model_b(env, rmp, plen, extra, mut):
    if not rmp:
        return json_tail(env, "B", plen, extra, mut)
    if env.case["tag"] not in range(4):
        raise ToolError("enum tag outside the four-entry jump table")
    env.log.append(("unit", UNIT_NAMES[(env.case["tag"] + (1 if mut == "unit-shift" else 0)) % 4]))
    rax, rdx, vec = env.rmp("B")
    if rax != 2:
        return rmp_failed(env, plen, vec, rax, rdx, mut)
    return finish(env, vec[1], vec[2], vec[0], plen, extra, mut)


def json_tail(env, body, plen, extra, mut):
    buf = env.alloc_buf()
    if not buf:
        return "alloc-error"
    err, ptr, data = env.jsonw(body)
    c = env.case
    if err:
        if c["jecap"]:
            env.dealloc(buf, c["jecap"])
        return env.errp(PATH, plen, err)
    if c["jcap"] == NEG and mut != "no-overflow":
        return env.errp(PATH, plen, ptr)
    return finish(env, ptr, len(data), c["jcap"], plen, extra, mut)


def model_c(env, rmp, plen, extra, mut):
    if not rmp:
        return json_tail(env, "C", plen, extra, mut)
    for step in ("hdr", "field", "body"):
        if step == "field" and (not env.case["flag"]) != (mut == "field-always"):
            continue
        rax, rdx, vec = env.rmp(step)
        if rax != 2:
            return rmp_failed(env, plen, vec, rax, rdx, mut)
    return finish(env, vec[1], vec[2], vec[0], plen, extra, mut)


UNIT_NAMES = None


def unit_names():
    return UNIT_NAMES


def read_unit_names(image):
    """Variant-name (address, length) per jump-table index, read from the table and target bytes."""
    off = image.file_offset(0x91a3e4)
    names = []
    for k in range(4):
        target = struct.unpack_from("<i", image.data, off + 4 * k)[0] + 0x91a3e4
        t = image.file_offset(target)
        raw = image.data[t:t + 18]
        if raw[:3] != b"\x48\x8d\x35" or raw[7:12] != b"\x48\x8d\x7c\x24\x40" or raw[12] != 0xba:
            raise ToolError("variant name site pattern changed")
        addr = target + 7 + struct.unpack_from("<i", raw, 3)[0]
        n = struct.unpack_from("<I", raw, 13)[0]
        names.append((addr, n))
    return names


# --------------------------------------------------------------------------- machine side
class Halt(Exception):
    def __init__(self, how):
        super().__init__(how)
        self.how = how


class Rig(cpu.Machine):
    def __init__(self, image, env, body):
        super().__init__(image)
        self.env, self.body, self.t = env, body, BODIES[body]
        self.mem.update(env.mem)

    def a(self, reg):
        v = self.get(reg, 64)
        if v is None:
            raise ToolError("unknown argument register")
        return v

    def ret(self, rax=None, rdx=None):
        for r in cpu.CALLER_SAVED:
            self.known[r] = 0
        self.flags = [None, None, None, None]
        if rax is not None:
            self.set_reg(cpu.RAX, rax)
        if rdx is not None:
            self.set_reg(cpu.RDX, rdx)

    def w8(self, at, v):
        self.store(at, 8, v)

    def blob(self, ptr):
        for i, b in enumerate(self.env.blobs[ptr]):
            self.mem[ptr + i] = b

    def reader_flags(self, ser):
        if self.load(ser + 8, 4) != 0x1000400 or self.load(ser + 0xc, 1) != 0:
            raise ToolError("rmp reader flags changed")

    def write_vec(self, at, vec):
        for k, v in enumerate(vec):
            self.w8(at + 8 * k, v)
        if vec[1] in self.env.blobs:
            self.blob(vec[1])

    def bytes_at(self, at, n):
        return bytes(self.mem.get(at + i, 0) for i in range(n))

    def call(self, target, where):
        e, t, a = self.env, self.t, self.a
        if target == COMP:
            iterp = a(cpu.RSI)
            tag, nptr, nlen = e.comp(self.load(iterp, 8), self.load(iterp + 8, 8), self.load(iterp + 0x3a, 1))
            out = a(cpu.RDI)
            self.store(out, 1, tag)
            self.w8(out + 8, nptr)
            self.w8(out + 0x10, nlen)
            self.ret()
        elif target == EQ:
            if (a(cpu.RDX), a(cpu.RCX)) != (EXT_LIT, 3):
                raise ToolError("extension literal changed")
            self.ret(int(e.eq(a(cpu.RDI), a(cpu.RSI))))
        elif target == ALLOC:
            if a(cpu.RDI) != 0x80:
                raise ToolError("unexpected buffer size")
            ptr = e.alloc_buf()
            if ptr:
                self.blob(ptr)
            self.ret(ptr)
        elif target == DEALLOC:
            if a(cpu.RDX) != 0:
                raise ToolError("unexpected alignment")
            e.dealloc(a(cpu.RDI), a(cpu.RSI))
            self.ret()
        elif target == ALLOC_ERR:
            raise Halt("alloc-error")
        elif target == PARENT:
            self.ret(e.parent(a(cpu.RDI), a(cpu.RSI)))
        elif target == WRITE:
            buf, n = a(cpu.RDI), a(cpu.RSI)
            self.ret(e.write(buf, n, self.bytes_at(buf, n), a(cpu.RDX), a(cpu.RCX), a(cpu.R8)))
        elif target == MEMCPY:
            dst, src, n = a(cpu.RDI), a(cpu.RSI), a(cpu.RDX)
            e.memcpy(dst, src, n)
            for i in range(n):
                self.mem[dst + i] = self.mem.get(src + i, 0)
            self.ret()
        elif self.body == "A" and target == t["rmp"]:
            res, ser, val = a(cpu.RDI), a(cpu.RSI), a(cpu.RDX)
            if val != VALUE:
                raise ToolError("value pointer not forwarded")
            self.reader_flags(ser)
            rax, rdx, vec = e.rmp("A")
            self.write_vec(self.load(ser, 8), vec)
            self.w8(res, rax)
            self.w8(res + 8, rdx)
            self.ret()
        elif self.body == "A" and target == t["json"]:
            if a(cpu.RDI) != VALUE:
                raise ToolError("value pointer not forwarded")
            _, ptr, data = e.jsonw("A")
            self.blob(ptr)
            self.ret(ptr, len(data))
        elif self.body == "A" and target == t["grow"]:
            buf, n = a(cpu.RDI), a(cpu.RDX)
            if (a(cpu.RSI), a(cpu.RCX), a(cpu.R8)) != (0, 1, 1):
                raise ToolError("grow arguments changed")
            cap, ptr = e.grow(self.load(buf, 8), n)
            self.w8(buf, cap)
            self.w8(buf + 8, ptr)
            self.w8(buf + 0x10, 0)
            self.blob(ptr)
            self.ret()
        elif self.body == "B" and target == t["unit"]:
            ser, name, n = a(cpu.RDI), a(cpu.RSI), a(cpu.RDX)
            self.reader_flags(ser)
            e.log.append(("unit", (name, n)))
            rax, rdx, vec = e.rmp("B")
            self.write_vec(self.load(ser, 8), vec)
            self.ret(rax, rdx)
        elif self.body == "C" and target in (t["hdr"], t["field"], t["body"]):
            kind = {t["hdr"]: "hdr", t["field"]: "field", t["body"]: "body"}[target]
            if kind == "field":
                ser = a(cpu.RDI)
                if (a(cpu.RSI), a(cpu.RDX)) != (0x7e1c4f, 0x1b):
                    raise ToolError("field literal changed")
                rax, rdx, vec = e.rmp(kind)
                self.write_vec(self.load(ser, 8), vec)
                self.ret(rax, rdx)
                return
            res, ser = a(cpu.RDI), a(cpu.RSI)
            if kind == "hdr":
                self.reader_flags(ser)
                if a(cpu.RDX) != 1:
                    raise ToolError("header argument changed")
                self.store(ser + 0xb, 1, e.case["flag"])
            elif a(cpu.RDX) != VALUE:
                raise ToolError("value pointer not forwarded")
            rax, rdx, vec = e.rmp(kind)
            self.write_vec(self.load(ser, 8), vec)
            self.w8(res, rax)
            self.w8(res + 8, rdx)
            self.ret()
        elif self.body in "BC" and target == t["json"]:
            ser = a(cpu.RSI)
            bufp = self.load(ser, 8)
            err, ptr, data = e.jsonw(self.body)
            if err:
                self.w8(bufp, e.case["jecap"])
                self.ret(err)
            else:
                self.blob(ptr)
                self.w8(bufp, e.case["jcap"])
                self.w8(bufp + 8, ptr)
                self.w8(bufp + 0x10, len(data))
                self.ret(0)
        elif target == t["conv"]:
            sl, sp = a(cpu.RDI), a(cpu.RSI)
            self.ret(e.errs(self.load(sl, 8), self.load(sl + 8, 8), self.load(sp, 8), self.load(sp + 8, 8),
                            self.load(sp + 0x10, 8)))
        elif target == t["pan"]:
            sl = a(cpu.RDI)
            self.ret(e.errp(self.load(sl, 8), self.load(sl + 8, 8), a(cpu.RSI)))
        else:
            raise ToolError(f"unmodelled call {target:#x} from {where:#x}")


COVER = {}


def run_machine(image, body, case, patches=()):
    env = Env(case)
    m = Rig(image, env, body)
    m.set_reg(cpu.RSP, cpu.STACK)
    m.store(cpu.STACK, 8, cpu.RETURN_MARK)
    m.set_reg(cpu.RDI, VALUE if body == "B" else CTX)
    m.set_reg(cpu.RSI, PATH)
    m.set_reg(cpu.RDX, len(case["path"]))
    m.set_reg(cpu.RCX, case["extra"])
    m.pc = BODIES[body]["entry"]
    try:
        m.run(m.pc)
    except Halt as h:
        COVER.setdefault(body, set()).update(m.seen)
        return h.how, env
    except cpu.Done as d:
        if d.how != "ret":
            raise ToolError(f"unexpected stop {d.how}")
    COVER.setdefault(body, set()).update(m.seen)
    if m.regs[cpu.RSP] != cpu.STACK + 8:
        raise ToolError("stack not balanced at return")
    return m.regs[cpu.RAX], env


# --------------------------------------------------------------------------- case generation
FRONTS = [  # (path, last component the components callee reports, component tag)
    (b"/dev/null", b"null", 9), (b"/dev/nul", b"nul", 9), (b"/dev/nulL", b"nulL", 9), (b"/dev/null/", b"null", 9),
    (b"dev/null", b"null", 9), (b"/dev/null ", b"null ", 9), (b"", b"", 0), (b"/", b"", 0),
    (b"/s/a.rmp", b"a.rmp", 9), (b"/s/a.RMP", b"a.RMP", 9), (b"/s/a.RmP", b"a.RmP", 9), (b"s/a.rmp", b"a.rmp", 9),
    (b"/s/a.rmq", b"a.rmq", 9), (b"/s/a.rm", b"a.rm", 9), (b"/s/a.rmpx", b"a.rmpx", 9), (b"/s/a.", b"a.", 9),
    (b"/s/.rmp", b".rmp", 9), (b"/s/rmp", b"rmp", 9), (b"/s/a.b.rmp", b"a.b.rmp", 9),
    (b"/s/a.rmp.json", b"a.rmp.json", 9),
    (b"/s/a.json", b"a.json", 9), (b"/s/..", b"..", 9), (b"/s/.", b".", 9), (b"/s/a.rmp/", b"a.rmp", 9),
    (b"/s/a.rmp", b"a.rmp", 0), (b"/s/a.rmp", b"a.rmp", 5), (b"/s/a.rmp", b"a.rmp", 8), (b"/s/a.rmp", b"a.rmp", 10),
    (b"/s/a.rmp", b"a.rmp", 0xff), (b"/s/x.RMP", b"x.RMP", 9), (b"/s/ab.rMp", b"ab.rMp", 9),
    (b"/s/a.r\xc3\xa9p", b"a.r\xc3\xa9p", 9),
    (b"x.rmp", b"x.rmp", 9), (b"/a/b/c/d/state.rmp", b"state.rmp", 9), (b"/a/b/c/d/state.json", b"state.json", 9),
    (b"/a/b.d/state", b"state", 9), (b"/a/b.rmp/state", b"state", 9), (b"/s/a..rmp", b"a..rmp", 9),
    (b"/s/a.rmp.", b"a.rmp.", 9),
    (b"/s/a.\0mp", b"a.\0mp", 9), (b"/s/a.rmp", b"..", 9), (b"/x/y/state.rmp", b"state.rmp", 9), (b"/x/y/state.RMP", b"state.RMP", 9),
    (b"./s.rmp", b"s.rmp", 9), (b"../z/s.rmp", b"s.rmp", 9), (b"/a/b/c.json", b"c.json", 9), (b"/dev/null2", b"null2", 9),
    (b"/dev/nuLL", b"nuLL", 9), (b"//s//a.rmp", b"a.rmp", 9), (b"/s/a.rmp", b".rmp", 9), (b"/s/a.rmp", b"a.rmp ", 9),
]
TAILS = [(0, 0, 3), (0, 9, 3), (7, 0, 0x1234abcd), (7, 9, U64)]  # parent_rc, write_rc, extra cycle
DATA_LENS = (0, 1, 5, 0x7f, 0x80, 0x81, 0x100, 300)


def blob(n, salt):
    return bytes((i * 37 + n + salt) & 0xff for i in range(n))


def scenarios(body):
    out = []
    for n in (0, 1, 5, 129, 300):
        for cap in (0, n, n + 7):
            for flag in ((0, 1) if body == "C" else (0,)):
                stages = 1 if body != "C" else 2 + flag
                out.append(dict(kind="rmp-ok", data=blob(n, 1), cap=cap, flag=flag, precap=0,
                                rmp_calls=[(2, 0x11)] * stages))
    for rax, rdx in ((0, 1), (1, 7), (3, 0), (5, 0xffff), (U64, 2)):
        for precap in (0, 9):
            for flag in ((0, 1) if body == "C" else (0,)):
                for stage in range(2 + flag if body == "C" else 1):
                    out.append(dict(kind="rmp-err%d" % stage, data=b"", cap=0, flag=flag, precap=precap,
                                    rmp_calls=[(2, 0x11)] * stage + [(rax, rdx)]))
    jsons = []
    if body == "A":
        for n in DATA_LENS:
            for gcap in (0, NEG):
                jsons.append(dict(data=blob(n, 2), gcap=gcap, jcap=0x80, jerr=0, jecap=0x80, alloc_ok=True))
    else:
        for n in (0, 1, 5, 0x7f, 0x80, 0x81, 300):
            for jcap in (0x80, 0, 0x300, NEG):
                jsons.append(dict(data=blob(n, 3), gcap=0, jcap=jcap, jerr=0, jecap=0x80, alloc_ok=True))
        for jecap in (0, 0x80):
            jsons.append(dict(data=b"", gcap=0, jcap=0x80, jerr=0x1234, jecap=jecap, alloc_ok=True))
    jsons.append(dict(data=blob(3, 4), gcap=0, jcap=0x80, jerr=0, jecap=0x80, alloc_ok=False))
    for j in jsons:
        j.update(kind="json", cap=0, flag=0, precap=0, rmp_calls=[(2, 0x11)] * (2 if body == "C" else 1))
    return out + jsons


def cases(body):
    k = 0
    for path, name, ctag in FRONTS:
        for sc in scenarios(body):
            parent, write, extra = TAILS[k % 4]
            case = dict(sc)
            case.update(path=path, name=name, ctag=ctag, tag=(k // 4) % 4 if body == "B" else 0,
                        parent_rc=parent, write_rc=write, extra=extra, conv_rc=0x5a00 + (k & 0xff))
            for key, val in (("gcap", 0), ("jcap", 0x80), ("jerr", 0), ("jecap", 0x80), ("alloc_ok", True)):
                case.setdefault(key, val)
            case["rmp_calls"] = list(sc["rmp_calls"])
            yield k, case
            k += 1


def fresh(case):
    c = dict(case)
    c["rmp_calls"] = list(case["rmp_calls"])
    return c


def outcome(image, body, case, mut=None, machine=True):
    """Return (return value, call log) from the machine bytes, or from the model when machine is False."""
    case = fresh(case)
    if machine:
        ret, env = run_machine(image, body, case)
        return ret, env.log
    env = Env(case)
    return model(body, env, mut), env.log


def digest(ret, log):
    return hashlib.sha256(repr((ret, log)).encode()).hexdigest()[:12]


# --------------------------------------------------------------------------- negative controls
def jcc_sites(image, body):
    """Short conditional jumps of the body, found by walking the decoded instruction stream."""
    t = BODIES[body]
    sites, va, end = [], t["entry"], t["entry"] + t["size"]
    while va < end:
        insn = image.fetch(va)
        if (isinstance(insn.key, int) and 0x70 <= insn.key <= 0x7f and image.data[image.file_offset(va)] == insn.key
                and va in COVER[body]):
            sites.append(va)
        va += insn.size
    return sites


def pattern_sites(image, body):
    """Compare immediates and constants worth corrupting: '.', '..', component tag 9, buffer size, rmp reader flags."""
    t = BODIES[body]
    lo = image.file_offset(t["entry"])
    chunk = bytes(image.data[lo:lo + t["size"]])
    found = []
    for pat, off, new, label in ((b"\x80\x79\xfe\x2e", 3, 0x2d, "dot-immediate"),
                                 (b"\x66\x81\x39\x2e\x2e", 3, 0x2d, "dotdot-immediate"),
                                 (b"\xbf\x80\x00\x00\x00", 1, 0x81, "alloc-size"),
                                 (b"\x00\x04\x00\x01", 3, 0x02, "rmp-reader-flags")):
        at = chunk.find(pat)
        while at != -1:
            found.append((t["entry"] + at + off, new, label))
            at = chunk.find(pat, at + 1)
    at = chunk.find(b"\x80\x7c\x24")
    while at != -1:
        if chunk[at + 4] == 0x09:
            found.append((t["entry"] + at + 4, 0x08, "component-tag"))
        at = chunk.find(b"\x80\x7c\x24", at + 1)
    return found


def patch(image, va, new):
    off = image.file_offset(va)
    old = image.data[off]
    image.data[off] = new
    image.cache.clear()
    return off, old


def unpatch(image, off, old):
    image.data[off] = old
    image.cache.clear()


def model_detects(image, body, probes, mut):
    """A model mutant is detected when it disagrees with the real bytes on any probe."""
    for k, case in probes:
        want = outcome(image, body, case)
        try:
            got = outcome(image, body, case, mut=mut, machine=False)
        except (ToolError, KeyError, IndexError, ValueError, TypeError):
            return True
        if got != want:
            return True
    return False


def byte_detects(image, body, probes, va, new):
    """A byte corruption is detected when the patched code disagrees with the model (or breaks a stub contract)."""
    off, old = patch(image, va, new)
    try:
        for k, case in probes:
            want = outcome(image, body, case, machine=False)
            try:
                got = outcome(image, body, case)
            except (ToolError, cpu.ToolError, cpu.Done, KeyError, IndexError, ValueError, TypeError, AssertionError):
                return True
            if got != want:
                return True
        return False
    finally:
        unpatch(image, off, old)


MODEL_MUTANTS = {
    "A": ["always-json", "always-rmp", "ignore-tag", "dotdot", "no-null", "null-prefix", "abs-flag", "dot-zero", "ext-off",
          "case-sensitive", "write-despite-parent", "write-first", "free-always", "leak", "keep-vec", "no-overflow",
          "grow-early"],
    "B": ["always-json", "always-rmp", "ignore-tag", "dotdot", "no-null", "null-prefix", "abs-flag", "dot-zero", "ext-off",
          "case-sensitive", "write-despite-parent", "write-first", "leak", "keep-vec", "no-overflow", "unit-shift"],
    "C": ["always-json", "always-rmp", "ignore-tag", "dotdot", "no-null", "null-prefix", "abs-flag", "dot-zero", "ext-off",
          "case-sensitive", "write-despite-parent", "write-first", "leak", "keep-vec", "no-overflow", "field-always"],
}


def run_all(out_dir=None, probe_step=11):
    global UNIT_NAMES
    image = load_image()
    image.data = bytearray(image.data)
    UNIT_NAMES = read_unit_names(image)
    total = bad = 0
    per = {}
    controls = []
    chain = {b: hashlib.sha256() for b in "ABC"}
    rows = open(out_dir / "cases.tsv", "w") if out_dir else None
    if rows:
        rows.write("body\tindex\tpath_hex\tname_hex\tctag\ttag\tscenario\tparent_rc\twrite_rc\tret\tcalls\tdigest\n")
    for body in "ABC":
        probes = []
        n = 0
        for k, case in cases(body):
            ret, log = outcome(image, body, case)
            want = outcome(image, body, case, machine=False)
            n += 1
            if (ret, log) != want:
                bad += 1
            chain[body].update(digest(ret, log).encode())
            if rows and k % 2 == 0:
                rows.write("%s\t%d\t%s\t%s\t%d\t%d\t%s\t%d\t%d\t%s\t%d\t%s\n" % (
                    body, k, case["path"].hex(), case["name"].hex(), case["ctag"], case["tag"], case["kind"],
                    case["parent_rc"], case["write_rc"], ret if isinstance(ret, str) else hex(ret), len(log),
                    digest(ret, log)))
            if k % probe_step == 0:
                probes.append((k, case))
        per[body] = n
        total += n
        for mut in MODEL_MUTANTS[body]:
            controls.append((body, "model:" + mut, model_detects(image, body, probes, mut)))
        for va in jcc_sites(image, body):
            controls.append((body, "flip-jcc@%#x" % va,
                             byte_detects(image, body, probes, va, image.data[image.file_offset(va)] ^ 1)))
        for va, new, label in pattern_sites(image, body):
            controls.append((body, "%s@%#x" % (label, va), byte_detects(image, body, probes, va, new)))
    for tag in (4, 7, 0xff):  # outside the four-entry jump table: the model refuses
        case = fresh(next(cases("B"))[1])
        case.update(tag=tag, path=b"/s/a.rmp", name=b"a.rmp", ctag=9, rmp_calls=[(2, 0x11)])
        try:
            outcome(image, "B", case, machine=False)
            controls.append(("B", "range:tag=%d" % tag, False))
        except ToolError:
            controls.append(("B", "range:tag=%d" % tag, True))
    return image, total, bad, per, controls, rows, {b: chain[b].hexdigest() for b in "ABC"}


def main(argv):
    if len(argv) != 3 or argv[1] != "--out":
        print("usage: state_export_sibling_router_115.py --out <folder>", file=sys.stderr)
        return 2
    out = Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    image, total, bad, per, controls, rows, chain = run_all(out)
    rows.close()
    detected = [c for c in controls if c[2]]
    with open(out / "controls.tsv", "w") as f:
        f.write("body\tcontrol\tdetected\n")
        for body, name, det in controls:
            f.write("%s\t%s\t%d\n" % (body, name, int(det)))
    names = [{"index": i, "address": hex(a), "length": n,
              "bytes_hex": bytes(image.data[image.file_offset(a):image.file_offset(a) + n]).hex()}
             for i, (a, n) in enumerate(UNIT_NAMES)]
    (out / "unit_names.json").write_text(json.dumps(names, indent=1) + "\n")
    cover = {}
    for body in "ABC":
        t = BODIES[body]
        va, every = t["entry"], []
        while va < t["entry"] + t["size"]:
            every.append(va)
            va += image.fetch(va).size
        miss = [v for v in every if v not in COVER[body]]
        cover[body] = {"instructions": len(every), "executed": len(every) - len(miss), "not_executed": [hex(v) for v in miss]}
    summary = {"binary_sha256": SHA, "coverage": cover, "cases": total, "case_digest_chain_sha256": chain, "listed_cases": "every second case index is listed in cases.tsv", "mismatches": bad, "per_body": per,
               "controls_attempted": len(controls), "controls_detected": len(detected),
               "controls_undetected": [c[:2] for c in controls if not c[2]]}
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": total, "negative_controls": len(controls),
                                                  "negative_detected": len(detected)}, indent=1) + "\n")
    print(json.dumps(summary))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
