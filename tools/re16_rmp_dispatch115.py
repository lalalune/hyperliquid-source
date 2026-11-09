#!/usr/bin/env python3
"""RE-016: the MessagePack marker front end of the state-file decoder at 0x3266520 (node #115).

The function (an rmp-style `Deserializer` front end; the name is an inference) reads one marker from a
slice reader, or consumes a marker cached by an earlier peek, and hands the value to one of five
external bodies.  This tool rebuilds that front end as a pure Python function (`model`), runs the real
bytes of the function on the repository's x86 emulator with every callee replaced by a halting stub, and
compares the model with the machine on a generated grid of reader states and input bytes.

Reader layout recovered from the bytes (slice reader `r14`):
  +0x10 pointer to the unread bytes, +0x18 count of unread bytes,
  +0x20 cached marker tag (1 = nothing cached; the function stores 1 on entry),
  +0x21 cached marker payload (fixint value / fix length), consumed only for the fix-style tags.

No external program is run; every number comes from ELF bytes or from the emulator.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import re16_state_materialize115 as base  # noqa: E402  (the merged emulator and ELF image reader)

START, END = 0x3266520, 0x3267997
TABLE = 0x70087C           # 256 x int32, relative to TABLE
UD2_VA = 0x326787C
ENTRY_FIX_ADDR = 0x3266601  # fast path used for fix-style markers read fresh
EXT = {  # external callees reached from the front end, by the stub address
    0x341FF00: "invalid_type",   # via GOT slot 0x64e4220
    0x1681E40: "container",      # map / array / ext bodies
    0x16815E0: "str_body",
    0x2F909A0: "bin_body",
}
STATIC_MAP, STATIC_ARRAY, STATIC_EXT = 0x6464FA8, 0x6464F78, 0x6464F60
EOF_PTR = 0x64622F0
IN, RD, OUT = 0x10000000, 0x30000000, 0x20000000
STACK_REF = base.STACK_TOP - 0x100
STR_SLOT, BIN_SLOT = -0x4F88, -0x27E0   # callee scratch slots, relative to STACK_REF
OUT_KIND, OUT_EOF, OUT_RANGE = 0x32665FD, None, None
SHA256 = base.SHA256

_orig_decode = base.decode


def decode16(code, va):
    """The merged decoder reads imm32 for 66 c7 / 66 81; those forms carry an imm16."""
    form = _orig_decode(code, va)
    if form["p66"] and form["op"] in (0xC7, 0x81):
        end = form["len"]
        form["imm"] = struct.unpack_from("<h", code, end - 4)[0]
        form["len"] = end - 2
    return form


base.decode = decode16


class ToolError(Exception):
    pass


def fail(msg):
    raise ToolError(msg)


# ------------------------------------------------------------------ static evidence
def load_image(data=None):
    if data is None:
        data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    return base.Image(data)


def jump_table(img):
    rows = []
    for i in range(256):
        rel = struct.unpack("<i", img.read(TABLE + 4 * i, 4))[0]
        rows.append((TABLE + rel) & base.M64)
    return rows


def decoded_function(img):
    rows = base.sweep_padded(img, START, END)
    return rows


def call_sites(img, rows):
    out = []
    for va, f in rows:
        if f is None:
            continue
        if f["op"] == 0xE8:
            out.append((va, "direct", f["target"], ""))
        elif f["op"] == 0xE9 and not START <= f["target"] < END:
            out.append((va, "tail", f["target"], ""))
        elif f["op"] == 0xFF and f["reg"] & 7 in (2, 4):
            rm = f["rm"]
            if rm[0] == "m" and rm[1] == "rip":
                slot = (va + f["len"] + rm[4]) & base.M64
                out.append((va, "got" if f["reg"] & 7 == 2 else "got-jmp", img.relative.get(slot, 0), hex(slot)))
            else:
                out.append((va, "register-jump" if f["reg"] & 7 == 4 else "register-call", 0, ""))
    return out


# ------------------------------------------------------------------ the rebuilt front end
def be(data, off, w):
    return int.from_bytes(data[off:off + w], "big")


FIX_FAST = {}   # filled lazily: unused, kept for readability of `normalise`


def normalise(b):
    """Marker byte -> (cached tag, payload).  Fix families keep the family tag and their value."""
    if b < 0x80:
        return 0x00, b
    if b < 0x90:
        return 0x80, b & 15
    if b < 0xA0:
        return 0x90, b & 15
    if b < 0xC0:
        return 0xA0, b & 31
    if b < 0xE0:
        return b, b & 31
    return 0xE0, b


KIND_ONLY = frozenset([0xC0, 0xC2, 0xC3] + list(range(0xCA, 0xD4)))
EXT_FIXED = frozenset(range(0xD4, 0xD9))
WIDTH = {0xC4: 1, 0xC5: 2, 0xC6: 4, 0xD9: 1, 0xDA: 2, 0xDB: 4, 0xDC: 2, 0xDD: 4, 0xDE: 2, 0xDF: 4,
         0xC7: 1, 0xC8: 2, 0xC9: 4}


def out_bytes(kind, tail):
    if kind == "eof0":
        return bytes([0]) + bytes(7) + struct.pack("<Q", EOF_PTR)
    if kind == "eof1":
        return bytes([1]) + bytes(7) + struct.pack("<Q", EOF_PTR)
    if kind == "ext-eof":
        return bytes([1, tail[0], tail[1]]) + bytes(5) + struct.pack("<Q", EOF_PTR)
    if kind == "reserved":
        return bytes([2, 0xC1]) + bytes(14)
    if kind == "range":
        return bytes([1]) + bytes(7) + struct.pack("<II", 3, 0x25)
    fail("unknown out kind")


def model(tag, aux, data, table, mut=frozenset()):
    """Expected observable outcome of one front-end run: a call (callee, regs) or a return, plus reader state."""
    n = len(data)
    off, rem = 0, n
    ptr = IN
    if tag == 1:                                   # nothing cached: read one marker byte
        if n == 0:
            return ("ret", out_bytes("eof0", 0), 0, 0)
        b = data[0]
        off, rem = 1, n - 1
        if b < 0xC0:
            fam, val = normalise(b)
            if fam == 0x00:
                return ("call", 0x341FF00, OUT, RD, 0, val, 0, off, rem)
            if fam == 0x80:
                return ("call", 0x1681E40, STATIC_MAP, val, val, rem, 0, off, rem)
            if fam == 0x90:
                return ("call", 0x1681E40, STATIC_ARRAY, val, 0, rem, 0, off, rem)
            if val > rem:
                return ("ret", out_bytes("range", 0), off, rem)
            return ("call", 0x16815E0, STACK_REF + STR_SLOT, IN + off, val, rem - val, 0, off + val, rem - val)
        tag, aux = normalise(b)
    if mut and "ud2-as-call" in mut and table[tag] == UD2_VA:
        return ("ud2",)
    if table[tag] == UD2_VA:
        return ("ud2", off, rem)
    handler = table[tag]
    if tag == 0x00:
        return ("call", 0x341FF00, OUT, RD, 0, aux, handler, off, rem)
    if tag == 0x80:
        return ("call", 0x1681E40, STATIC_MAP, aux, aux, TABLE, handler, off, rem)
    if tag == 0x90:
        return ("call", 0x1681E40, STATIC_ARRAY, aux, 0, TABLE, handler, off, rem)
    if tag == 0xA0:
        if aux > rem:
            return ("ret", out_bytes("range", 0), off, rem)
        return ("call", 0x16815E0, STACK_REF + STR_SLOT, IN + off, aux, rem - aux, handler, off + aux, rem - aux)
    if tag == 0xC1:
        return ("ret", out_bytes("reserved", 0), off, rem)
    if tag in KIND_ONLY or tag == 0xE0:
        return ("call", 0x341FF00, OUT, RD, tag, aux, 0 if tag == 0xE0 and off else handler, off, rem)
    if tag in EXT_FIXED:
        return ("call", 0x1681E40, STATIC_EXT, aux, 0x700C00, 0, handler, off, rem)
    if tag not in WIDTH:
        fail("cached tag %#x is outside the front end's domain" % tag)
    w = WIDTH[tag]
    if rem < w:                                    # short length word: everything left is consumed
        if tag in (0xC7, 0xC8, 0xC9):
            return ("ret", out_bytes("ext-eof", (tag, aux)), off + rem, 0)
        return ("ret", out_bytes("eof1", 0), off + rem, 0)
    cnt = be(data, off, w)
    off, rem = off + w, rem - w
    if tag in (0xC7, 0xC8, 0xC9):
        r = rem if w > 1 else 0
        return ("call", 0x1681E40, STATIC_EXT, aux, (IN + off) if w == 1 else rem, 0, handler, off, rem)
    if tag in (0xDC, 0xDD, 0xDE, 0xDF):
        st = STATIC_ARRAY if tag in (0xDC, 0xDD) else STATIC_MAP
        rdx = cnt if (tag in (0xDC, 0xDE, 0xDF)) else 0
        return ("call", 0x1681E40, st, aux, rdx, rem, handler, off, rem, cnt if tag in (0xDC, 0xDD) else None)
    if cnt > rem:
        return ("ret", out_bytes("range", 0), off, rem)
    if tag in (0xC4, 0xC5, 0xC6):
        return ("call", 0x2F909A0, OUT, STACK_REF + BIN_SLOT, 0, rem - cnt, handler, off + cnt, rem - cnt)
    return ("call", 0x16815E0, STACK_REF + STR_SLOT, IN + off, cnt, rem - cnt, handler, off + cnt, rem - cnt)


# ------------------------------------------------------------------ the machine side
class Rig:
    def __init__(self, img, override=None):
        self.img = img
        self.m = base.Machine(img, override)
        self.targets = sorted(set(t for _, k, t, _ in call_sites(img, decoded_function(img)) if t))

    def run(self, tag, aux, data):
        m = self.m
        m.reset()
        for t in self.targets:
            m.stubs[t] = "x%x" % t
        m.add_region(IN, 0x400, bytes(data))
        out = m.add_region(OUT, 0x40)
        rd = m.add_region(RD, 0x100)
        struct.pack_into("<QQBB", rd, 0x10, IN, len(data), tag, aux)
        m.regs[7], m.regs[6] = OUT, RD
        try:
            m.run(START, limit=5000)
            res = ("ret", bytes(out[:16]))
        except base.Boundary as b:
            r = b.regs
            res = ("call", int(b.kind[1:], 16), r[7], r[6], r[2], r[1], r[8], r[5])
        except base.ToolError as e:
            if "ud2" in str(e):
                res = ("ud2",)
            else:
                res = ("fault", str(e)[:40])
        p, n, _, _ = struct.unpack_from("<QQBB", rd, 0x10)
        return res, p - IN, n


def observed(rig, tag, aux, data):
    res, off, rem = rig.run(tag, aux, data)
    if res[0] == "call":
        return res[:7] + (off, rem) + ((res[7],) if True else ())
    if res[0] == "ret":
        return ("ret", res[1], off, rem)
    if res[0] == "ud2":
        return ("ud2", off, rem)
    return res + (off, rem)


def expected(table, tag, aux, data, mut=frozenset()):
    e = model(tag, aux, data, table, mut)
    if e[0] == "call":
        base_ = e[:9]
        rbp = e[9] if len(e) > 9 else None
        return base_, rbp
    return e, None


def same(obs, exp):
    e, rbp = exp
    if obs[0] == "call":
        if e[0] != "call":
            return False
        if obs[:9] != e[:9]:
            return False
        if rbp is not None and obs[9] & 0xFFFFFFFF != rbp:
            return False
        return True
    return obs == e


# ------------------------------------------------------------------ case grid
class Lcg:
    def __init__(self, seed):
        self.s = seed

    def next(self, k):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & base.M64
        return (self.s >> 33) % k


BYTE_POOL = [0, 0, 0, 0, 1, 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 0x7F, 0x80, 0xC0, 0xDC, 0xFF]


def make_data(r, variant):
    shape = variant % 9
    length = [0, 1, 2, 3, 4, 5, 6, 9, 20][shape]
    if variant >= 18:
        length = r.next(24)
    out = bytearray()
    for _ in range(length):
        out.append(BYTE_POOL[r.next(len(BYTE_POOL))] if r.next(3) else r.next(256))
    if length >= 4 and r.next(2):
        out[0:4] = bytes([0, 0, 0, r.next(8)])
    return bytes(out)


def cached_tags(table):
    tags = [0x00, 0x80, 0x90, 0xA0, 0xE0] + list(range(0xC0, 0xE0))
    ud2 = [t for t in range(2, 0x80) if table[t] == UD2_VA][:12]
    return tags + ud2


def all_cases(table):
    r = Lcg(0x5EED16)
    for b in range(256):                      # fresh marker read
        for v in range(24):
            yield 1, 0, bytes([b]) + make_data(r, v)
    yield 1, 0, b""
    for tag in cached_tags(table):            # cached marker
        for aux in (0, 1, 5, 15, 16, 31, 32, 127, 255):
            for v in range(10):
                yield tag, aux, make_data(r, v)


def evaluate(rig, table, cases, mut=frozenset(), stop_first=False):
    n = bad = 0
    first = None
    for tag, aux, data in cases:
        n += 1
        if not same(observed(rig, tag, aux, data), expected(table, tag, aux, data, mut)):
            bad += 1
            if first is None:
                first = (tag, aux, data)
            if stop_first:
                break
    return n, bad, first


# ------------------------------------------------------------------ controls
def mutate_expected(exp, name, tag, aux, data):
    """Deliberately wrong rebuilds, applied to the model output."""
    e, rbp = exp
    e = list(e)
    if name == "ud2-reports-call" and e[0] == "ud2":
        return ("call", 0, 0, 0, 0, 0, 0, 0, 0), None
    if e[0] == "call":
        if name == "swap-rsi-rdx" and e[1] == 0x1681E40:
            e[3], e[4] = e[4], e[3]
        elif name == "kind-value-swapped" and e[1] == 0x341FF00:
            e[4], e[5] = e[5], e[4]
        elif name == "str-skips-length-word" and e[1] == 0x16815E0 and tag in (0xD9, 0xDA, 0xDB):
            e[7] += 1
        elif name == "bin-wrong-rest" and e[1] == 0x2F909A0:
            e[5] += 1
        elif name == "fixarray-uses-map-table" and e[1] == 0x1681E40 and e[2] == STATIC_ARRAY:
            e[2] = STATIC_MAP
        elif name == "ext-pointer-dropped" and e[1] == 0x1681E40 and e[2] == STATIC_EXT:
            e[4] = 0
        elif name == "handler-address-zero" and e[6] != 0:
            e[6] = 0
        elif name == "consumed-off-by-one" and e[1] == 0x16815E0:
            e[7] += 1
        elif name == "rest-ignores-body" and e[1] == 0x16815E0:
            e[8] = e[8] + e[5]
        return tuple(e), rbp
    if e[0] == "ret":
        if name == "range-error-as-eof":
            if e[1][8:12] == struct.pack("<I", 3):
                e[1] = out_bytes("eof1", 0)
        elif name == "short-length-keeps-bytes" and tag in WIDTH and e[3] == 0 and e[2] > 0:
            e[3] = 1
        elif name == "reserved-marker-as-kind" and e[1][:2] == b"\x02\xc1":
            e[1] = b"\x01\xc1" + e[1][2:]
        return tuple(e), rbp
    return tuple(e), rbp


MODEL_MUTANTS = ("ud2-reports-call", "swap-rsi-rdx", "kind-value-swapped", "str-skips-length-word", "bin-wrong-rest",
                 "fixarray-uses-map-table", "ext-pointer-dropped", "handler-address-zero", "consumed-off-by-one",
                 "rest-ignores-body", "range-error-as-eof", "short-length-keeps-bytes", "reserved-marker-as-kind")


def model_mutant_detected(rig, table, name, cases):
    for tag, aux, data in cases:
        exp = mutate_expected(expected(table, tag, aux, data), name, tag, aux, data)
        if not same(observed(rig, tag, aux, data), exp):
            return True
    return False


def jcc_sites(rows):
    out = []
    for va, f in rows:
        if f is None:
            continue
        if 0x70 <= f["op"] <= 0x7F:
            out.append((va, "short"))
        elif 0x0F80 <= f["op"] <= 0x0F8F:
            out.append((va + 1, "near"))
    return out


def byte_mutant_detected(img, table, va, cases):
    old = img.code(va, 1)[0]
    rig = Rig(img, {va: old ^ 1})
    for tag, aux, data in cases:
        try:
            obs = observed(rig, tag, aux, data)
        except (base.ToolError, base.Boundary, KeyError, IndexError, struct.error):
            return True
        if not same(obs, expected(table, tag, aux, data)):
            return True
    return False


def table_mutant_detected(rig, table, a, b, cases):
    bad = list(table)
    bad[a] = table[b]
    n, mism, _ = evaluate(rig, bad, cases, stop_first=True)
    return mism > 0


def domain_rejected(table, tag):
    try:
        model(tag, 3, b"\x01\x02\x03", table)
    except ToolError:
        return True
    return False


def image_rejected(kind):
    data = bytearray((ROOT / "artifacts/node/115/hl-node").read_bytes())
    if kind == "flipped-byte":
        data[len(data) // 2] ^= 1
    else:
        data = data[:-1]
    try:
        base.Image(bytes(data))
    except base.ToolError:
        return True
    return False


def unmapped_rejected(img):
    try:
        img.read(0xDEADBEEF, 4)
    except base.ToolError:
        return True
    return False


def run_controls(img, rig, table, cases):
    sub = cases[::7]
    rows = []
    for name in MODEL_MUTANTS:
        rows.append(("model-mutant", name, model_mutant_detected(rig, table, name, sub)))
    sites = jcc_sites(decoded_function(img))
    step = max(1, len(sites) // 40)
    tried = 0
    for va, form in sites[::step]:
        tried += 1
        det = byte_mutant_detected(img, table, va, sub[::3])
        if det:
            rows.append(("byte-mutant", "%s-jcc-%#x" % (form, va), True))
    rows.append(("byte-mutant-candidates", "tried", tried))
    for a, b in ((0xC4, 0xC5), (0xD9, 0xDA), (0xDC, 0xDD), (0xC7, 0xC4)):
        rows.append(("table-mutant", "entry-%#x-as-%#x" % (a, b), table_mutant_detected(rig, table, a, b, cases)))
    for tag in (0xE1, 0xF0, 0xFF):
        rows.append(("domain", "cached-tag-%#x" % tag, domain_rejected(table, tag)))
    rows.append(("image", "flipped-byte", image_rejected("flipped-byte")))
    rows.append(("image", "truncated", image_rejected("truncated")))
    rows.append(("image", "unmapped-read", unmapped_rejected(img)))
    return rows


# ------------------------------------------------------------------ generation
def describe(o):
    if o[0] == "call":
        return "call\t%s\t%s\t%d\t%d" % (EXT[o[1]], ",".join(hex(x) for x in o[2:7]), o[7], o[8])
    if o[0] == "ret":
        return "ret\t%s\t%s\t%d\t%d" % ("return", o[1].hex(), o[2], o[3])
    return "ud2\tunreachable\t-\t%d\t%d" % (o[1], o[2])


def generate(out):
    img = load_image()
    table = jump_table(img)
    rig = Rig(img)
    if base.fde_rows(img, [START]) != {START: (START, END)}:
        fail("the unwind record does not give the expected function extent")
    rows = decoded_function(img)
    out.mkdir(parents=True, exist_ok=True)
    files = {}

    def w(name):
        f = open(out / name, "w", newline="\n")
        files[name] = f
        return f

    f = w("jump_table.tsv")
    f.write("index\ttarget\tinside_function\tunreachable_trap\n")
    for i, t in enumerate(table):
        f.write("%#x\t%#x\t%d\t%d\n" % (i, t, START <= t < END, t == UD2_VA))
    f = w("call_sites.tsv")
    f.write("site\tkind\ttarget\tgot_slot\n")
    for va, kind, tgt, slot in call_sites(img, rows):
        f.write("%#x\t%s\t%#x\t%s\n" % (va, kind, tgt, slot))
    f = w("cases.tsv")
    f.write("case\ttag\taux\tbytes\toutcome\tdetail\targs_or_out\toffset\tremaining\n")
    counts = {}
    n = bad = 0
    case_list = []
    for tag, aux, data in all_cases(table):
        n += 1
        obs = observed(rig, tag, aux, data)
        if not same(obs, expected(table, tag, aux, data)):
            bad += 1
        key = obs[0] if obs[0] != "call" else EXT[obs[1]]
        counts[key] = counts.get(key, 0) + 1
        f.write("%d\t%#x\t%d\t%s\t%s\n" % (n, tag, aux, data.hex(), describe(obs)))
        case_list.append((tag, aux, data))
    if bad:
        fail("model disagrees with the machine on %d cases" % bad)
    ctl = run_controls(img, rig, table, case_list)
    f = w("controls.tsv")
    f.write("kind\tname\tdetected\n")
    neg = det = 0
    for kind, name, d in ctl:
        f.write("%s\t%s\t%s\n" % (kind, name, d))
        if kind != "byte-mutant-candidates":
            neg += 1
            det += bool(d)
    summary = {
        "binary_sha256": SHA256,
        "function": [START, END],
        "instructions": sum(1 for _, x in rows if x is not None),
        "jump_table": TABLE,
        "table_targets_distinct": len(set(table)),
        "trap_entries": sum(1 for t in table if t == UD2_VA),
        "outcomes": dict(sorted(counts.items())),
        "cases": n,
        "mismatches": bad,
    }
    with open(out / "summary.json", "w", newline="\n") as g:
        json.dump(summary, g, indent=2, sort_keys=True)
        g.write("\n")
    with open(out / "measure.json", "w", newline="\n") as g:
        json.dump({"cases": n, "negative_controls": neg, "negative_detected": det}, g, indent=2)
        g.write("\n")
    for f in files.values():
        f.close()
    return summary, neg, det


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    summary, neg, det = generate(Path(args.out))
    print(json.dumps(summary, sort_keys=True), neg, det)
    return 0


if __name__ == "__main__":
    sys.exit(main())
