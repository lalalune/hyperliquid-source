#!/usr/bin/env python3
"""Reconstruct and validate the node #115 path-component trio 0x5c8e790 / 0x5c8e8c0 / 0x5cab560.

The three functions are the Unix half of the Rust standard-library path iterator `Components` as it is compiled
into node #115 (state-file and database paths are walked with it).  A `Components` value is 0x3b bytes: path
pointer +0, path length +8, an unused Option<Prefix> area +0x10..0x38, `front` +0x38 and `back` +0x39 (state byte
0 Prefix, 1 StartDir, 2 Body, 3 Done) and `has_physical_root` +0x3a.
  0x5c8e790  parse_next_component_back(out, comps): scans the path from the end for '/', classifies the last piece
             ("" and "." are skipped, ".." is a parent, anything else a normal name) and returns
             (consumed bytes, kind, piece pointer, piece length) in a 0x20-byte record.
  0x5c8e8c0  Components::as_path(comps) -> (ptr, len): works on a copy, trims skipped pieces from the front when
             front is Body and from the back when back is Body, and returns the remaining path slice.
  0x5cab560  Components::next_back(out, comps): shrinks the path and the back state, returning an Option<Component>
             record whose first byte is 6 RootDir, 7 CurDir, 8 ParentDir, 9 Normal or 0xa for None.
The tool reads every code byte, relocation and panic-site constant from the ELF file and evaluates the real machine
code with the concrete x86-64 evaluator of the repository tool re16_state_materialize115 (the binary is never run;
the two panic slots are stubs that stop the run).  Each case is compared with the pure-Python reconstruction in
`parse_back`, `as_path` and `next_back`, including the post-call Components bytes; negative controls (wrong
reconstructions, flipped code bytes, a corrupted input binary, an out-of-range address) must all be caught.
Names (Components, as_path, next_back) are inferences from the standard-library shape, not proven by any string.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_state_materialize115 as base  # noqa: E402

BINARY = base.BINARY if hasattr(base, "BINARY") else ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = base.SHA256
M64 = (1 << 64) - 1
ToolError, Boundary, Image, Stream = base.ToolError, base.Boundary, base.Image, base.Stream
fail = base.fail

PARSE, AS_PATH, NEXT_BACK = 0x5c8e790, 0x5c8e8c0, 0x5cab560
PANIC_SLOT, UNREACH_SLOT = 0x64df570, 0x64df730
PATH_AT = 0x7d00_0100_0000
COMP_AT = 0x7d00_0200_0000
OUT_AT = 0x7d00_0300_0000
PRE, POST = 0x10, 0x8          # padding bytes before / after the path inside its buffer
COMP_SIZE = 0x40
OUT_SIZE = 0x80
FILL_OUT, FILL_STACK = 0xcc, 0x5c

# (call site VA, name, instruction prefix bytes of the lea that loads the location)
PANIC_SITES = (
    (0x5c8e7c5, "parse_start_gt_len", 0x5c8e7b5),
    (0x5c8e8ad, "parse_len_sub", 0x5c8e8a0),
    (0x5c8eb00, "as_path_trim_sub", 0x5c8eaf1),
    (0x5c8eb10, "as_path_left_add", 0x5c8eb06),
    (0x5cab8fd, "next_back_sub_comp", 0x5cab8f1),
    (0x5cab916, "next_back_unreachable", 0x5cab90a),
    (0x5cab92a, "next_back_root_sub", 0x5cab91c),
    (0x5cab93f, "next_back_cur_sub", 0x5cab933),
    (0x5cab957, "next_back_body_sub", 0x5cab94b),
    (0x5cab96b, "next_back_curdir_sub", 0x5cab95d),
)


# ---------------------------------------------------------------- reconstruction
def include_cur_dir(path):
    """True when the path starts with "." followed by end or '/' (reads at most two bytes)."""
    if len(path) == 0:
        return False
    if len(path) == 1:
        return path[0] == 0x2e
    return path[0] == 0x2e and path[1] == 0x2f


def len_before_body(path, front, root, mut=frozenset()):
    if front > 1:
        return 0
    if root:
        return 1
    return 1 if include_cur_dir(path) else 0


def classify(piece, mut=frozenset()):
    if len(piece) == 0:
        return 0x0a
    if len(piece) == 1 and piece[0] == 0x2e:
        return 0x0a if "dot_normal" not in mut else 9
    if len(piece) == 2 and piece == b"..":
        return 8 if "parent_normal" not in mut else 9
    return 9


class Panic(Exception):
    def __init__(self, site, args):
        super().__init__(site)
        self.site, self.args = site, tuple(args)


def parse_back(path, front, root, mut=frozenset()):
    """-> (consumed, kind, piece_offset, piece_len) for the slice path; raises Panic(slice start past end)."""
    start = len_before_body(path, front, root)
    if "parse_no_start" in mut:
        start = 0
    if start > len(path):
        raise Panic("parse_start_gt_len", (1, 0, 0))
    tail = path[start:]
    i = tail.rfind(b"/")
    if "parse_first_sep" in mut:
        i = tail.find(b"/")
    if i < 0:
        off, extra = start, 0
    else:
        off, extra = start + i + 1, 1
        if "parse_extra_zero" in mut:
            extra = 0
    piece = path[off:]
    return len(piece) + extra, classify(piece, mut), off, len(piece)


def trim_left(path, mut=frozenset()):
    """Drop leading empty or "." pieces; return the new start offset."""
    pos = 0
    while pos < len(path):
        rest = path[pos:]
        i = rest.find(b"/")
        end = len(rest) if i < 0 else i
        sep = 0 if i < 0 else 1
        piece = rest[:end]
        if end == 0 or (end == 1 and piece[0] == 0x2e):
            pos += end + sep
            continue
        return pos
    return len(path)


def as_path(path, front, back, root, mut=frozenset()):
    """-> (offset, length) of the trimmed slice; raises Panic only on the unreachable arithmetic guards."""
    off = 0
    if front == 2:
        off = trim_left(path, mut)
        path = path[off:]
    if back == 2:
        for _ in range(len(path) + 2):
            if front > 1:
                floor = 0
            elif root:
                floor = 1
            else:
                floor = 1 if include_cur_dir(path) else 0
            if "trim_floor_zero" in mut:
                floor = 0
            if len(path) <= floor:
                break
            consumed, kind, _, _ = parse_back(path, front, root, mut)
            if kind != 0x0a:
                break
            path = path[:len(path) - consumed]
        else:
            fail("as_path model does not terminate")
    return off, len(path)


def next_back(path, front, back, root, mut=frozenset()):
    """-> (result, path_len, front, back) where result is (kind, piece_off, piece_len) or None."""
    n = len(path)
    state_back = back
    if front == 3:
        return None, n, front, state_back
    for _ in range(2 * n + 8):
        if state_back == 3 or front == 3 or front > state_back:
            return None, n, front, state_back
        cur = path[:n]
        if state_back == 2:
            if n > len_before_body(cur, front, root):
                consumed, kind, off, plen = parse_back(cur, front, root, mut)
                n -= consumed
                if kind != 0x0a:
                    return (kind, off, plen), n, front, state_back
                continue
            state_back = 1
            if "body_to_prefix" in mut:
                state_back = 3
            continue
        if state_back == 1:
            state_back = 3
            if root:
                if n == 0:
                    raise Panic("next_back_root_sub", (0, M64, 0))
                n -= 1
                return (6, None, None), n, front, state_back
            if include_cur_dir(cur) and "no_curdir" not in mut:
                n -= 1
                return (7, None, None), n, front, state_back
            return None, n, front, state_back
        raise Panic("next_back_unreachable", ())
    fail("next_back model does not terminate")


# ---------------------------------------------------------------- machine harness
def machine(image, override=None):
    m = base.Machine(image, code_override=override)
    return m


def setup(m, image, path, front, back, root, junk, with_out):
    m.reset()
    for b in m.regions[0:1]:
        b[2][:] = bytes([FILL_STACK]) * len(b[2])
    m.stubs[image.relative[PANIC_SLOT]] = "panic"
    m.stubs[image.relative[UNREACH_SLOT]] = "unreachable"
    buf = b"\x2e" * PRE + path + b"\x2e" * POST
    m.add_region(PATH_AT, len(buf), buf)
    comp = bytearray(COMP_SIZE)
    base.put(comp, 0, 8, PATH_AT + PRE)
    base.put(comp, 8, 8, len(path))
    comp[0x10:0x38] = junk
    comp[0x38], comp[0x39], comp[0x3a] = front, back, root
    comp[0x3b:] = b"\x77" * (COMP_SIZE - 0x3b)
    cbuf = m.add_region(COMP_AT, COMP_SIZE, bytes(comp))
    obuf = m.add_region(OUT_AT, OUT_SIZE, bytes([FILL_OUT]) * OUT_SIZE)
    return cbuf, obuf


def run(m, image, entry, path, front, back, root, junk):
    """Run one entry; returns a result dict (panics included) and the final Components bytes."""
    cbuf, obuf = setup(m, image, path, front, back, root, junk, True)
    m.regs[6 if entry != AS_PATH else 7] = COMP_AT
    if entry != AS_PATH:
        m.regs[7] = OUT_AT
    try:
        m.run(entry, limit=4000)
    except Boundary as b:
        return {"panic": b.kind, "regs": (b.regs[7] & M64, b.regs[6] & M64, b.regs[2] & M64, b.regs[1] & M64)}, bytes(cbuf)
    if entry == AS_PATH:
        return {"ret": (m.regs[0] & M64, m.regs[2] & M64)}, bytes(cbuf)
    return {"out": bytes(obuf), "ret": m.regs[0] & M64}, bytes(cbuf)


def site_table(image):
    """Location constants loaded by the lea in front of each panic call, read from the code bytes."""
    rows = []
    for call, name, lea in PANIC_SITES:
        code = image.code(lea, 7)
        if code[0] not in (0x48, 0x4c) or code[1] != 0x8d:
            fail(f"no lea at {lea:#x}")
        disp = struct.unpack("<i", code[3:7])[0]
        rows.append((name, call, lea, lea + 7 + disp))
    return rows


# ---------------------------------------------------------------- cases
PIECES = (b"/", b"/", b".", b"..", b"a", b"bc", b"x.y", b"...", b"./", b"../", b"//", b"hl/", b"state", b"")


def make_path(s):
    parts = []
    for _ in range(s.below(9)):
        parts.append(s.pick(PIECES))
    path = b"".join(parts)
    if s.below(4) == 0:
        path = path[:s.below(len(path) + 1)]
    return path


def junk_bytes(s):
    return s.take(0x28)


def all_cases():
    """Deterministic list of (entry name, path, front, back, root, junk, tag)."""
    s = Stream("re16-path-components-115")
    out = []
    # reachable initial states: front Prefix, back Body, root = path starts with '/'
    for i in range(1400):
        p = make_path(s)
        out.append(("next_back_drain", p, 0, 2, int(p.startswith(b"/")), junk_bytes(s), "initial"))
    for i in range(1300):
        p = make_path(s)
        out.append(("as_path", p, 0, 2, int(p.startswith(b"/")), junk_bytes(s), "initial"))
    for i in range(1200):
        p = make_path(s)
        out.append(("parse_back", p, 0, 2, int(p.startswith(b"/")), junk_bytes(s), "initial"))
    # arbitrary state bytes (front 0..3, back 0..3, root 0/1) with arbitrary paths
    for entry, count in (("parse_back", 3000), ("as_path", 3000), ("next_back", 3200), ("next_back_drain", 1500)):
        for i in range(count):
            p = make_path(s)
            out.append((entry, p, s.below(4), s.below(4), s.below(2), junk_bytes(s), "arbitrary"))
    # exhaustive small paths over a 3-letter alphabet for every reachable-ish state
    alpha = (b"/", b".", b"a")
    paths = [b""]
    frontier = [b""]
    for _ in range(5):
        frontier = [x + a for x in frontier for a in alpha]
        paths += frontier
    for p in paths:
        for front, back in ((0, 2), (1, 2), (2, 2), (0, 1), (1, 1)):
            for root in (0, 1):
                out.append(("next_back_drain" if back == 2 else "next_back", p, front, back, root, bytes(0x28), "exhaustive"))
    return out


def expect_view(entry, case, mut):
    _, path, front, back, root, _, _ = case
    if entry == "parse_back":
        return parse_back(path, front, root, mut)
    if entry == "as_path":
        return as_path(path, front, back, root, mut)
    return next_back(path, front, back, root, mut)


def run_case(m, image, case, sites, mut=frozenset()):
    """Run a case on the machine and the model; returns (ok, summary string)."""
    kind, path, front, back, root, junk, _ = case
    steps = []
    if kind == "next_back_drain":
        p, f, b = path, front, back
        n = len(path)
        for _ in range(len(path) + 3):
            pe = path[:n]
            res, cbuf = run(m, image, NEXT_BACK, pe, f, b, root, junk)
            try:
                want = next_back(pe, f, b, root, mut)
            except Panic as pn:
                want = pn
            line = compare_next_back(res, cbuf, pe, f, b, root, want, sites)
            steps.append(line[1])
            if not line[0]:
                return False, "|".join(steps)
            if isinstance(want, Panic) or want[0] is None:
                break
            _, n, f, b = want
            steps.append("")
            # the machine state must also drive the next iteration; use the model's (already proven equal) state
        # as_path after the drain on the shrunken state is compared in as_path cases
        return True, "|".join(x for x in steps if x)
    if kind == "next_back":
        res, cbuf = run(m, image, NEXT_BACK, path, front, back, root, junk)
        try:
            want = next_back(path, front, back, root, mut)
        except Panic as pn:
            want = pn
        return compare_next_back(res, cbuf, path, front, back, root, want, sites)
    if kind == "parse_back":
        res, cbuf = run(m, image, PARSE, path, front, back, root, junk)
        try:
            want = parse_back(path, front, root, mut)
        except Panic as pn:
            want = pn
        return compare_parse(res, cbuf, path, front, back, root, want, sites)
    res, cbuf = run(m, image, AS_PATH, path, front, back, root, junk)
    try:
        want = as_path(path, front, back, root, mut)
    except Panic as pn:
        want = pn
    return compare_as_path(res, cbuf, path, front, back, root, want, sites)


def panic_matches(res, want, sites):
    if "panic" not in res or not isinstance(want, Panic):
        return False
    loc = {n: l for n, _, _, l in sites}[want.site]
    if res["panic"] == "unreachable":
        return want.site == "next_back_unreachable"
    return res["regs"][3] == loc and (not want.args or res["regs"][:3] == tuple(want.args))


def same_comp(cbuf, path, front, back, root, junk, n):
    exp = bytearray(COMP_SIZE)
    base.put(exp, 0, 8, PATH_AT + PRE)
    base.put(exp, 8, 8, n)
    exp[0x10:0x38] = junk
    exp[0x38], exp[0x39], exp[0x3a] = front, back, root
    return None


def compare_parse(res, cbuf, path, front, back, root, want, sites):
    if isinstance(want, Panic):
        ok = panic_matches(res, want, sites)
        return ok, f"panic:{want.site}" if ok else f"MISMATCH panic {want.site} vs {res}"
    if "out" not in res:
        return False, f"MISMATCH unexpected panic {res}"
    out = res["out"]
    consumed, kind, off, plen = want
    got = (base.u(out, 0, 8), out[8], base.u(out, 0x10, 8) - (PATH_AT + PRE), base.u(out, 0x18, 8))
    same_struct = cbuf[:0x3b].startswith(struct.pack("<QQ", PATH_AT + PRE, len(path)))
    ok = got == (consumed, kind, off, plen) and same_struct
    return ok, f"consumed={consumed} kind={kind:#x} off={off} len={plen}" if ok else f"MISMATCH want={want} got={got}"


def compare_as_path(res, cbuf, path, front, back, root, want, sites):
    if isinstance(want, Panic):
        ok = panic_matches(res, want, sites)
        return ok, f"panic:{want.site}" if ok else f"MISMATCH panic {want.site} vs {res}"
    if "ret" not in res or "panic" in res:
        return False, f"MISMATCH unexpected panic {res}"
    ptr, ln = res["ret"]
    off, n = want
    ok = (ptr - (PATH_AT + PRE), ln) == (off, n) and cbuf[0x38:0x3b] == bytes([front, back, root]) \
        and struct.unpack_from("<QQ", cbuf, 0) == (PATH_AT + PRE, len(path))
    return ok, f"off={off} len={n}" if ok else f"MISMATCH want={want} got={(ptr - PATH_AT - PRE, ln)}"


def compare_next_back(res, cbuf, path, front, back, root, want, sites):
    if isinstance(want, Panic):
        ok = panic_matches(res, want, sites)
        return ok, f"panic:{want.site}" if ok else f"MISMATCH panic {want.site} vs {res}"
    if "out" not in res:
        return False, f"MISMATCH unexpected panic {res}"
    comp, n, f, b = want
    out = res["out"]
    tag = out[0]
    ok = True
    if comp is None:
        ok = tag == 0x0a
    else:
        ok = tag == comp[0]
        if comp[0] in (8, 9):
            ok = ok and base.u(out, 8, 8) - (PATH_AT + PRE) == comp[1] and base.u(out, 0x10, 8) == comp[2]
    ok = ok and struct.unpack_from("<Q", cbuf, 0)[0] == PATH_AT + PRE and base.u(cbuf, 8, 8) == n \
        and cbuf[0x38] == f and cbuf[0x39] == b and cbuf[0x3a] == root
    names = {6: "RootDir", 7: "CurDir", 8: "ParentDir", 9: "Normal", 0x0a: "None"}
    text = f"{names.get(tag, hex(tag))} len={n} state={f}{b}"
    if comp is not None and comp[0] in (8, 9):
        text += f" piece={comp[1]}+{comp[2]}"
    return ok, text if ok else f"MISMATCH want={want} tag={tag:#x} len={base.u(cbuf, 8, 8)} state={cbuf[0x38]}{cbuf[0x39]}"


def evaluate(image, cases, override=None, mut=frozenset(), stop_on_first=False):
    m = machine(image, override)
    sites = site_table(image)
    bad = total = 0
    rows = []
    for i, case in enumerate(cases):
        total += 1
        try:
            ok, text = run_case(m, image, case, sites, mut)
        except ToolError as exc:
            ok, text = False, f"MISMATCH evaluator {exc}"
        if not ok:
            bad += 1
            if stop_on_first:
                return total, bad, rows
        if not stop_on_first:
            rows.append((i, case, ok, text))
    return total, bad, rows


# ---------------------------------------------------------------- negative controls
MODEL_MUTANTS = ["dot_normal", "parent_normal", "parse_no_start", "parse_first_sep", "parse_extra_zero",
                 "trim_floor_zero", "body_to_prefix", "no_curdir"]
BYTE_MUTANTS = []   # filled by build_byte_mutants


def build_byte_mutants():
    """(va of the byte, expected old byte, new byte, description); old bytes are asserted before use."""
    return [
        (0x5c8e83a, 0x2e, 0x2f, "parse ..: first '.' test '.' -> '/'"),
        (0x5c8e803, 0x2f, 0x2e, "parse separator test '/' -> '.'"),
        (0x5c8e83e, 0x08, 0x09, "parse ParentDir kind 8 -> 9"),
        (0x5c8e826, 0x0a, 0x0b, "parse None kind 0xa -> 0xb"),
        (0x5c8e867, 0x09, 0x08, "parse Normal kind 9 -> 8"),
        (0x5c8e7ac, 0x01, 0x02, "parse root start 1 -> 2"),
        (0x5c8e861 + 2, 0x2e, 0x2f, "parse single-byte '.' test -> '/'"),
        (0x5c8e923, 0x2f, 0x2e, "as_path trim_left separator '/' -> '.'"),
        (0x5c8e94d, 0x01, 0x02, "as_path trim_left single piece length 1 -> 2"),
        (0x5c8e952, 0x2e, 0x2f, "as_path trim_left '.' test -> '/'"),
        (0x5c8e98e, 0x02, 0x03, "as_path trim_right floor 2 -> 3"),
        (0x5c8e8f6, 0x02, 0x03, "as_path front Body 2 -> 3"),
        (0x5c8e976, 0x02, 0x03, "as_path back Body 2 -> 3"),
        (0x5c8e984, 0x00, 0x01, "as_path has_root 0 -> 1 test"),
        (0x5cab57d, 0x03, 0x02, "next_back front Done 3 -> 2"),
        (0x5cab57a, 0x0a, 0x0b, "next_back None kind 0xa -> 0xb"),
        (0x5cab8cc, 0x07, 0x06, "next_back CurDir kind 7 -> 6"),
        (0x5cab8e8, 0x06, 0x07, "next_back RootDir kind 6 -> 7"),
        (0x5cab73d, 0x2e, 0x2f, "next_back cur-dir '.' test -> '/'"),
        (0x5cab8ab, 0x2e, 0x2f, "next_back StartDir cur-dir '.' test (len>=2) -> '/'"),
        (0x5cab8b5, 0x2f, 0x2e, "next_back StartDir cur-dir second byte '/' -> '.'"),
        (0x5cab5aa, 0x01, 0x00, "next_back front<=1 test 1 -> 0"),
        (0x5cab5ac, 0x87, 0x86, "next_back ja -> jbe on front>1"),
        (0x5cab5c3, 0x84, 0x85, "next_back has_root je -> jne"),
        (0x5cab5ca, 0x75, 0x74, "next_back finished jne -> je"),
        (0x5cab5b2, 0x03, 0x02, "next_back back Done 3 -> 2"),
        (0x5cab5d1, 0x01, 0x02, "next_back back StartDir 1 -> 2"),
        (0x5cab5dd, 0x02, 0x01, "next_back back Body 2 -> 1"),
        (0x5cab89b, 0x01, 0x02, "next_back StartDir cur-dir len 1 -> 2"),
        (0x5cab8bf, 0x01, 0x00, "next_back CurDir shrink by 1 -> 0"),
        (0x5cab8df, 0x01, 0x00, "next_back RootDir shrink by 1 -> 0"),
        (0x5c8e9b1, 0x0a, 0x09, "as_path trim_right stop kind 0xa -> 9"),
    ]


def controls(image, cases):
    rows = []
    for name in MODEL_MUTANTS:
        _, bad, _ = evaluate(image, cases, mut=frozenset([name]), stop_on_first=True)
        rows.append(("model", name, int(bad > 0)))
    for va, old, new, what in build_byte_mutants():
        if image.code(va, 1)[0] != old:
            fail(f"byte mutant at {va:#x}: expected {old:#04x}, found {image.code(va, 1)[0]:#04x}")
        _, bad, _ = evaluate(image, cases, override={va: new}, stop_on_first=True)
        rows.append(("code", f"{va:#x}={new:#04x} {what}", int(bad > 0)))
    corrupt = bytearray(image.data)
    corrupt[image.text["offset"] + 5] ^= 1
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


# ---------------------------------------------------------------- output
def generate(out):
    image = Image(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    cases = all_cases()
    sites = site_table(image)
    total, bad, rows = evaluate(image, cases)
    classes = {}
    lines = ["case\tentry\tclass\tfront\tback\troot\tpath_hex\tresult\tmatch"]
    for i, case, ok, text in rows:
        kind, path, front, back, root, _, tag = case
        key = kind + "/" + tag + "/" + text.split(" ")[0].split("=")[0].split(":")[0]
        classes[key] = classes.get(key, 0) + 1
        lines.append(f"{i}\t{kind}\t{tag}\t{front}\t{back}\t{root}\t{path.hex() or '-'}\t{text}\t{'yes' if ok else 'NO'}")
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "outcome-classes.tsv").write_text(
        "class\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    (out / "panic-sites.tsv").write_text(
        "name\tcall_va\tlea_va\tlocation_va\n" + "".join(f"{n}\t{c:#x}\t{l:#x}\t{loc:#x}\n" for n, c, l, loc in sites))
    ctl = controls(image, cases)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    detected = sum(r[2] for r in ctl)
    measure = {"cases": total, "negative_controls": len(ctl), "negative_detected": detected, "mismatches": bad}
    (out / "measure.json").write_text(json.dumps(measure, indent=2, sort_keys=True) + "\n")
    summary = dict(measure, binary_sha256=SHA256)
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
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
    bad = summary["mismatches"] or summary["negative_detected"] != summary["negative_controls"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
