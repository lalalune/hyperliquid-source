"""Extend the rmp-serde `newtype(Vec<T>)` reconstruction of node #115 to the bodies the first packet left out.

`RE-015-rmp-seq-newtype-115` modelled 54 six-call bodies and listed 66 further `_ExtStruct` family members as
"other-shape" without testing them. This tool re-derives the six-call shape (header writer, element, element,
Compound::end, element, compound element), the single element stride, the four `.got` calls and the ext-arm text from
the bytes of every one of those members, keeps the ones that pass `body_facts` (33 of 66; the rest are listed with the
reason), and runs the same reconstruction on them with recording element stubs (part A).

Six of the new bodies walk 8-byte elements through the in-binary MessagePack unsigned writers. For those the tool also
runs the real writers (part B), so the whole array is checked byte for byte: header, smallest-form unsigned tags,
payload byte order, the compound counter, the buffered copy and the error hand-back.

The binary is never executed; the reconstruction is `seq.model` (part A) and `model_b` (part B).
"""
import argparse
import hashlib
import itertools
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re015_rmp_seq_newtype_115 as seq  # noqa: E402
import re015_rmp_vecdeque_u64_115 as vd  # noqa: E402

BINARY = seq.BINARY
SHA256 = seq.SHA256
M64 = seq.M64
ERRORS = (seq.ToolError, vd.ToolError)

# the in-binary rmp `write_uint` copies that the stride-8 bodies call: layout a, layout b direct (finish_grow inlined)
UINT_WRITERS = (0x25e9f10, 0x25e9c70, 0x3d51450, 0x3d517e0, 0x57cfd20, 0x57d00b0)
PER_BODY = 400
PER_UINT = 600
SMALL_N = seq.SMALL_N
EDGE_N = seq.EDGE_N
# the 0xdc/0xdd array-header bound is reached with a fault at element 1..3, so no 64 Ki-element walk is needed
EDGE_B = (0xffff, 0x10000, 0x10001) + tuple(EDGE_N)
VALS = vd.VALS


def fail(message):
    raise seq.ToolError(message)


# ---------------------------------------------------------------- discovery from bytes
def discover(image, ext):
    """Split the first packet's other-shape members into bodies that pass `body_facts` and the rest."""
    merged = dict(seq.BODIES)
    scan = seq.family_scan(image, ext)
    wide, skipped, order = {}, {}, []
    for va, size, fl, ncalls, status in scan:
        order.append((va, size, fl, ncalls, status))
        if status != "other-shape":
            continue
        if "," in fl:
            skipped[va] = "members of two copy families"
            continue
        fam, layout = fl.split("/")
        insns = seq.sweep(image, va, ext[va])
        adds = {f["imm"] for _, f in insns if f["op"] in (0x81, 0x83) and f["reg"] & 7 == 0 and f["rm"][0] == "r"}
        strides = sorted(a for a in adds if a > 0 and -a in adds)
        if len(strides) != 1:
            skipped[va] = f"{len(strides)} candidate strides"
            continue
        seq.BODIES[va] = (fam, layout, strides[0])
        try:
            seq.body_facts(image, ext, va)
            wide[va] = (fam, layout, strides[0])
        except seq.ToolError as exc:
            skipped[va] = str(exc).split(" ", 2)[2]
        finally:
            del seq.BODIES[va]
    return merged, wide, skipped, order


def split_abi(image, ext, wide, by, ub):
    """A body whose element callee does not take (slot, &element, serializer) cannot run on the recording stubs:
    twelve probe cases per body, the stub contract check raising is the reason to leave the body out."""
    abi = {}
    saved = dict(seq.BODIES)
    try:
        for va in sorted(wide):
            if va in ub:
                continue
            seq.BODIES.clear()
            seq.BODIES[va] = wide[va]
            try:
                seq.evaluate(image, ext, [by[va]], seq.all_cases(12))
            except seq.ToolError as exc:
                abi[va] = str(exc).split(" with ")[0].split(" called")[0] + " ABI differs"
    finally:
        seq.BODIES.clear()
        seq.BODIES.update(saved)
    return abi


# ---------------------------------------------------------------- part B: real unsigned-integer element writers
class BMachine(vd.CaseMachine):
    """Logs every call of an element writer (value, serializer kind, compound state) before the real bytes run."""

    def transfer(self, target, call, va):
        if call and target in self.uints:
            comp = self.regs[6]
            if comp == vd.SER_AT:
                self.events.append(("wu", self.regs[2], "ser"))
            elif vd.STACK_TOP - 0x10000 <= comp < vd.STACK_TOP:
                self.events.append(("wu", self.regs[2], "cmp", self.load(comp + 0x20, 4), self.load(comp + 0x10, 8),
                                    self.load(comp + 0x18, 8)))
            else:
                fail("element writer called with a foreign serializer")
            if self.next_fault():
                self.fail_result()
                return None
        return super().transfer(target, call, va)


def model_b(c, row, mut=frozenset()):
    """Predicted (appended bytes, result words or None for Ok, ordered events, boundary) of one stride-8 body case."""
    p = {"out": b"", "result": None, "events": [], "boundary": None}
    if vd.is_ext(c["name"], mut):
        p["result"] = (vd.EXT_TAG if "ext-tag" not in mut else vd.ERR_TAG, row["msg"][0],
                       row["msg"][1] + (1 if "msg-len" in mut else 0))
        return p
    n, words, ev, k = c["n"], c["words"], p["events"], [0]

    def hit():
        h = c["fault"] == k[0]
        k[0] += 1
        return h

    def word(i):
        if i >= len(words):
            fail("case reads past its element words")
        return words[i]

    count = seq.iterations(n, 8, mut)
    walk = range(count) if count is not None else itertools.count()
    err = (vd.ERR_TAG if "wu-err-tag" not in mut else vd.EXT_TAG, vd.FAULT[0], vd.FAULT[1])
    if not seq.buffered(n, mut):
        ev.append(("hdr", n & 0xffffffff))
        if hit():
            p["result"] = (vd.ERR_TAG if "hdr-err-tag" not in mut else vd.EXT_TAG, vd.FAULT[0], vd.FAULT[1])
            return p
        vec = vd.VecSim(len(c["prefix"]) + c["room"], len(c["prefix"]), ev)
        vec.push(seq.mp_array(n, mut))
        for i in walk:
            w = word(i)
            ev.append(("wu", w, "ser"))
            if hit():
                p["result"] = err
                p["out"] = bytes(vec.out)
                return p
            vd.write_uint(vec, w, mut)
        p["out"] = bytes(vec.out)
        return p
    ev.append(("malloc", vd.BUF_CAP))
    if c["oom"]:
        p["boundary"] = ("alloc-error", 1, vd.BUF_CAP)
        return p
    cfg = vd.config_word(c["cfg"], mut)
    comp = vd.VecSim(vd.BUF_CAP, 0, ev)
    for i in walk:
        w = word(i)
        ev.append(("wu", w, "cmp", i, comp.ln, cfg))
        if hit():
            if "err-no-free" not in mut:
                ev.append(("free", comp.cap))
            p["result"] = err
            return p
        vd.write_uint(comp, w, mut)
    cnt = count + (1 if "count-plus1" in mut else 0)
    ev.append(("hdr", cnt))
    if hit():
        p["result"] = (vd.ERR_TAG, vd.FAULT[0], vd.FAULT[1])
        ev.append(("free", comp.cap))
        return p
    vec = vd.VecSim(len(c["prefix"]) + c["room"], len(c["prefix"]), ev)
    vec.push(seq.mp_array(cnt, mut))
    if comp.ln:
        vec.ensure(comp.ln)
    if "end-no-copy" not in mut:
        vec.push(bytes(comp.out))
    ev.append(("free", comp.cap))
    p["out"] = bytes(vec.out)
    return p


def machine_b(image, ext, override=None):
    m = BMachine(image, override)
    m.extents = ext
    return m


def run_case_b(m, c, row):
    m.reset()
    m.case = c
    layout = c["layout"]
    roles = {"hdrs": [row["hdr"]], "wus": [], "chains": []}
    vd.install(m, m.image, c, roles)
    m.uints = {row["direct"], row["compound"]}
    sreg, buf, ring = vd.serializer_regions(m, c, layout)
    out = m.add_region(vd.OUT_AT, 0x18, b"\x5a" * 0x18)
    for kk, v in zip(vd.SAVED_REGS, vd.SAVED):
        m.regs[kk] = v
    heap = m.add_region(vd.HEAP_AT, vd.HEAP_SIZE, b"")
    arg = bytearray(0x18)
    vd.put(arg, 0, 8, c["vcap"])
    vd.put(arg, 8, 8, vd.ELEM_AT)
    vd.put(arg, 0x10, 8, c["n"])
    areg = m.add_region(vd.ARG_AT, 0x18, bytes(arg))
    name = m.add_region(vd.NAME_AT, 0x40, c["name"] + bytes(0x40 - len(c["name"])))
    m.regs[7], m.regs[6], m.regs[2], m.regs[1], m.regs[8] = vd.OUT_AT, vd.SER_AT, vd.NAME_AT, len(c["name"]), vd.ARG_AT
    try:
        m.run(c["body"], limit=c.get("limit", 4_000_000))
    except vd.Boundary:
        pass
    vbase = vd.SER_AT if layout == "a" else vd.VEC_AT
    ln = m.load(vbase + 0x10, 8)
    return {"boundary": m.boundary, "out": bytes(buf[:ln]) if ln <= len(buf) else None,
            "tail_clean": ln <= len(buf) and (not any(buf[ln:]) or ln < len(c["prefix"])),
            "ptr": m.load(vbase + 8, 8), "cap": m.load(vbase, 8),
            "ser_rest": bytes(sreg[0x18:] if layout == "a" else sreg[8:]), "result": bytes(out),
            "ring_same": bytes(ring) == b"".join(w.to_bytes(8, "little") for w in c["words"]),
            "inputs_same": bytes(areg) == bytes(arg) and bytes(name[:len(c["name"])]) == c["name"],
            "regs_ok": [m.regs[kk] for kk in vd.SAVED_REGS] == list(vd.SAVED) and m.regs[4] == vd.STACK_TOP - 0x100,
            "events": list(m.events)}


def compare_b(c, want, got):
    if want["boundary"] is not None or got["boundary"] is not None:
        return None if got["boundary"] == want["boundary"] and got["events"] == want["events"] else "boundary"
    if not got["regs_ok"] or not got["ring_same"] or not got["tail_clean"] or got["out"] is None \
            or not got["inputs_same"]:
        return "machine"
    if got["ser_rest"] != c["cfg"] + c["ser_tail"][:3] or got["ptr"] != vd.BUF_AT or got["cap"] < len(got["out"]):
        return "serializer"
    if got["events"] != want["events"]:
        return "events"
    if got["out"] != c["prefix"] + want["out"]:
        return "bytes"
    res = want["result"]
    expect = vd.OK_TRIPLE.to_bytes(8, "little") + b"\x5a" * 0x10 if res is None \
        else b"".join(x.to_bytes(8, "little") for x in res)
    return None if got["result"] == expect else "result"


def evaluate_b(image, ext, rows, cases, mut=frozenset(), override=None, stop_on_first=False):
    m = machine_b(image, ext, override)
    results, bad = [], []
    for c in cases:
        row = rows[c["body"]]
        try:
            got = run_case_b(m, c, row)
        except ERRORS:
            if override is None:
                raise
            got = None
        why = compare_b(c, model_b(c, row, mut), got) if got is not None else "tool-error"
        results.append((c, got, why))
        if why:
            bad.append((c, why))
            if stop_on_first:
                break
    return results, bad


def word_pool(stream, k, count):
    out = []
    for i in range(count):
        sel = (k + i) % 4
        if sel == 0:
            out.append(VALS[stream.below(len(VALS))])
        elif sel == 1:
            out.append(int.from_bytes(stream.take(8), "little") >> stream.below(64))
        elif sel == 2:
            out.append(((1 << stream.below(65)) - 1 + stream.below(3) - 1) & M64)
        else:
            out.append(int.from_bytes(stream.take(8), "little"))
    return out


def make_case_b(stream, va, layout, k, row):
    c = {"body": va, "layout": layout, "k": k, "kind": "body", "prefix": stream.take(stream.below(6)),
         "ser_tail": stream.take(8), "cfg": seq.CFG_BYTES[(k // 3) % len(seq.CFG_BYTES)] if k % 5 else stream.take(5),
         "fault": None, "oom": False, "name": seq.names(stream, k), "vcap": int.from_bytes(stream.take(8), "little")}
    sel = (k // 8) % 10
    if sel < 5:
        c["n"] = SMALL_N[(k // 2) % len(SMALL_N)]
    elif sel < 7:
        c["n"] = seq.wrap_len(8, 1 + stream.below(40), k)
    elif sel == 7:
        c["n"] = EDGE_B[((k // 80) * 8 + k % 80 - 56) % len(EDGE_B)]
        c["fault"] = 1 + stream.below(3) if c["n"] >> 32 == 0 else stream.below(3)
    elif sel == 8:
        c["n"] = seq.wrap_len(8, 1 + stream.below(3), k)
        c["oom"] = (k // 80) % 2 == 0
    else:
        c["n"] = stream.below(70)
    count = seq.iterations(c["n"], 8)
    have = 8 if (count is None or count > 400) else max(count, 1)
    c["words"] = word_pool(stream, k, have)
    c["room"] = 16 + 9 * have + stream.below(48)
    c["errw"] = 0
    if c["fault"] is None and (k // 4) % 3 == 1:
        events = model_b(dict(c, fault=None), row)["events"]
        nf = sum(1 for e in events if e[0] in ("hdr", "wu"))
        if nf:
            c["fault"] = stream.below(nf)
    return c


def all_cases_b(rows, layouts, per_body=PER_UINT):
    out = []
    for va in sorted(rows):
        stream = vd.Stream(f"rmp-seq-wide/uint/{va:#x}")
        for k in range(per_body):
            out.append(make_case_b(stream, va, layouts[va], k, rows[va]))
    return out


IMM8_OPS = (0x80, 0x83, 0xc6, 0x3c)
IMM32_OPS = (0x81, 0xc7, 0x3d)
SITE_IMMS = (0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xcc, 0xcd, 0xce, 0xcf)


def writer_sites(image, ext, writers):
    """Flip-able immediates (width thresholds, tag bytes) in the real element writers, low byte of each."""
    sites = []
    for va in sorted(writers):
        prev = None
        for v, f in vd.sweep(image, va, ext[va]):
            before, prev = prev, f
            imm = f.get("imm")
            if imm is None or (imm & 0xffffffff) not in SITE_IMMS and (imm & 0xff) not in (0xcc, 0xcd, 0xce, 0xcf):
                continue
            size = 1 if f["op"] in IMM8_OPS else 4 if f["op"] in IMM32_OPS else None
            if size is None:
                continue
            raw = image.code(v, f["len"])
            if int.from_bytes(raw[-size:], "little") != imm & ((1 << (8 * size)) - 1):
                continue
            # `mov [slot+8], 0xcc..0xcf` stores the Ok(Marker) result byte (word 0 = 2 is the Ok tag) that the
            # bodies discard
            marker = (f["op"] in (0xc6, 0xc7) and f["rm"][0] == "m" and f["rm"][4] == 8
                      and (imm & 0xffffffff) in (0xcc, 0xcd, 0xce, 0xcf))
            sites.append((va, f"imm{imm & 0xffffffff:#x}" + ("-ok-marker" if marker else ""), v + f["len"] - size,
                          0x01))
    return sites


B_MUTANTS = ("arr-fix17", "arr16-limit", "hdr-u16", "ext-prefix", "ext-tag", "msg-len", "cfg-nomask", "split-31",
             "count-plus1", "end-no-copy", "err-no-free", "hdr-err-tag", "wu-err-tag", "uint-80", "uint-100",
             "uint-10000", "uint-2e32")


def controls_b(image, ext, rows, results, writers):
    by = rows
    gots = [(c, got) for c, got, _ in results]
    out, undetected = [], []
    for name in B_MUTANTS:
        hit = None
        for i, (c, got) in enumerate(gots):
            if compare_b(c, model_b(c, by[c["body"]], frozenset({name})), got):
                hit = i
                break
        out.append(("uint-model", name, hit))
    for va, label, at, bit in writer_sites(image, ext, writers):
        cases = [c for c, _, _ in results if rows[c["body"]]["direct"] == va or rows[c["body"]]["compound"] == va]
        _, bad = evaluate_b(image, ext, rows, cases[::2], override={at: image.code(at, 1)[0] ^ bit}, stop_on_first=True)
        hit = cases[::2].index(bad[0][0]) if bad else None
        (out if hit is not None else undetected).append(("uint-bytes", f"{label}@{at:#x}", hit))
    for _, name, _ in undetected:  # only the returned Marker byte may be unobservable from the body
        if "-ok-marker@" not in name:
            fail(f"writer byte flip {name} is not detected")
    return out, undetected


# ---------------------------------------------------------------- generation
def hexs(b):
    return b.hex() if b else "-"


def generate(out, per_body=PER_BODY, per_uint=PER_UINT):
    data = BINARY.read_bytes()
    image = seq.Image(data)
    vimage = vd.Image(data)
    ext = seq.extents(image)
    merged, wide, skipped, scan = discover(image, ext)
    if set(wide) & set(merged):
        fail("a body is in both sets")
    # part A ---------------------------------------------------------------
    seq.BODIES.clear()
    seq.BODIES.update(wide)
    rows_all = seq.static_rows(image, ext)
    by = {r["va"]: r for r in rows_all}
    # stride-8 bodies that load their elements and call the unsigned writers are checked in part B only: the
    # recording stubs never give the elements memory
    ub = {va: by[va] for va in sorted(wide) if wide[va][2] == 8 and by[va]["direct"] in UINT_WRITERS
          and by[va]["compound"] in UINT_WRITERS}
    abi = split_abi(image, ext, wide, by, ub)
    for va in abi:
        skipped[va] = abi[va]
        del wide[va]
    rows_all = [r for r in rows_all if r["va"] in wide]
    seq.BODIES.clear()
    seq.BODIES.update({va: d for va, d in wide.items() if va not in ub})
    try:
        rows = [r for r in rows_all if r["va"] not in ub]
        sites = seq.byte_sites(image, ext)
        cases = seq.all_cases(per_body)
        results, bad = seq.evaluate(image, ext, rows, cases)
        if bad:
            c, why = bad[0]
            fail(f"{len(bad)} mismatches; first body {c['body']:#x} case {c['k']} ({why})")
        ctrl_a = seq.controls(image, ext, rows, results, sites)
        cov_a = seq.coverage(image, ext, rows, [c for c in cases[::3] if c.get("limit") is None])
        kinds = {}
        digest = hashlib.sha256()
        for c, got, _ in results:
            digest.update(got["out"] + got["result"])
            cm = seq.with_msg(c, by)
            p = seq.model(cm)
            if seq.is_ext(c["name"]):
                kind = "ext_error"
            elif p["boundary"]:
                kind = "alloc_error"
            elif seq.buffered(c["n"]):
                kind = "buffered_fault" if p["result"] else "buffered_ok"
            else:
                kind = "direct_fault" if p["result"] else "direct_ok"
            kinds[kind] = kinds.get(kind, 0) + 1
    finally:
        seq.BODIES.clear()
        seq.BODIES.update(merged)
    # part B ---------------------------------------------------------------
    layouts = {va: wide[va][1] for va in ub}
    writers = sorted({by[va]["direct"] for va in ub} | {by[va]["compound"] for va in ub})
    cases_b = all_cases_b(ub, layouts, per_uint)
    results_b, bad_b = evaluate_b(vimage, ext, ub, cases_b)
    if bad_b:
        c, why = bad_b[0]
        fail(f"{len(bad_b)} unsigned-writer mismatches; first body {c['body']:#x} case {c['k']} ({why})")
    ctrl_b, undet_b = controls_b(vimage, ext, ub, results_b, writers)
    # range controls -------------------------------------------------------
    ctrl_r = range_controls(image, ext, wide, merged)
    ctrl = [("wide-stub", n.replace("@", ":"), h) for _, n, h in ctrl_a] \
        + [("uint-real", n.replace("@", ":"), h) for _, n, h in ctrl_b] + ctrl_r
    # B coverage
    mm = machine_b(vimage, ext)
    seen = set()
    orig = mm.step

    def step(va):
        seen.add(va)
        return orig(va)

    mm.step = step
    for c in cases_b[::3]:
        run_case_b(mm, c, ub[c["body"]])
    cov_b = []
    for va in sorted(ub) + writers + sorted({ub[v]["hdr"] for v in ub}):
        insns = [v for v, _ in vd.sweep(vimage, va, ext[va])]
        cov_b.append((va, len(insns), sum(1 for v in insns if v in seen)))

    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    lines = ["body\tfde_end\tinstructions\tcopy_family\tlayout\tstride\tflag_offset\tconfig_offsets\theader_writer\t"
             "direct_element\tcompound_element\tcompound_end\text_message_at\text_message_len\telement_kind"]
    for r in rows_all:
        fam, layout, stride = wide[r["va"]]
        lines.append(f"{r['va']:#x}\t{r['end']:#x}\t{r['insns']}\t{fam}\t{layout}\t{stride:#x}\t{r['flag']:#x}\t"
                     f"{','.join(f'{o:#x}' for o in r['cfg_offsets']) or '-'}\t{r['hdr']:#x}\t{r['direct']:#x}\t"
                     f"{r['compound']:#x}\t{r['end_fn']:#x}\t{r['msg'][0]:#x}\t{r['msg'][1]}\t"
                     f"{'uint-real' if r['va'] in ub else 'stub'}")
    (out / "bodies.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tfde_size\tcopy_family_layout\tcompound_end_calls\tstatus"]
    for va, size, fl, ncalls, status in scan:
        st = "first-packet" if va in merged else "wide" if va in wide else "excluded" if status.startswith("excluded") \
            else "skipped: " + skipped[va]
        lines.append(f"{va:#x}\t{size}\t{fl}\t{ncalls}\t{st}")
    (out / "scan.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tcase\tname_hex\tlength\tconfig\tfault_event\toom\troom\tprefix\tout_len\tout_sha256\tresult\tevents\treserves"]
    for c, got, _ in results:
        if c["k"] % 8 not in (0, 3, 5, 6):
            continue
        evs = got["events"]
        short = ",".join(e[0][0] for e in evs[:12]) + ("+" + str(len(evs) - 12) if len(evs) > 12 else "")
        lines.append("\t".join([f"{c['body']:#x}", str(c["k"]), hexs(c["name"]), f"{c['n']:#x}", c["cfg"].hex(),
                                "-" if c["fault"] is None else str(c["fault"]), "1" if c["oom"] else "0",
                                str(c["room"]), hexs(c["prefix"]), str(len(got["out"])),
                                hashlib.sha256(got["out"]).hexdigest()[:16], got["result"].hex(), short or "-",
                                str(len(got["reserves"]))]))
    (out / "cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["body\tcase\tname_hex\tlength\tconfig\tfault_event\toom\tout_len\tout_sha256\tresult\twu_calls\tfirst_values"]
    for c, got, _ in results_b:
        if c["k"] % 8 not in (0, 3, 5):
            continue
        wus = [e for e in got["events"] if e[0] == "wu"]
        lines.append("\t".join([f"{c['body']:#x}", str(c["k"]), hexs(c["name"]), f"{c['n']:#x}", c["cfg"].hex(),
                                "-" if c["fault"] is None else str(c["fault"]), "1" if c["oom"] else "0",
                                str(len(got["out"])), hashlib.sha256(got["out"]).hexdigest()[:16], got["result"].hex(),
                                str(len(wus)), ",".join(f"{e[1]:#x}" for e in wus[:4]) or "-"]))
    (out / "uint-cases-sample.tsv").write_text("\n".join(lines) + "\n")

    lines = ["family\tcontrol\tdetected\tfirst_failing_case_index"]
    for fam, name, hit in ctrl:
        lines.append(f"{fam}\t{name}\t{'yes' if hit is not None else 'NO'}\t{'-' if hit is None else hit}")
    (out / "controls.tsv").write_text("\n".join(lines) + "\n")

    lines = ["writer\tcontrol\tnote"]
    for fam, name, hit in undet_b:
        lines.append(f"{name.split('@')[1]}\t{name.split('@')[0]}\tOk(Marker) result byte of write_uint; every body drops it")
    (out / "undetected-sites.tsv").write_text("\n".join(lines) + "\n")

    lines = ["function\trole\tinstructions\texecuted"]
    for va, n, hit in cov_a:
        lines.append(f"{va:#x}\t{'body' if va in wide else 'real-callee'}\t{n}\t{hit}")
    for va, n, hit in cov_b:
        role = "uint-body" if va in ub else "uint-writer" if va in writers else "real-callee"
        lines.append(f"{va:#x}\t{role}\t{n}\t{hit}")
    (out / "coverage.tsv").write_text("\n".join(lines) + "\n")

    digest_b = hashlib.sha256()
    kinds_b = {}
    for c, got, _ in results_b:
        digest_b.update(got["out"] + got["result"])
        p = model_b(c, ub[c["body"]])
        if vd.is_ext(c["name"]):
            kind = "ext_error"
        elif p["boundary"]:
            kind = "alloc_error"
        elif seq.buffered(c["n"]):
            kind = "buffered_fault" if p["result"] else "buffered_ok"
        else:
            kind = "direct_fault" if p["result"] else "direct_ok"
        kinds_b[kind] = kinds_b.get(kind, 0) + 1
    ncases = len(results) + len(results_b)
    summary = {
        "binary_sha256": SHA256,
        "first_packet_bodies": len(merged),
        "scan_members": len(scan),
        "wide_bodies": len(wide),
        "skipped_members": len(skipped),
        "uint_real_bodies": len(ub),
        "uint_writers": [f"{w:#x}" for w in writers],
        "body_instructions": sum(r["insns"] for r in rows),
        "body_instructions_executed": sum(h for v, _, h in cov_a if v in wide),
        "stub_cases": len(results),
        "uint_cases": len(results_b),
        "case_kinds_stub": dict(sorted(kinds.items())),
        "case_kinds_uint": dict(sorted(kinds_b.items())),
        "mismatches": 0,
        "outputs_sha256_stub": digest.hexdigest(),
        "outputs_sha256_uint": digest_b.hexdigest(),
        "controls": len(ctrl),
        "controls_detected": sum(1 for _, _, h in ctrl if h is not None),
        "uint_flip_sites_undetected": len(undet_b),
    }
    if summary["controls_detected"] != summary["controls"]:
        missed = [n for _, n, h in ctrl if h is None]
        fail(f"negative controls not detected: {missed}")
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps(
        {"cases": ncases, "negative_controls": summary["controls"], "negative_detected": summary["controls_detected"]},
        indent=2, sort_keys=True) + "\n")
    return summary


def range_controls(image, ext, wide, merged):
    """Bad declarations and a damaged binary must be refused."""
    out = []
    va = sorted(wide)[0]
    fam, layout, stride = wide[va]
    other_layout = "a" if layout == "b" else "b"
    other_fam = "419" if fam != "419" else "226"
    for label, decl in (("stride-wrong", (fam, layout, stride + 0x10)), ("layout-wrong", (fam, other_layout, stride)),
                        ("family-wrong", (other_fam, layout, stride))):
        seq.BODIES[va] = decl
        try:
            seq.body_facts(image, ext, va)
            out.append(("range", f"declared-{label}", None))
        except seq.ToolError:
            out.append(("range", f"declared-{label}", 0))
        finally:
            del seq.BODIES[va]
    seq.BODIES[va + 1] = (fam, layout, stride)
    try:
        seq.extents(image)
        out.append(("range", "body-not-fde-start", None))
    except seq.ToolError:
        out.append(("range", "body-not-fde-start", 0))
    finally:
        del seq.BODIES[va + 1]
    try:
        seq.Image(image.data[:-1] + bytes([image.data[-1] ^ 1]))
        out.append(("range", "binary-digest", None))
    except seq.ToolError:
        out.append(("range", "binary-digest", 0))
    # a first-packet body must never be re-listed as wide
    out.append(("range", "first-packet-body-relisted", 0 if not set(wide) & set(merged) else None))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-body", type=int, default=PER_BODY)
    ap.add_argument("--per-uint", type=int, default=PER_UINT)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out, args.per_body, args.per_uint)
    except ERRORS as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
