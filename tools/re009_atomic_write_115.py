"""Reconstruct the node #115 ensure-directory and atomic-write helpers (RE-009 state/storage output).

Two real bodies are run in the shared evaluator of tools/decimal_scaled_u64.py with every callee
replaced by a logging stub whose answer the case chooses:

* 0x15020f0 `ensure_dir(path)`: normalise the path through three opaque callees, return when it
  exists, otherwise create it with mode 0x1ff and recursive=1 and hand back the error word.
* 0x15024a0 `write_atomic(content, path)`: build a temporary name, write the content there, then
  make sure the parent of the target exists and finally move the temporary file onto the target.

`ensure_model` and `write_model` are independently written Python reconstructions. The tool compares
the return word and the ordered callee log (callee role plus the argument values the body passed)
for every case, flips every reached conditional jump and every compare/store immediate of both
bodies, and runs deliberately wrong reconstructions as negative controls. The target is read, never
executed. Every number in the output comes from ELF bytes or from these runs.
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
ENSURE, WRITE = 0x15020F0, 0x15024A0
BODIES = (ENSURE, WRITE)
FMT_CALLBACK = 0x14FCB40   # fn pointer the write body stores beside the format argument
FMT_PIECES = 0x44B7F0      # rodata pointer handed to the formatter stub

# slot -> role. The slot value is the relocated target the body calls through.
SLOTS = {0x64E0938: "A", 0x64E09B0: "B", 0x64DFCA8: "C", 0x64E0928: "D", 0x64E0940: "E",
         0x64E0978: "S1", 0x64DF6E8: "S2", 0x64DF4A0: "free", 0x64E09F0: "S3", 0x64E09F8: "S4",
         0x64E0A00: "S5"}
DIRECT = {0x1500B90: "F", 0x15026E0: "W"}

PATH, DIR, CONTENT, TMP, FMT = (cpu.INPUT + i * 0x1000 for i in range(5))
ENTRY_SP = cpu.STACK - 0x800
STEP_LIMIT = 4000


class Fail(Exception):
    pass


def load_image():
    data = TARGET.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise Fail(f"target digest {digest} != {SHA256}")
    image = cpu.Image(data)
    ROLES.update(role_table(image))
    return image


ROLES = {}


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
    """Direct and slot calls of a body in byte order: (site, kind, target, role)."""
    rows = []
    for insn in body_insns(image, start)[2]:
        if insn.key == 0xE8:
            rows.append((insn.va, "call", insn.target, DIRECT.get(insn.target, "?")))
        elif insn.key == 0xFF and (image.data[insn.modrm] >> 3) & 7 == 2:
            slot = slot_of(image, insn)
            if slot is not None:
                rows.append((insn.va, "slot_call", image.slots.get(slot, 0), SLOTS.get(slot, "?")))
    return rows


def jcc_sites(image, start):
    rows = []
    for insn in body_insns(image, start)[2]:
        if isinstance(insn.key, int) and 0x70 <= insn.key <= 0x7F:
            rows.append((insn.va, insn.off + insn.size - 2))
        elif isinstance(insn.key, tuple) and len(insn.key) == 2 and 0x80 <= insn.key[1] <= 0x8F:
            rows.append((insn.va, insn.off + insn.size - 5))
    return rows


def imm_sites(image, start):
    """Compare immediates and constant stores: (va, byte offset of the low immediate byte)."""
    data, rows = image.data, []
    for insn in body_insns(image, start)[2]:
        key = insn.key
        if not isinstance(key, int):
            continue
        reg = (data[insn.modrm] >> 3) & 7 if insn.modrm is not None else None
        stack_adjust = insn.modrm is not None and data[insn.modrm] >> 6 == 3
        if key in (0x80, 0x83) and reg == 7 and not stack_adjust:
            rows.append((insn.va, insn.off + insn.size - 1))
        elif key == 0xC6:
            rows.append((insn.va, insn.off + insn.size - 1))
        elif key == 0xC7:
            rows.append((insn.va, insn.off + insn.size - (2 if insn.wide16 else 4)))
        elif key < 0x40 and key & 7 == 4 and key >> 3 in (0, 7):
            rows.append((insn.va, insn.off + insn.size - 1))
    return rows


def role_table(image):
    roles = {}
    for slot, role in SLOTS.items():
        roles[role] = image.slots[slot]
    for target, role in DIRECT.items():
        roles[role] = target
    return roles


# ---------------------------------------------------------------- evaluator with stubs

class Machine(cpu.Machine):
    def __init__(self, image, case, roles):
        super().__init__(image)
        self.case, self.log = case, []
        self.by_target = {t: r for r, t in roles.items()}

    def call(self, target, where):
        role = self.by_target.get(target)
        if role is None:
            raise cpu.Done(f"unexpected call {target:#x}", where)
        a = [self.get(r, 64) for r in (cpu.RDI, cpu.RSI, cpu.RDX, cpu.RCX)]
        ret = getattr(self, "stub_" + role)(a)
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        if ret is not None:
            self.set_reg(cpu.RAX, ret)
        self.flags = [None, None, None, None]
        self.pc = where + self.image.fetch(where).size

    # opaque path normaliser A(out, req): req = {ptr, len, tag 6, word 0x201, absolute flag}
    def stub_A(self, a):
        req = a[1]
        self.log.append(("A", self.load(req, 8), self.load(req + 8, 8), self.mem.get(req + 0x10),
                         self.load(req + 0x38, 2), self.mem.get(req + 0x3A)))
        self.store(a[0], 1, self.case["tag"])

    def stub_B(self, a):
        self.log.append(("B",))
        return self.case["b"]

    def stub_C(self, a):
        self.log.append(("C", a[1]))
        self.store(a[0], 4, self.case["disc"])
        self.store(a[0] + 8, 8, self.case["dir_ptr"])
        self.store(a[0] + 16, 8, self.case["dir_len"])

    def stub_D(self, a):
        self.log.append(("D", a[0], a[1]))
        return int(self.case["exists"])

    def stub_E(self, a):
        self.log.append(("E", a[1], a[2], self.load(a[0], 4), self.mem.get(a[0] + 4)))
        return self.case["mk"]

    def stub_F(self, a):
        self.log.append(("F", a[1]))
        return self.case["fret"]

    def stub_S1(self, a):
        self.log.append(("S1",))
        self.store(a[0], 8, self.case["s1cap"])
        self.store(a[0] + 8, 8, TMP)

    def stub_S2(self, a):
        self.log.append(("S2", a[1], self.load(a[2] + 8, 8)))
        self.store(a[0], 8, self.case["s2cap"])
        self.store(a[0] + 8, 8, FMT)
        self.store(a[0] + 16, 8, self.case["s2len"])

    def stub_free(self, a):
        self.log.append(("free", a[0], a[1], a[2]))

    def stub_S3(self, a):
        self.log.append(("S3", a[1], a[2]))
        self.store(a[0], 8, self.case["tcap"])
        self.store(a[0] + 8, 8, TMP + 0x100)
        self.store(a[0] + 16, 8, self.case["tlen"])

    def stub_S4(self, a):
        self.log.append(("S4", a[0], a[1], a[2], a[3]))
        return self.case["s4"]

    def stub_W(self, a):
        self.log.append(("W", a[2], self.load(a[1], 8), self.load(a[1] + 8, 8)))
        return self.case["wret"]

    def stub_S5(self, a):
        self.log.append(("S5", a[0], a[1], a[2], a[3]))
        return self.case["s5"]


def setup(m, start, case):
    for reg in range(16):
        m.set_reg(reg, 0x0BAD_0000 + reg * 0x100)
    path = case["path"]
    for i, b in enumerate(path + b"/"):     # the byte past the end must never count as part of the path
        m.store(PATH + i, 1, b)
    m.store(DIR, 8, 0)
    m.set_reg(cpu.RSP, ENTRY_SP)
    m.store(ENTRY_SP, 8, cpu.RETURN_MARK)
    if start == ENSURE:
        m.set_reg(cpu.RDI, PATH)
        m.set_reg(cpu.RSI, len(path))
    else:
        m.set_reg(cpu.RDI, CONTENT)
        m.set_reg(cpu.RSI, case["clen"])
        m.set_reg(cpu.RDX, PATH)
        m.set_reg(cpu.RCX, len(path))


def run_body(image, start, case, seen=None):
    m = Machine(image, case, ROLES)
    setup(m, start, case)
    try:
        m.pc = start
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
    return ("ret", m.get(cpu.RAX, 64), tuple(m.log))


# ---------------------------------------------------------------- the reconstructions

def _abs(path, variant):
    if variant == "abs_ignores_len":
        return int(path[:1] == b"/" or not path)
    return int(len(path) != 0 and path[0] == 0x2F)


def normalise(case, path, log, variant):
    """The shared front half: returns the directory the body will test (ptr, len)."""
    absolute = _abs(path, variant)
    if variant == "abs_always_zero":
        absolute = 0
    log.append(("A", PATH, len(path), 6, 0x201, absolute))
    lo, hi = (7, 9) if variant != "tag_range_wide" else (7, 10)
    cur = (PATH, len(path))
    if lo <= case["tag"] <= hi and variant != "skip_normalise":
        log.append(("B",))
        if case["b"]:
            log.append(("C", case["b"]))
            take = case["disc"] != 1
            if variant == "keep_on_disc0":
                take = case["disc"] == 1
            if variant == "disc_ignored":
                take = True
            if take:
                cur = (case["dir_ptr"], case["dir_len"])
    return cur


def make_dir(case, cur, log, variant):
    """exists check, then mkdir mode 0x1ff recursive. Returns (done_ok, error word)."""
    log.append(("D", cur[0], cur[1]))
    if case["exists"] and variant != "no_exists_check":
        return True, 0
    mode = 0x1FE if variant == "mode_0x1fe" else 0x1FF
    log.append(("E", cur[0], cur[1], mode, 1))
    if case["mk"] == 0 or variant == "mk_error_ignored":
        return True, 0
    log.append(("F", case["mk"]))
    return False, case["fret"]


def ensure_model(case, variant=None):
    log = []
    path = case["path"]
    cur = normalise(case, path, log, variant)
    ok, word = make_dir(case, cur, log, variant)
    if variant == "error_word_one" and not ok:
        word = 1
    return ("ret", word, tuple(log))


def write_model(case, variant=None):
    log = []
    path = case["path"]
    log.append(("S1",))
    log.append(("S2", FMT_PIECES, FMT_CALLBACK))
    if case["s1cap"] and variant != "skip_free_first":
        log.append(("free", TMP, case["s1cap"], 0))
    log.append(("S3", FMT, case["s2len"]))
    if case["s2cap"]:
        log.append(("free", FMT, case["s2cap"], 0))
    log.append(("S4", TMP + 0x100, case["tlen"], CONTENT, case["clen"]))
    word = case["s4"]
    if word and variant != "write_error_ignored":
        log.append(("W", word, PATH, len(path)))
        word = case["wret"]
    else:
        cur = normalise(case, path, log, variant)
        ok, word = make_dir(case, cur, log, variant)
        if ok or variant == "rename_after_mk_error":
            if variant == "rename_dir_path":
                target = cur
            else:
                target = (PATH, len(path))
            log.append(("S5", TMP + 0x100, case["tlen"], target[0], target[1]))
            word = case["s5"]
    if case["tcap"] and variant != "no_free_temp":
        log.append(("free", TMP + 0x100, case["tcap"], 0))
    return ("ret", word, tuple(log))


MODELS = {ENSURE: ensure_model, WRITE: write_model}
ENSURE_VARIANTS = ("abs_ignores_len", "abs_always_zero", "tag_range_wide", "keep_on_disc0", "disc_ignored",
                   "skip_normalise", "no_exists_check", "mode_0x1fe", "mk_error_ignored", "error_word_one")
WRITE_VARIANTS = ("skip_free_first", "write_error_ignored", "rename_after_mk_error", "rename_dir_path",
                  "no_free_temp", "skip_normalise", "keep_on_disc0", "no_exists_check")
VARIANTS = {ENSURE: ENSURE_VARIANTS, WRITE: WRITE_VARIANTS}


# ---------------------------------------------------------------- cases

PATHS = (b"/a/b", b"a/b", b"/", b"x", b"//x/y/", b"a")
ERR = 0x7700_0000_0000_0011


def base_case(**kw):
    case = {"path": b"/a/b", "tag": 6, "b": 0, "disc": 0, "dir_ptr": DIR, "dir_len": 3, "exists": 0, "mk": 0,
            "fret": 0x55, "s1cap": 0, "s2cap": 0, "s2len": 5, "tcap": 0, "tlen": 9, "s4": 0, "wret": 0x66,
            "s5": 0, "clen": 7}
    case.update(kw)
    return case


def ensure_cases():
    for path in PATHS + (b"",):
        for tag in (0, 1, 5, 6, 7, 8, 9, 10, 11, 15, 250):
            for b in (0, 0x7400_0000):
                for disc in (0, 1, 2):
                    for exists in (0, 1):
                        for mk in (0, ERR):
                            for fret, dp, dl in ((0x55, DIR, 3), (0x6000_0001, DIR + 0x40, 0)):
                                yield base_case(path=path, tag=tag, b=b, disc=disc, exists=exists, mk=mk,
                                                fret=fret, dir_ptr=dp, dir_len=dl)
    for tag in range(256):          # every tag byte once through the 7..9 window test
        yield base_case(tag=tag, b=0x7400_0000, disc=0)
    yield base_case(path=b"/a/b" * 4, tag=7, b=1, disc=2, dir_ptr=PATH + 4, dir_len=0xFFFF_FFFF_FFFF_FFFF)


def write_cases():
    for path in (b"/a/b", b"a/b", b"/", b"a", b"//x/y/"):
        for s1cap in (0, 5):
            for s2cap in (0, 9):
                for tcap in (0, 12):
                    for s4 in (0, ERR):
                        for tag in (6, 7, 8, 9, 10):
                            for b in (0, 0x7400_0000):
                                for disc in (0, 1, 2):
                                    for exists in (0, 1):
                                        for mk in (0, ERR):
                                            for s5 in (0, 0x3300_0001):
                                                if s4 and (tag != 6 or b or disc or exists or mk or s5):
                                                    continue
                                                yield base_case(path=path, s1cap=s1cap, s2cap=s2cap,
                                                                tcap=tcap, s4=s4, tag=tag, b=b, disc=disc,
                                                                exists=exists, mk=mk, s5=s5,
                                                                dir_ptr=DIR + 8, dir_len=2 if disc else 1)
    for clen in (0, 1, 0xFFFF_FFFF_FFFF_FFFF):
        for tlen in (0, 0xFFFF_FFFF):
            yield base_case(clen=clen, tlen=tlen, s2len=tlen)


CASE_GEN = {ENSURE: ensure_cases, WRITE: write_cases}


def describe(case):
    return "\t".join([
        case["path"].decode(), str(case["tag"]), "1" if case["b"] else "0", str(case["disc"]),
        str(case["exists"]), "ok" if case["mk"] == 0 else "err", f"{case['fret']:#x}", str(case["s1cap"]),
        str(case["s2cap"]), str(case["tcap"]), "ok" if case["s4"] == 0 else "err",
        "ok" if case["s5"] == 0 else "err", str(case["clen"])])


def outcome(result):
    if result[0] != "ret":
        return result[0]
    return f"{result[1]:#x}/" + ",".join(row[0] for row in result[2])


def mutated(image, off):
    data = bytearray(image.data)
    data[off] ^= 1
    out = copy.copy(image)
    out.data, out.cache = bytes(data), {}
    return out


def generate(out_dir, sample_every=12):
    image = load_image()
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {"target_sha256": SHA256, "bodies": {}}
    case_lines = ["#\tbody\tpath\ttag\tb\tdisc\texists\tmkdir\tmkdir_word\ts1cap\ts2cap\ttmpcap\twrite\trename\t"
                  "content_len\toutcome(word/calls)\tverdict"]
    mut_lines = ["body\tkind\tva\tfile_offset_flipped\tverdict\tfirst_killing_case"]
    var_lines = ["body\tvariant\tcaught_cases\tfirst_case"]
    call_lines = ["body\tsite\tkind\ttarget\trole"]
    total = mismatches = 0
    neg_total = neg_detected = 0
    for start in BODIES:
        lo, hi, insns = body_insns(image, start)
        model = MODELS[start]
        counts, digest, seen = {}, hashlib.sha256(), set()
        # killers: for each negative control remember the first killing case index
        var_first = {v: [0, None] for v in VARIANTS[start]}
        sample = []                       # one case per distinct outcome, for the mutation runs
        sample_keys = set()
        n = 0
        for case in CASE_GEN[start]():
            got = run_body(image, start, case, seen)
            want = model(case)
            ok = got == want
            mismatches += not ok
            key = outcome(got)
            counts[key] = counts.get(key, 0) + 1
            digest.update(key.encode() + b"\n")
            for v in VARIANTS[start]:
                if model(case, v) != got:
                    var_first[v][0] += 1
                    if var_first[v][1] is None:
                        var_first[v][1] = n
            if (key, case["tag"]) not in sample_keys:
                sample_keys.add((key, case["tag"]))
                sample.append((n, case, got))
            if n % sample_every == 0 or not ok:
                case_lines.append(f"{n}\t{start:#x}\t" + describe(case) + "\t" + key + "\t" + ("match" if ok else "MISMATCH"))
            n += 1
        total += n
        for v, (caught, first) in var_first.items():
            var_lines.append(f"{start:#x}\t{v}\t{caught}\t{'-' if first is None else first}")
            neg_total += 1
            neg_detected += caught > 0
        reached = {i.va for i in insns if i.va in seen}
        for kind, sites in (("jcc", jcc_sites(image, start)), ("imm", imm_sites(image, start))):
            for va, off in sites:
                mutant = mutated(image, off)
                killer = None
                for idx, case, real in sample:
                    if run_body(mutant, start, case) != real:
                        killer = idx
                        break
                if va not in reached:
                    verdict = "unreached"
                else:
                    verdict = "killed" if killer is not None else "survived"
                    neg_total += 1
                    neg_detected += killer is not None
                mut_lines.append(f"{start:#x}\t{kind}\t{va:#x}\t{off:#x}\t{verdict}\t{'-' if killer is None else killer}")
        for site, kind, target, role in call_rows(image, start):
            call_lines.append(f"{start:#x}\t{site:#x}\t{kind}\t{target:#x}\t{role}")
        summary["bodies"][f"{start:#x}"] = {
            "fde": [f"{lo:#x}", f"{hi:#x}"], "instructions": len(insns), "cases": n,
            "instructions_reached": len(reached), "outcomes": len(counts), "result_digest": digest.hexdigest()}
    # static negative controls: wrong digest, non-start address, address outside every FDE
    for label, check in (("digest", lambda: _digest_control()), ("non_start", lambda: _non_start(image)),
                         ("outside_fde", lambda: _outside(image))):
        neg_total += 1
        neg_detected += check()
        var_lines.append(f"static\t{label}\t1\t-")
    summary["cases"] = total
    summary["negative_controls"] = neg_total
    summary["negative_detected"] = neg_detected
    summary["mismatches"] = mismatches
    (out_dir / "cases.tsv").write_text("\n".join(case_lines) + "\n")
    (out_dir / "mutants.tsv").write_text("\n".join(mut_lines) + "\n")
    (out_dir / "variants.tsv").write_text("\n".join(var_lines) + "\n")
    (out_dir / "calls.tsv").write_text("\n".join(call_lines) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out_dir / "measure.json").write_text(json.dumps(
        {"cases": total, "negative_controls": neg_total, "negative_detected": neg_detected}, indent=1) + "\n")
    return summary


def _digest_control():
    global SHA256
    saved, SHA256 = SHA256, "0" * 64
    try:
        load_image()
    except Fail:
        return True
    finally:
        SHA256 = saved
    return False


def _non_start(image):
    try:
        body_insns(image, ENSURE + 4)
    except Fail:
        return True
    return False


def _outside(image):
    try:
        body_insns(image, 0x10)
    except cpu.ToolError:
        return True
    return False


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)
    try:
        s = generate(args.out)
    except Fail as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    print(json.dumps({k: s[k] for k in ("cases", "mismatches", "negative_controls", "negative_detected")}))
    good = s["mismatches"] == 0 and s["negative_controls"] == s["negative_detected"]
    return 0 if good else 2


if __name__ == "__main__":
    sys.exit(main())
