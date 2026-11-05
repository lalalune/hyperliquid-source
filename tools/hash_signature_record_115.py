"""Reconstruct the node #115 hash signature tracker record path (abci, RE-017/RE-009).

The two bodies at 0x27606d0 and 0x2760bc0 carry the `l1/src/abci/hash_signature_tracker.rs`
Locations for lines 107 and 123. This tool runs their real instruction bytes in the
shared evaluator of tools/decimal_scaled_u64.py with every callee replaced by a logging
stub, and compares the result word, the tracker writes and the ordered callee log with
`record`, an independently written Python reconstruction. It then flips every
conditional jump of each body and checks that the comparison catches the change, and
runs deliberately wrong reconstructions as negative controls. The target is read, never
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
SOURCE = b"l1/src/abci/hash_signature_tracker.rs"
U64 = (1 << 64) - 1
NONE_VEC = 1 << 63          # Option<Vec<_>> niche read by `neg; jo`
NONE_OLD = (1 << 63) + 1    # insert result niche compared after `inc r14`
OK_TAG, ERR_TAG = 0x1A2, 0x95

# Bodies and their direct callees, in call order. Slot callees are shared.
BODIES = {
    0x27606D0: {"prior": 0x2BAFCE0, "insert": 0x28AEAC0, "watermark": 0x27605D0},
    0x2760BC0: {"prior": 0x2BAFF80, "insert": 0x28B2F10, "watermark": 0x27604D0},
}
SHARED = {"drop_check": 0x277E390, "drop_old": 0x277D220}
SLOTS = {0x64E6470: "predicate", 0x64E4F18: "recover", 0x64E6478: "check",
         0x64E4EA8: "report", 0x64DF4A0: "dealloc", 0x64DFB50: "memcmp"}
MEMCMP = 0x5000_0000        # fake address planted in the memcmp GLOB_DAT slot

OUT, TRACKER, MSG, BLOCK, CTX, VSET, ARG7 = (cpu.INPUT + i * 0x1000 for i in range(7))
NODES = cpu.INPUT + 0x10000
SIG = MSG + 0x30
ENTRY_SP = cpu.STACK - 0x800
STEP_LIMIT = 20000


class Fail(Exception):
    pass


def load_image():
    data = TARGET.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise Fail(f"target digest {digest} != {SHA256}")
    return cpu.Image(data)


# ---------------------------------------------------------------- static facts from bytes

def locations(image):
    """Location records (ptr,len,line,col) whose ptr is the tracker source path string."""
    data = image.data
    at = data.find(SOURCE)
    if at < 0 or data.find(SOURCE, at + 1) >= 0:
        raise Fail("source path string is missing or not unique")
    va = None
    for addr, off, size in image.sections.values():
        if addr and off <= at < off + size:
            va = at - off + addr
    rows = []
    for slot, add in sorted(image.slots.items()):
        if add != va:
            continue
        off = image.file_offset(slot)
        length, line, col = struct.unpack_from("<QII", data, off + 8)
        if length == len(SOURCE):
            rows.append((slot, line, col))
    return rows


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
    """Direct and slot calls, plus rip-relative lea of tracker Locations, in byte order."""
    locs = {slot: (line, col) for slot, line, col in locations(image)}
    rows = []
    for insn in body_insns(image, start)[2]:
        if insn.key == 0xE8:
            rows.append((insn.va, "call", insn.target, ""))
        elif insn.key == 0xFF and (image.data[insn.modrm] >> 3) & 7 == 2:
            slot = slot_of(image, insn)
            if slot is not None:
                rows.append((insn.va, "slot_call", image.slots.get(slot, 0), f"slot={slot:#x}"))
        elif insn.key == 0x8D:
            slot = slot_of(image, insn)
            if slot in locs:
                line, col = locs[slot]
                rows.append((insn.va, "location", slot, f"line={line} col={col}"))
    return rows


def body_constants(image, start):
    """Report code (mov edi, imm32 before each report slot call) and the Location of each
    tracker line the body loads with a rip-relative lea, both read from the body bytes."""
    insns = body_insns(image, start)[2]
    codes, lines = [], {}
    for prev, insn in zip(insns, insns[1:]):
        if insn.key == 0xFF and slot_of(image, insn) == 0x64E4EA8:
            if prev.key != 0xBF or prev.rex:
                raise Fail(f"report call at {insn.va:#x} is not preceded by mov edi, imm32")
            codes.append(struct.unpack_from("<I", image.data, prev.off + 1)[0])
    for va, kind, target, note in call_rows(image, start):
        if kind == "location":
            lines[int(note.split()[0][5:])] = target
    if len(set(codes)) != 1 or sorted(lines) != [107, 123]:
        raise Fail(f"unexpected report constants in {start:#x}: {codes} {sorted(lines)}")
    return codes[0], lines[107], lines[123]


def jcc_sites(image, start):
    rows = []
    for insn in body_insns(image, start)[2]:
        if isinstance(insn.key, int) and 0x70 <= insn.key <= 0x7F:
            rows.append((insn.va, insn.off + insn.size - 2))
        elif isinstance(insn.key, tuple) and len(insn.key) == 2 and 0x80 <= insn.key[1] <= 0x8F:
            rows.append((insn.va, insn.off + insn.size - 5))
    return rows


# ---------------------------------------------------------------- evaluator with stubs

class Machine(cpu.Machine):
    def __init__(self, image, case, roles):
        super().__init__(image)
        self.case, self.roles, self.log = case, roles, []
        self.by_target = {t: r for r, t in roles.items()}

    def step(self):
        insn = self.image.fetch(self.pc)
        here, data = self.pc, self.image.data
        key = insn.key
        self.seen.add(here)
        if key == 0x98 and insn.rex & 8:          # cdqe
            self.pc = here + insn.size
            v = self.get(cpu.RAX, 32)
            self.put(cpu.RAX, 64, None if v is None else (v - (1 << 32) if v >> 31 else v) & U64)
            return
        if key == 0xFF and (data[insn.modrm] >> 3) & 7 == 6:   # push r/m64
            self.pc = here + insn.size
            v = self.read(self.operand(insn), 64)
            sp = self.get(cpu.RSP, 64) - 8
            self.set_reg(cpu.RSP, sp)
            self.store(sp, 8, v)
            return
        if key == 0xFF and (data[insn.modrm] >> 3) & 7 == 2 and data[insn.modrm] >> 6 == 3:
            self.pc = here + insn.size                   # call reg
            target = self.get((data[insn.modrm] & 7) | ((insn.rex & 1) << 3), 64)
            if target is None:
                cpu.fail(f"call through unknown register at {here:#x}")
            self.call(target, here)
            return
        if isinstance(key, tuple) and len(key) == 2 and key[1] in (0x74, 0xDB, 0xD7) and insn.wide16:
            self.pc = here + insn.size
            reg = ((data[insn.modrm] >> 3) & 7) | ((insn.rex & 4) << 1)
            operand = self.operand(insn)
            if key[1] == 0xD7:
                src = self.xmm[operand[1]]
                self.put(reg, 32, None if src is None else sum(((b >> 7) & 1) << i for i, b in enumerate(src)))
                return
            if operand[0] == "r":
                other = self.xmm[operand[1]]
            else:
                at = self.address(operand)
                lo, hi = self.load(at, 8), self.load(at + 8, 8)
                other = None if lo is None or hi is None else struct.pack("<QQ", lo, hi)
            mine = self.xmm[reg]
            if mine is None or other is None:
                self.xmm[reg] = None
            elif key[1] == 0x74:
                self.xmm[reg] = bytes(0xFF if a == b else 0 for a, b in zip(mine, other))
            else:
                self.xmm[reg] = bytes(a & b for a, b in zip(mine, other))
            return
        super().step()

    def bytes_at(self, at, n):
        out = []
        for i in range(n):
            b = self.mem.get(at + i)
            out.append(None if b is None else b)
        return out

    def call(self, target, where):
        role = "memcmp" if target == MEMCMP else self.by_target.get(target)
        if role is None:
            raise cpu.Done(f"unexpected call {target:#x}", where)
        a = [self.get(r, 64) for r in (cpu.RDI, cpu.RSI, cpu.RDX, cpu.RCX, cpu.R8, cpu.R9)]
        ret = getattr(self, "stub_" + role)(a)
        for reg in cpu.CALLER_SAVED:
            self.put(reg, 64, None)
        if ret is not None:
            self.set_reg(cpu.RAX, ret)
        self.flags = [None, None, None, None]
        self.pc = where + self.image.fetch(where).size

    # Each stub records what the body passed and returns what the case chose.
    def stub_predicate(self, a):
        self.log.append(("predicate", a[0], a[1] & 0xFFFFFFFF, a[2]))
        return int(self.case["pred"])

    def stub_recover(self, a):
        self.log.append(("recover", a[1], a[2]))
        signer = self.case["signer"]
        self.store(a[0], 1, 0 if signer is None else 1)
        if signer is not None:
            for i, b in enumerate(signer):
                self.store(a[0] + 1 + i, 1, b)

    def stub_memcmp(self, a):
        left, right = self.bytes_at(a[0], a[2]), self.bytes_at(a[1], a[2])
        if None in left or None in right:
            cpu.fail("memcmp of unknown bytes")
        for x, y in zip(left, right):
            if x != y:
                return (x - y) & U64
        return 0

    def stub_check(self, a):
        self.log.append(("check", a[1], a[2], a[3]))
        res = self.case["check"]
        if res is None:
            self.store(a[0], 2, 0x0020)
        else:
            self.store(a[0], 2, OK_TAG)
            for i, b in enumerate(res):
                self.store(a[0] + 2 + i, 1, b)

    def stub_drop_check(self, a):
        self.log.append(("drop_check",))

    def stub_prior(self, a):
        self.log.append(("prior", a[1], a[2], bytes(self.bytes_at(a[3], 32))))
        prior = self.case["prior"]
        self.store(a[0], 8, NONE_VEC if prior is None else prior)
        self.store(a[0] + 8, 8, 0x7300_0000)

    def stub_report(self, a):
        self.log.append(("report", a[0] & 0xFFFFFFFF, a[1]))

    def stub_dealloc(self, a):
        self.log.append(("dealloc", a[0], a[1], a[2]))

    def stub_insert(self, a):
        sp = self.get(cpu.RSP, 64)
        rec = self.bytes_at(a[4], 54)
        chk = tuple(rec[1:33]) if rec[0] == 1 else None
        who = tuple(rec[34:54]) if rec[33] == 1 else None
        self.log.append(("insert", a[1], a[2], bytes(self.bytes_at(a[3], 32)), rec[0], chk, rec[33], who,
                         bytes(self.bytes_at(a[5], 0x48)), self.load(sp, 8), self.load(sp + 8, 8),
                         self.load(self.load(sp + 8, 8), 8)))
        old = self.case["old"]
        if old is None:
            self.store(a[0], 8, NONE_OLD)
        else:
            self.store(a[0], 8, 0x11)
            for i in range(8, 0x40):
                self.store(a[0] + i, 1, 0x40 + i)
            for i, b in enumerate(old):
                self.store(a[0] + 0x40 + i, 1, b)

    def stub_watermark(self, a):
        self.log.append(("watermark", a[0], a[1], a[2], self.load(a[2], 8), a[3]))

    def stub_drop_old(self, a):
        self.log.append(("drop_old", a[0] - self.get(cpu.RSP, 64)))


def build_tree(m, keys, fanout):
    """Lay out a BTreeSet<[u8;20]> of uniform depth: node len u16 +0xe6, keys +8 stride 0x14,
    edges +0xe8. Returns (root, height)."""
    keys = sorted(keys)
    nodes = [0]

    def alloc():
        at = NODES + nodes[0] * 0x200
        nodes[0] += 1
        return at

    def write(node, ks, edges):
        m.store(node + 0xE6, 2, len(ks))
        for i, k in enumerate(ks):
            for j, b in enumerate(k):
                m.store(node + 8 + 0x14 * i + j, 1, b)
        for i, e in enumerate(edges):
            m.store(node + 0xE8 + 8 * i, 8, e)

    if len(keys) <= fanout:
        root = alloc()
        write(root, keys, [])
        return root, 0
    # two levels: leaves of `fanout` keys separated by one key each
    leaves, seps, i = [], [], 0
    while i < len(keys):
        chunk = keys[i:i + fanout]
        i += fanout
        leaves.append(chunk)
        if i < len(keys):
            seps.append(keys[i])
            i += 1
    if len(seps) >= len(leaves):
        leaves.append([])
    root = alloc()
    edges = []
    for chunk in leaves:
        leaf = alloc()
        write(leaf, chunk, [])
        edges.append(leaf)
    write(root, seps, edges)
    return root, 1


def address(n):
    return bytes([0x10 + n * 7 & 0xFF, 0xA0, n & 0xFF] + [(n * 13 + j * 29) & 0xFF for j in range(17)])


HASH = bytes((0x31 * i + 5) & 0xFF for i in range(32))
OTHER_HASH = [HASH[:31] + bytes([HASH[31] ^ 1]), bytes([HASH[0] ^ 0x80]) + HASH[1:], HASH[:16] + bytes(16)]
CHECK_OUT = bytes((0x9D + 11 * i) & 0xFF for i in range(32))


def setup(m, case):
    for reg in range(16):
        m.set_reg(reg, 0x0BAD_0000 + reg * 0x100)
    m.set_reg(cpu.RDI, OUT)
    m.set_reg(cpu.RSI, TRACKER)
    m.set_reg(cpu.RDX, MSG)
    m.set_reg(cpu.RCX, case["flag"])
    m.set_reg(cpu.R8, CTX)
    m.set_reg(cpu.R9, VSET)
    m.set_reg(cpu.RSP, ENTRY_SP)
    m.store(ENTRY_SP, 8, cpu.RETURN_MARK)
    m.store(ENTRY_SP + 8, 8, ARG7)
    m.store(0x64DFB50, 8, MEMCMP)
    for i in range(4):
        m.store(OUT + i, 1, 0xEE)
    for i in range(0x80, 0xC0):
        m.store(TRACKER + i, 1, 0xC0 ^ i)
    m.store(TRACKER + 0x90, 1, case["sealed"])
    m.store(MSG, 8, BLOCK)
    m.store(MSG + 8, 8, case["height"])
    for i, b in enumerate(HASH):
        m.store(MSG + 0x10 + i, 1, b)
    for i in range(0x40):
        m.store(SIG + i, 1, (0x5A + 3 * i) & 0xFF)
    for i in range(0x48):
        m.store(BLOCK + i, 1, (0x21 * i + 1) & 0xFF)
    m.store(CTX, 8, 0x7200_0000)
    m.store(CTX + 0x58, 8, 0x7200_0058)
    m.store(ARG7 + 0x10, 8, case["boundary"])
    root, height = build_tree(m, [address(n) for n in case["members"]], case["fanout"])
    m.store(VSET + 0x30, 8, root if case["members"] or case["fanout"] else 0)
    m.store(VSET + 0x38, 8, height)


def run_body(image, start, case, seen=None):
    roles = dict(SHARED)
    roles.update(BODIES[start])
    for slot, role in SLOTS.items():
        if role != "memcmp":
            roles[role] = image.slots[slot]
    m = Machine(image, case, roles)
    setup(m, case)
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
    word = m.load(OUT, 2)
    flag = m.mem.get(OUT + 2)
    tracker = tuple(m.mem.get(TRACKER + i) for i in range(0x90, 0xB2))
    return ("ret", word, flag, tracker, tuple(m.log))


# ---------------------------------------------------------------- the reconstruction

def record(case, code, line107, line123, variant=None):
    """Independent reconstruction of the record path. Returns what run_body returns."""
    log = []
    tracker = [0xC0 ^ i for i in range(0x90, 0xB2)]
    tracker[0] = case["sealed"]
    pred = bool(case["pred"])
    log.append(("predicate", VSET, case["flag"], SIG))
    first_seal = tracker[0] == 0 and case["height"] == case["boundary"]
    if variant == "seal_ignores_flag":
        first_seal = case["height"] == case["boundary"]
    if first_seal and (pred or variant == "seal_ignores_predicate"):
        tracker[1] = 1
        tracker[2:34] = list(HASH)
    log.append(("recover", VSET, SIG))
    signer = case["signer"]
    members = {address(n) for n in case["members"]}
    found = signer is not None and signer in members
    if variant == "member_without_recover":
        found = bool(case["members"])
    log.append(("check", CTX, SIG, 0x7200_0058))
    chk = case["check"]
    if chk is None:
        log.append(("drop_check",))
        if not found and variant != "error_ignored":
            if not pred:
                return ("ret", ERR_TAG, 0xEE, tuple(tracker), tuple(log))
            return ("ret", OK_TAG, 0, tuple(tracker), tuple(log))
    log.append(("prior", TRACKER, case["height"], HASH))
    if case["prior"] is not None:
        log.append(("report", code, line107))
        if case["prior"] and variant != "no_dealloc":
            log.append(("dealloc", 0x7300_0000, case["prior"] * 32 & U64, 0))
    who = (tuple(signer) if signer is not None else (None,) * 20) if found else None
    log.append(("insert", TRACKER, case["height"], HASH, 1 if chk is not None else 0,
                tuple(chk) if chk is not None else None, 1 if found else 0, who,
                bytes((0x21 * i + 1) & 0xFF for i in range(0x48)), CTX, None, VSET + 0x30))
    old = case["old"]
    if old is not None:
        if old != HASH or variant == "always_report":
            log.append(("report", code, line123))
        log.append(("watermark", TRACKER, case["height"], None, VSET + 0x30, ARG7))
        log.append(("drop_old", 0xF0))
    return ("ret", OK_TAG, int(old is not None), tuple(tracker), tuple(log))


def normalize(result):
    """Stack addresses vary only by where the body put its locals; keep them relative."""
    if result[0] != "ret":
        return result
    log = []
    for row in result[4]:
        if row[0] == "insert":
            row = row[:10] + (None,) + row[11:]
        if row[0] == "watermark":
            row = row[:3] + (None,) + row[4:]
        log.append(row)
    return result[:4] + (tuple(log),)


# ---------------------------------------------------------------- cases

def cases():
    member_sets = [
        ("empty_root", [], 0),          # root node with zero keys
        ("one_leaf", [3, 5, 9], 11),
        ("full_leaf", list(range(1, 12)), 11),
        ("two_level", list(range(1, 30)), 4),
    ]
    out = []
    for mname, members, fanout in member_sets:
        ordered = sorted(address(n) for n in members)
        signers = [("none", None), ("absent_0", address(0)), ("absent_40", address(40))]
        picks = sorted({0, len(ordered) // 2, fanout, fanout + 1, len(ordered) - 1})
        signers += [(f"sorted_{k}", ordered[k]) for k in picks if 0 <= k < len(ordered)]
        for sname, signer in signers:
            for pred in (0, 1):
                for sealed in (0, 1):
                    for height, boundary in ((7, 7), (7, 8)):
                        for check in (None, CHECK_OUT):
                            for prior in (None, 0, 3):
                                for old in (None, HASH, OTHER_HASH[0], OTHER_HASH[1], OTHER_HASH[2]):
                                    if old is not None and old is not HASH and (prior != 0 or check is None):
                                        continue
                                    out.append({
                                        "name": f"{mname}/{sname}", "members": members, "fanout": fanout,
                                        "signer": signer, "pred": pred, "sealed": sealed,
                                        "height": height, "boundary": boundary, "flag": 0x8000_0003,
                                        "check": check, "prior": prior, "old": old})
    for big in (0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0000, 0):
        out.append({"name": "edge/height", "members": [3, 5, 9], "fanout": 11, "signer": address(5),
                    "pred": 1, "sealed": 0, "height": big, "boundary": big, "flag": 0,
                    "check": CHECK_OUT, "prior": (1 << 59) - 1, "old": HASH})
    return out


def describe(case):
    return "\t".join([
        case["name"], str(len(case["members"])), str(case["fanout"]),
        "-" if case["signer"] is None else case["signer"][:3].hex(),
        str(case["pred"]), str(case["sealed"]), f"{case['height']:#x}", f"{case['boundary']:#x}",
        "err" if case["check"] is None else "ok", "none" if case["prior"] is None else str(case["prior"]),
        "none" if case["old"] is None else ("same" if case["old"] == HASH else "diff:" + case["old"][-1:].hex())])


def outcome(result):
    if result[0] != "ret":
        return result[0]
    roles = ",".join(row[0] for row in result[4])
    seal = "sealed" if result[3][1] == 1 and bytes(result[3][2:34]) == HASH else "-"
    return f"{result[1]:#x}/{'unset' if result[2] == 0xEE else result[2]}/{seal}/{roles}"


VARIANTS = ("seal_ignores_flag", "seal_ignores_predicate", "member_without_recover", "error_ignored",
            "no_dealloc", "always_report")


def variant_rows(image, all_cases, consts, real):
    out = []
    for variant in VARIANTS:
        first, total = None, 0
        for i, c in enumerate(all_cases):
            if normalize(record(c, *consts, variant)) != real[i]:
                total += 1
                if first is None:
                    first = i
        out.append((variant, total, first))
    return out


def mutant_rows(image, start, all_cases, real):
    sample = select_cases(all_cases, real)
    out = []
    for va, op_off in jcc_sites(image, start):
        data = bytearray(image.data)
        data[op_off] ^= 1
        mutant = copy.copy(image)
        mutant.data = bytes(data)
        mutant.cache = {}
        killer = None
        for i in sample:
            if normalize(run_body(mutant, start, all_cases[i])) != real[i]:
                killer = i
                break
        out.append((va, op_off, killer))
    return out, sample


def select_cases(all_cases, real):
    """One case per distinct real outcome and per case name, in case order."""
    seen, picked = set(), []
    for i, c in enumerate(all_cases):
        k = (outcome(real[i]), c["name"], c["pred"], c["sealed"], c["height"] == c["boundary"])
        if k not in seen:
            seen.add(k)
            picked.append(i)
    return picked


def generate(out_dir):
    image = load_image()
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    locs = locations(image)
    all_cases = cases()
    files = {}
    summary = {"target_sha256": SHA256, "source": SOURCE.decode(), "cases_per_body": len(all_cases),
               "bodies": {}}
    case_lines = ["#\tname\tmembers\tfanout\tsigner\tpred\tsealed\theight\tboundary\tcheck\tprior\told\t"
                  "outcome(word/flag/seal/calls)\tverdict"]
    real_base, mismatches, digests, reached = None, 0, {}, {}
    for start in BODIES:
        lo, hi, insns = body_insns(image, start)
        consts = body_constants(image, start)
        if start == min(BODIES):
            base_consts = consts
        counts, h, real, seen = {}, hashlib.sha256(), [], set()
        for i, case in enumerate(all_cases):
            got = normalize(run_body(image, start, case, seen))
            want = normalize(record(case, *consts))
            ok = got == want
            mismatches += not ok
            real.append(got)
            key = outcome(got)
            counts[key] = counts.get(key, 0) + 1
            h.update(key.encode() + b"\n")
            if start == min(BODIES):
                case_lines.append(f"{i}\t" + describe(case) + "\t" + key + "\t" + ("match" if ok else "MISMATCH"))
        if real_base is None:
            real_base = real
        digests[start] = h.hexdigest()
        summary["bodies"][f"{start:#x}"] = {
            "fde": [f"{lo:#x}", f"{hi:#x}"], "instructions": len(insns),
            "direct_callees": {k: f"{v:#x}" for k, v in sorted(BODIES[start].items())},
            "report_code": consts[0], "line_107_location": f"{consts[1]:#x}",
            "line_123_location": f"{consts[2]:#x}",
            "outcomes": dict(sorted(counts.items())), "result_digest": digests[start],
            "instructions_reached": sum(1 for insn in insns if insn.va in seen)}
        reached[start] = seen
    summary["mismatches"] = mismatches
    summary["twins_agree"] = len(set(digests.values())) == 1
    vrows = variant_rows(image, all_cases, base_consts, real_base)
    summary["negative_controls"] = {v: {"caught_cases": t, "first_case": f} for v, t, f in vrows}
    mut_lines = ["body\tjcc_va\tfile_offset_flipped\tverdict\tfirst_killing_case"]
    killed = survived = unreached = 0
    for start in BODIES:
        real = real_base if start == min(BODIES) else [normalize(run_body(image, start, c)) for c in all_cases]
        rows, sample = mutant_rows(image, start, all_cases, real)
        for va, off, killer in rows:
            verdict = "killed" if killer is not None else "unreached" if va not in reached[start] else "survived"
            mut_lines.append(f"{start:#x}\t{va:#x}\t{off:#x}\t{verdict}\t{'-' if killer is None else killer}")
            killed += verdict == "killed"
            survived += verdict == "survived"
            unreached += verdict == "unreached"
        summary.setdefault("mutation_sample_cases", len(sample))
    summary["mutants"] = {"killed": killed, "survived": survived, "unreached": unreached}
    loc_lines = ["location_va\tline\tcolumn"] + [f"{s:#x}\t{l}\t{c}" for s, l, c in locs]
    call_lines = ["body\tsite\tkind\ttarget\tnote"]
    for start in BODIES:
        for va, kind, target, note in call_rows(image, start):
            call_lines.append(f"{start:#x}\t{va:#x}\t{kind}\t{target:#x}\t{note}")
    files["cases.tsv"] = "\n".join(case_lines) + "\n"
    files["mutants.tsv"] = "\n".join(mut_lines) + "\n"
    files["locations.tsv"] = "\n".join(loc_lines) + "\n"
    files["calls.tsv"] = "\n".join(call_lines) + "\n"
    files["summary.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    for name, text in files.items():
        (out_dir / name).write_text(text)
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
    print(json.dumps({"mismatches": s["mismatches"], "twins_agree": s["twins_agree"], "mutants": s["mutants"]}))
    good = s["mismatches"] == 0 and s["twins_agree"] and s["mutants"]["survived"] == 0
    return 0 if good else 2


if __name__ == "__main__":
    sys.exit(main())
