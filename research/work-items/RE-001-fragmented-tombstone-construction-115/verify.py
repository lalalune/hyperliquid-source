"""Self-check for RE-001-fragmented-tombstone-construction-115.

Run from the repository root:
    python3 research/work-items/RE-001-fragmented-tombstone-construction-115/verify.py

Checks, against a fresh objdump/readelf run on the real node #115 binary:
  1. artifact digest
  2. MANIFEST.sha256 matches the packet files on disk
  3. every excerpt regenerates byte-for-byte from the binary
  4. fixed instruction samples + 3 seeded random gate spots match the
     raw binary byte-for-byte
  5. frames.txt FDEs appear in a fresh readelf dump
  6. census.py reproduces the census in records.json, and every caller
     site is a real call inside its stated FDE
  7. every packet_internal_sites entry is a real call in its stated FDE
  8. relocations.txt RELATIVE addends and typeinfo name strings match
     the relocation table / the binary
  9. the key immediates (sizes, offsets, packed count, -1 seq, lea
     targets) appear in the excerpts
 10. the model module's constants match records.json, and its tests pass
"""

import json
import os
import re
import struct
import subprocess
import sys
import hashlib
import random

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BIN = os.path.join(ROOT, "work/hl-node-115.bin")
BIN_VA_BASE = 0x1000
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8

EXCERPTS = [
    # (file, fde_start, fde_end, fde_prefix)
    ("ctor-list-5f31470.objdump.txt", 0x5F31470, 0x5F3159E, "0035abcc"),
    ("split-by-snapshot-5f33950.objdump.txt", 0x5F33950, 0x5F33B36, "00746e64"),
    ("probe-5f31250.objdump.txt", 0x5F31250, 0x5F3137E, "00746dbc"),
    ("once-init-5f2eb90.objdump.txt", 0x5F2EB90, 0x5F2ECC2, "0035a7ac"),
    ("newiterator-5f29140.objdump.txt", 0x5F29140, 0x5F294CE, "00746d44"),
    ("block-table-new-60fcee0.objdump.txt", 0x60FCEE0, 0x60FCF6A, "00762a1c"),
    ("truncated-split-5f269e0.objdump.txt", 0x5F269E0, 0x5F26ED5, "00746bd0"),
    ("map-emplace-5f33670.objdump.txt", 0x5F33670, 0x5F338FA, "0035b15c"),
]

# (va, hex bytes) -- fixed instruction samples, all from the excerpts.
SAMPLES = [
    (0x5F31470, "f30f1efa"),
    (0x5F31498, "e823bc2800"),
    (0x5F314A7, "488d0532b65900"),
    (0x5F314BF, "488903"),
    (0x5F314E0, "0f114348"),
    (0x5F31590, "f083420801"),
    (0x5F33950, "f30f1efa"),
    (0x5F33A03, "e848d8ffff"),
    (0x5F33A10, "bfc8000000"),
    (0x5F33A3B, "e840d9ffff"),
    (0x5F33AB7, "e8b4fbffff"),
    (0x5F31250, "f30f1efa"),
    (0x5F312AC, "488d3dddd8ffff"),
    (0x5F312C1, "e80a014c00"),
    (0x5F31336, "4c3b6620"),
    (0x5F2EB90, "f30f1efa"),
    (0x5F2EC25, "bf28000000"),
    (0x5F2EC40, "e84b224c00"),
    (0x5F29140, "f30f1efa"),
    (0x5F291BF, "bf18010000"),
    (0x5F29367, "e8a4e00000"),
    (0x5F293B3, "e8b8800000"),
    (0x5F293A3, "48b9ffffffffffffff00"),
    (0x60FCEE0, "f30f1efa"),
    (0x60FCF1E, "bfc8000000"),
    (0x60FCF4B, "e82045e3ff"),
    (0x5F269E0, "f30f1efa"),
    (0x5F26A13, "e838cf0000"),
    (0x5F26A9A, "e8c1eeffff"),
    (0x5F33670, "f30f1efa"),
    (0x5F33693, "e838d74b00"),
    (0x5F3369C, "498d4e08"),
]

FAILURES = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" -- " + detail if detail else ""))
    if not ok:
        FAILURES.append(name + (" -- " + detail if detail else ""))


def load_records():
    with open(os.path.join(HERE, "records.json")) as fh:
        return json.load(fh)


def objdump_range(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%d" % start,
         "--stop-address=%d" % end, BIN],
        capture_output=True, text=True, check=True).stdout
    lines = [l for l in out.splitlines() if l.strip()]
    return [l for l in lines[6:] if l and l[0] == " "]


def parse_instructions(lines):
    """Return {va: bytes} from objdump lines, joining wrapped immediates."""
    insns = {}
    cur_va = None
    cur_bytes = ""
    for line in lines:
        m = re.match(r"^\s+([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)$", line)
        if m:
            if cur_va is not None:
                insns[cur_va] = bytes.fromhex(cur_bytes)
            cur_va = int(m.group(1), 16)
            cur_bytes = m.group(2).replace(" ", "")
        elif re.match(r"^\s+([0-9a-f]+):\t([0-9a-f ]+)$", line):
            m2 = re.match(r"^\s+([0-9a-f]+):\t([0-9a-f ]+)$", line)
            if cur_va is not None and int(m2.group(1), 16) == cur_va + len(cur_bytes) // 2:
                cur_bytes += m2.group(2).replace(" ", "")
    if cur_va is not None:
        insns[cur_va] = bytes.fromhex(cur_bytes)
    return insns


def check_digest():
    h = hashlib.sha256(open(BIN, "rb").read()).hexdigest()
    check("digest", h == DIGEST, "binary sha256 %s" % h[:16])


def check_manifest():
    import hashlib as hl
    man_path = os.path.join(HERE, "MANIFEST.sha256")
    if not os.path.exists(man_path):
        check("manifest", False, "MANIFEST.sha256 missing")
        return
    expected = {}
    for line in open(man_path):
        parts = line.split(None, 1)
        if len(parts) == 2:
            expected[parts[1].strip()] = parts[0]
    ok = True
    for name, want in expected.items():
        p = os.path.join(HERE, name)
        if not os.path.exists(p):
            check("manifest", False, "missing file %s" % name)
            ok = False
            continue
        got = hl.sha256(open(p, "rb").read()).hexdigest()
        if got != want:
            check("manifest", False, "%s hash mismatch" % name)
            ok = False
    extra = set(os.listdir(HERE)) - set(expected) - {"MANIFEST.sha256", "__pycache__"}
    if extra:
        check("manifest", False, "unlisted files: %s" % sorted(extra))
        ok = False
    if ok:
        check("manifest", True, "%d files" % len(expected))


def check_excerpts():
    for fname, start, end, prefix in EXCERPTS:
        p = os.path.join(HERE, fname)
        saved = open(p).read()
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=%d" % start,
             "--stop-address=%d" % end, "work/hl-node-115.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        check("excerpt-" + fname, saved == fresh,
              "saved %d bytes vs fresh %d bytes" % (len(saved), len(fresh))
              if saved != fresh else "%d lines" % len(fresh.splitlines()))


def check_samples():
    data = open(BIN, "rb").read()
    for va, hexbytes in SAMPLES:
        want = bytes.fromhex(hexbytes)
        got = data[va - BIN_VA_BASE: va - BIN_VA_BASE + len(want)]
        check("sample-%x" % va, got == want,
              "want %s got %s" % (hexbytes, got.hex()) if got != want else "")
    # 3 seeded random gate spots over the excerpt instruction VAs.
    all_insns = {}
    for fname, start, end, _ in EXCERPTS:
        insns = parse_instructions(objdump_range(start, end))
        all_insns.update(insns)
    rng = random.Random(0x5F31470)
    vas = sorted(all_insns)
    spots = [rng.choice(vas) for _ in range(3)]
    for va in spots:
        want = all_insns[va]
        got = data[va - BIN_VA_BASE: va - BIN_VA_BASE + len(want)]
        check("gate-spot-%x" % va, got == want,
              "want %s got %s" % (want.hex(), got.hex()) if got != want else "")


def check_frames():
    frames = open(os.path.join(HERE, "frames.txt")).read()
    out = subprocess.run(["objdump", "--dwarf=frames", "work/hl-node-115.bin"],
                         cwd=ROOT, capture_output=True, text=True,
                         check=True).stdout
    ok = True
    for line in frames.splitlines():
        if not line.strip():
            continue
        if line.strip() not in out:
            check("frames", False, "missing FDE line: %s" % line.strip())
            ok = False
    if ok:
        check("frames", True, "%d FDE lines" % len(
            [l for l in frames.splitlines() if l.strip()]))


def check_census_and_callers():
    import census as census_mod
    records = load_records()
    calls, tails, hits, slots, installs = census_mod.scan(BIN)
    ok = True
    for t in census_mod.TARGETS:
        want = records["census"][hex(t)]
        got = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
        if want != got:
            check("census-%x" % t, False, "records %s vs scan %s" % (want, got))
            ok = False
    if ok:
        check("census", True, "%d targets reproduce" % len(census_mod.TARGETS))
    # vtable-install census: the five lea sites (and no slot-0 installs).
    want_installs = {0x5F313B2, 0x5F314A7, 0x5F315D4, 0x5F32A1D, 0x5F32B8D}
    got_installs = {v for _k, v in installs[0x64CCAE0]}
    check("vtable-installs", got_installs == want_installs,
          "got %s" % [hex(v) for v in sorted(got_installs)])
    check("vtable-installs-slot0", installs[0x64CCAF0] == [],
          "got %s" % installs[0x64CCAF0])
    # every callers.tsv row is a real call inside its stated FDE.
    rows = [l.rstrip("\n").split("\t") for l in
            open(os.path.join(HERE, "callers.tsv")).read().splitlines()[1:] if l.strip()]
    fde_insns = {}
    for tgt, site, kind, fs, fe, role in rows:
        fde = (int(fs, 16), int(fe, 16))
        if fde not in fde_insns:
            fde_insns[fde] = parse_instructions(objdump_range(*fde))
        insns = fde_insns[fde]
        va = int(site, 16)
        if va not in insns:
            check("caller-%s-%s" % (tgt, site), False, "no instruction at site")
            continue
        raw = insns[va]
        if kind == "direct_call":
            good = raw[0] == 0xE8 and (
                va + 5 + struct.unpack("<i", raw[1:5])[0] == int(tgt, 16))
        elif kind == "tail_jump":
            good = raw[0] == 0xE9 and (
                va + 5 + struct.unpack("<i", raw[1:5])[0] == int(tgt, 16))
        else:
            good = False
        check("caller-%s-%s" % (tgt, site), good,
              "bytes %s kind %s" % (raw.hex(), kind) if not good else "")
    # records.json callers agree with callers.tsv.
    rec_callers = set()
    for tgt, entries in records["callers"].items():
        for e in entries:
            rec_callers.add((tgt, e["site"], e["kind"]))
    tsv_callers = set((r[0], r[1], r[2]) for r in rows)
    check("callers-agree", rec_callers == tsv_callers,
          "records-only %s tsv-only %s" % (
              sorted(rec_callers - tsv_callers), sorted(tsv_callers - rec_callers)))


def check_internal_sites():
    records = load_records()
    fde_insns = {}
    for tgt, entries in records["packet_internal_sites"].items():
        for e in entries:
            fde = tuple(int(x, 16) for x in e["containing_fde"])
            if fde not in fde_insns:
                fde_insns[fde] = parse_instructions(objdump_range(*fde))
            insns = fde_insns[fde]
            va = int(e["site"], 16)
            if va not in insns:
                check("internal-%s-%s" % (tgt, e["site"]), False,
                      "no instruction at site")
                continue
            raw = insns[va]
            good = raw[0] == 0xE8 and (
                va + 5 + struct.unpack("<i", raw[1:5])[0] == int(tgt, 16))
            check("internal-%s-%s" % (tgt, e["site"]), good,
                  "bytes %s" % raw.hex() if not good else "")


def check_relocations():
    data = open(BIN, "rb").read()
    rel = {}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if (info & 0xFFFFFFFF) == 8:
            rel[ro] = add
    lines = open(os.path.join(HERE, "relocations.txt")).read().splitlines()
    ok = True
    for line in lines:
        m = re.match(r"RELATIVE slot (0x[0-9a-f]+) -> (0x[0-9a-f]+)", line)
        if m:
            slot, want = int(m.group(1), 16), int(m.group(2), 16)
            if rel.get(slot) != want:
                check("relocation-%x" % slot, False,
                      "want %s got %s" % (hex(want), hex(rel.get(slot, -1))))
                ok = False
    if ok:
        check("relocations", True, "%d RELATIVE lines" % len(
            [l for l in lines if l.startswith("RELATIVE slot")]))
    # typeinfo name strings.
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        pt, fl, off, va, pa, fs, ms, al = struct.unpack_from(
            "<IIQQQQQQ", data, e_phoff + i * e_phentsize)
        if pt == 1:
            segs.append((va, off, fs))

    def va2off(va):
        for v, o, fs in segs:
            if v <= va < v + fs:
                return va - v + o
        return None

    names = {
        0x64CC9E0: "N7rocksdb32FragmentedRangeTombstoneIteratorE",
        0x64CC828: "*N7rocksdb12_GLOBAL__N_128TruncatedRangeDelMergingIterE",
        0x64CC840: "St23_Sp_counted_ptr_inplaceIN7rocksdb28FragmentedRangeTombstoneListE"
                   "SaIvELN9__gnu_cxx12_Lock_policyE2EE",
    }
    for ti, want in names.items():
        name_va = rel.get(ti + 8)
        noff = va2off(name_va) if name_va else None
        got = data[noff:data.index(b"\x00", noff)].decode() if noff is not None else None
        check("typeinfo-name-%x" % ti, got == want,
              "want %s got %s" % (want, got) if got != want else "")


def check_literals():
    excerpts = ""
    for fname, _, _, _ in EXCERPTS:
        excerpts += open(os.path.join(HERE, fname)).read()
    lits = [
        ("mov $0xc8 (iterator size)", r"mov\s+\$0xc8,%edi"),
        ("mov $0xf8 (make_shared size)", r"mov\s+\$0xf8,%edi"),
        ("mov $0x118 (merging-iter temp)", r"mov\s+\$0x118,%edi"),
        ("mov $0x48 (truncated wrapper)", r"mov\s+\$0x48,%edi"),
        ("mov $0x30 (map node)", r"mov\s+\$0x30,%edi"),
        ("mov $0x28 (index node)", r"mov\s+\$0x28,%edi"),
        ("packed 0x100000001 (fast dispose)", r"0x100000001"),
        ("movabs -1 (seq = kMaxSequenceNumber)", r"movabs\s+\$0xffffffffffffff,%rcx"),
        ("lea 0x64ccae0 (vtable install)", r"# 64ccae0"),
        ("lea 0x5f2eb90 (once-init address)", r"# 5f2eb90"),
        ("atomicity selector 0x64ed290", r"64ed290"),
        ("__once_callable 0x64ed818", r"64ed818"),
        ("__once_call 0x64ed820", r"64ed820"),
    ]
    for name, pat in lits:
        check("literal-" + name, re.search(pat, excerpts) is not None)


def check_model():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import fragmented_tombstone_construction_115 as model
    records = load_records()
    ok = True
    consts = {
        "ITERATOR_SIZE": 0xC8, "LIST_SIZE": 0xE8, "TRUNCATED_SIZE": 0x48,
        "VTABLE": 0x64CCAF0, "VTABLE_START": 0x64CCAE0,
        "GLOBAL_ATOMICITY_SELECTOR": 0x64ED290,
        "PACKED_COUNTS": 0x100000001,
        "OFF_VTABLE": 0x00, "OFF_LIST_HOLDER_PTR": 0x48,
        "OFF_LIST_HOLDER_CTRL": 0x50, "OFF_CACHE_HOLDER_PTR": 0x58,
        "OFF_CACHE_HOLDER_CTRL": 0x60, "OFF_LIST_PTR": 0x68,
        "OFF_READ_SEQ": 0x70, "OFF_ARG6": 0x78,
        "OFF_UPPER_BOUND": 0x80, "OFF_FRAG": 0x88, "OFF_SEQ": 0x90,
        "LIST_FRAG_END": 0x08, "LIST_SEQ_BASE": 0x18,
        "CACHE_SEQ_BASE": 0x20, "CACHE_LIST_PTR": 0x28,
        "LIST_ONCE_FLAG": 0x48, "LIST_INDEX_HEADER": 0x58,
        "LIST_INDEX_COUNT": 0x78,
        "MAX_SEQNUM": 0xFFFFFFFFFFFFFFFF,
    }
    for name, want in consts.items():
        got = getattr(model, name, None)
        if got != want:
            check("model-const-" + name, False, "want %s got %s" % (want, got))
            ok = False
    if ok:
        check("model-constants", True, "%d constants" % len(consts))
    # The tests are a standalone script (main() + check()), not pytest.
    r = subprocess.run([sys.executable,
                        "tests/test_fragmented_tombstone_construction_115.py"],
                       cwd=ROOT, capture_output=True, text=True)
    ok_tests = r.returncode == 0 and "tests passed" in r.stdout
    check("model-tests", ok_tests,
          r.stdout.strip().splitlines()[-1] if r.stdout.strip()
          else r.stderr[-300:])


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_samples()
    check_frames()
    check_census_and_callers()
    check_internal_sites()
    check_relocations()
    check_literals()
    check_model()
    print()
    if FAILURES:
        print("FAILED (%d):" % len(FAILURES))
        for f in FAILURES:
            print("  - " + f)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
