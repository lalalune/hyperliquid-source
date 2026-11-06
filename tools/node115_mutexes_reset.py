#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-mutexes-reset.

Byte reads only; never executes the node binary. Checks:
  1. binary size + SHA-256
  2. dispatcher FDE bytes, entry endbr64, strict mnemonic count
  3. tree-node file bytes + runtime fields via .rela.dyn addends
  4. index arithmetic for path [11, 8, 9]
  5. sweep/dispatcher censuses (E8/E9 scans, rela addend scans)
  6. disjointness vs the merged tree (excluding self and
     census/cited-only metadata subtrees)
  7. MANIFEST.sha256 entries, when the manifest exists
Exit 0 only when every check passes.
"""

import hashlib
import json
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research", "work-items", "RE-001-node115-lu-mutexes-reset")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032

DISP_START, DISP_END = 0x63A8FF0, 0x63A93BA
NODES = {
    "node_root": (0x64DA4C0, [1, 0x4376FD, 13, 0x64DA500, 0]),
    "node_stats": (0x64DA6B8, [1, 0x44869A, 11, 0x64DAAA0, 0]),
    "node_mutexes": (0x64DABE0, [1, 0x4385FA, 10, 0x64DAC60, 0]),
    "node_reset": (0x64DADC8, [1, 0x440C22, 0, 0, 0x63A5BF0]),
}
EXPECT_STRICT = 232
EXPECT_E8 = {
    0x63DC1CB, 0x63DC299, 0x63DC360, 0x63DC428, 0x63DC4F7, 0x63DC5BE,
    0x63DC639, 0x63DDD82, 0x63DDE07, 0x63DDE84, 0x63DDF26, 0x63DDFAC,
    0x63DE043, 0x63DE0C2, 0x63E02B9, 0x63E036D, 0x63E03EA, 0x63E04B9,
    0x63E0539, 0x63E05C0, 0x63E063E, 0x63E06BC, 0x63E073B, 0x63E07BA,
    0x63E0837, 0x63E08B4, 0x63E0933, 0x63E09B2, 0x63E0A30, 0x63E0AAE,
    0x63E0B9A, 0x63E0C63, 0x63E0D25, 0x63E0DEE, 0x63E0EAE, 0x63E0F6F,
    0x63E0FF9, 0x63E31AF, 0x63E323D, 0x63E32C6, 0x63E334F, 0x63E350B,
    0x63E62E8, 0x63E6378, 0x63E6400, 0x63E6482, 0x63E650A, 0x63E658C,
    0x63E796C, 0x63E79E1, 0x63E7A5F, 0x63E7AD3, 0x63E7B5B, 0x63E7BCD,
}
MY_RANGES = [
    (DISP_START, DISP_END),
    (0x64DA4C0, 0x64DA4E8),
    (0x64DA6B8, 0x64DA6E0),
    (0x64DABE0, 0x64DAC08),
    (0x64DADC8, 0x64DADF0),
]

FAILURES = []


def check(name, ok, detail=""):
    print(("%s %s %s" % ("PASS" if ok else "FAIL", name, detail)).strip())
    if not ok:
        FAILURES.append(name)


def read_binary():
    with open(BINARY, "rb") as f:
        return f.read()


def parse_rela(data):
    off0, size = 0x6BE8, 0x163CC8
    rela = {}
    for i in range(size // 24):
        o, _info, add = struct.unpack(
            "<QQq", data[off0 + i * 24: off0 + i * 24 + 24])
        rela[o] = add
    return rela


def runtime_value(data, rela, va):
    if va in rela:
        return rela[va]
    return struct.unpack("<Q", data[va - 0x2000: va - 0x2000 + 8])[0]


def strict_count(objdump_path):
    pat = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")
    n = 0
    with open(objdump_path) as f:
        for line in f:
            if pat.match(line):
                n += 1
    return n


def collect_claimed(root):
    """Recursive range+fde collector over records.json files.

    Excludes census and cited-only metadata subtrees; deduplicates
    by real path; excludes this packet's own directory.
    """
    import glob

    def walk(obj, out, skip):
        if isinstance(obj, dict):
            for k, v in obj.items():
                sk = skip or k in ("census", "cited_only_not_claimed")
                if (k in ("range", "fde") and isinstance(v, list)
                        and len(v) == 2
                        and all(isinstance(x, str)
                                and x.startswith("0x") for x in v)):
                    if not sk:
                        out.append((int(v[0], 16), int(v[1], 16)))
                else:
                    walk(v, out, sk)
        elif isinstance(obj, list):
            for v in obj:
                walk(v, out, skip)

    files = set()
    for f in glob.glob(os.path.join(
            root, "research", "work-items", "**", "records.json"),
            recursive=True):
        if os.path.realpath(f).startswith(os.path.realpath(PACKET)):
            continue
        files.add(os.path.realpath(f))
    claimed = set()
    for f in files:
        try:
            with open(f) as fh:
                doc = json.load(fh)
        except Exception:
            continue
        ranges = []
        walk(doc, ranges, False)
        claimed.update(ranges)
    return claimed


def main():
    data = read_binary()
    check("binary size", len(data) == EXPECT_SIZE, str(len(data)))
    check("binary sha256",
          hashlib.sha256(data).hexdigest() == EXPECT_SHA)

    # Dispatcher exhibit bytes.
    disp = data[DISP_START - 0x1000: DISP_END - 0x1000]
    with open(os.path.join(PACKET, "dispatcher.hex"), "rb") as f:
        check("dispatcher.hex bytes", f.read() == disp,
              "%d bytes" % len(disp))
    check("dispatcher entry endbr64", disp[:4] == bytes.fromhex("f30f1efa"))
    check("dispatcher strict count",
          strict_count(os.path.join(PACKET, "dispatcher.objdump.txt"))
          == EXPECT_STRICT, str(EXPECT_STRICT))

    # Tree-node exhibits: file bytes + runtime fields.
    rela = parse_rela(data)
    for name, (va, fields) in NODES.items():
        with open(os.path.join(PACKET, name + ".hex"), "rb") as f:
            raw = f.read()
        check(name + ".hex bytes",
              raw == data[va - 0x2000: va - 0x2000 + 40])
        got = [runtime_value(data, rela, va + k * 8) for k in range(5)]
        check(name + " runtime fields", got == fields,
              " ".join("%#x" % g for g in got))

    # Index arithmetic.
    check("index 11 root->stats", 0x64DA500 + 11 * 0x28 == 0x64DA6B8)
    check("index 8 stats->mutexes", 0x64DAAA0 + 8 * 0x28 == 0x64DABE0)
    check("index 9 mutexes->reset", 0x64DAC60 + 9 * 0x28 == 0x64DADC8)

    # Censuses: E8/E9 scans + rela addend scans.
    base_va, base_off = 0x1419300, 0x1418300
    text = data[base_off: base_off + 0x4FD7700]
    e8_disp, e9_disp, e8_sweep, e9_sweep = set(), set(), set(), set()
    for i in range(len(text) - 5):
        op = text[i]
        if op not in (0xE8, 0xE9):
            continue
        rel = struct.unpack("<i", text[i + 1: i + 5])[0]
        tgt = base_va + i + 5 + rel
        site = base_va + i
        if tgt == DISP_START:
            (e8_disp if op == 0xE8 else e9_disp).add(site)
        elif tgt == 0x63A5BF0:
            (e8_sweep if op == 0xE8 else e9_sweep).add(site)
    check("dispatcher E8 census", e8_disp == EXPECT_E8,
          "%d sites" % len(e8_disp))
    check("dispatcher E9 census", len(e9_disp) == 0)
    check("sweep E8 census", len(e8_sweep) == 0)
    check("sweep E9 census", len(e9_sweep) == 0)
    sweep_slots = [o for o, a in rela.items() if a == 0x63A5BF0]
    check("sweep rela.dyn slots", sweep_slots == [0x64DADE8],
          ",".join("%#x" % s for s in sweep_slots))
    disp_slots = [o for o, a in rela.items() if a == DISP_START]
    check("dispatcher rela.dyn slots", disp_slots == [])

    # Disjointness vs merged tree.
    claimed = collect_claimed(ROOT)
    overlaps = [(a, b) for (a, b) in claimed
                if any(x < b and a < y for x, y in MY_RANGES)]
    check("disjointness vs merged tree", len(overlaps) == 0,
          "%d unique claimed ranges, %d overlaps"
          % (len(claimed), len(overlaps)))

    # MANIFEST, when present.
    man = os.path.join(PACKET, "MANIFEST.sha256")
    if os.path.exists(man):
        ok = True
        with open(man) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                digest, rel = line.split(None, 1)
                path = os.path.normpath(os.path.join(PACKET, rel))
                with open(path, "rb") as fh:
                    got = hashlib.sha256(fh.read()).hexdigest()
                if got != digest:
                    ok = False
                    print("FAIL manifest entry %s" % rel)
        check("MANIFEST entries", ok)
    else:
        print("SKIP MANIFEST entries (not yet packaged)")

    if FAILURES:
        print("FAILED: %s" % ", ".join(FAILURES))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
