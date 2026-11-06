"""Packet checker for RE-001-zstd-decompress-cache-115.

Run from the repository root:
    python3 research/work-items/RE-001-zstd-decompress-cache-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (including 3 self-check instructions picked for this packet);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json and callers.tsv;
7. the model test file passes under plain python3;
8. relocations: no RELATIVE entry points at a packet window;
   the factory vtable lea and the static slot/guard are present;
9. key literals (malloc size, entry-init triple, cmpxchg, free call)
   are present in the excerpts.
Prints ALL CHECKS PASSED or the first failure.
"""

import hashlib
import json
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

EXCERPTS = [
    ("claim-61c1e10.objdump.txt", "0x61c1e10", "0x61c1f0f"),
    ("claim-landing-61c1dec.objdump.txt", "0x61c1dec", "0x61c1e0a"),
    ("create-dctx-628c0b0.objdump.txt", "0x628c0b0", "0x628c1d6"),
    ("table-ctor-61c1f30.objdump.txt", "0x61c1f30", "0x61c20b6"),
    ("static-init-61c20d0.objdump.txt", "0x61c20d0", "0x61c2109"),
    ("getter-61c2120.objdump.txt", "0x61c2120", "0x61c21a6"),
    ("teardown-61c1d60.objdump.txt", "0x61c1d60", "0x61c1dec"),
    ("factory-61c1ce0.objdump.txt", "0x61c1ce0", "0x61c1d5a"),
    ("picker-60d5cd0.objdump.txt", "0x60d5cd0", "0x60d5cf0"),
    ("seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x61C1E10: "f30f1efa",  # endbr64: claim entry
    0x61C1E24: "e8a73ef1ff",  # call picker 0x60d5cd0
    0x61C1E61: "f0480fb15510",  # lock cmpxchg %rdx,0x10(%rbp): the claim
    0x61C1E90: "e81ba20c00",  # call createDCtx 0x628c0b0 (null-slot path)
    0x61C1EE5: "49833c2400",  # cmpq $0x0,(%r12): contention path test
    0x628C0B5: "bff8760100",  # mov $0x176f8,%edi: DCtx malloc size
    0x628C184: "48c7863876000001000008",  # movq $0x8000001,0x7638(%rsi)
    0x61C1F3B: "48c70700000000",  # movq $0x0,(%rdi): table entries null
    0x61C1F94: "e897ee2200",  # call operator new[] for the array
    0x61C1FC3: "48895210",  # mov %rdx,0x10(%rdx): claim word = self
    0x61C2120: "f30f1efa",  # endbr64: getter entry
    0x61C1D60: "f30f1efa",  # endbr64: teardown entry
    0x61C1CE0: "f30f1efa",  # endbr64: factory entry
    0x60D5CD0: "f30f1efa",  # endbr64: picker entry
    0x61C4080: "f30f1efa",  # endbr64: seed entry
}

INSTR_RE = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]*?)\t(.*)$")
CONT_RE = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+?)\s*$")


def parse_instructions(text):
    """objdump text -> {va: bytes-hex}, joining wrapped byte lines."""
    out = {}
    last = None
    for line in text.splitlines():
        m = INSTR_RE.match(line)
        if m:
            va = int(m.group(1), 16)
            raw = m.group(2).replace(" ", "")
            rest = m.group(3).strip()
            if rest == "" and last is not None:
                out[last] += raw
            else:
                out[va] = raw
                last = va
            continue
        # Wrapped long instruction: address + bytes, no mnemonic tab.
        m2 = CONT_RE.match(line)
        if m2 and last is not None:
            out[last] += m2.group(2).replace(" ", "")
    return out


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    prov = json.load(open(os.path.join(ROOT, "provenance/artifacts.json")))
    paths = [f for f in prov["files"] if f["path"] == "artifacts/node/115/hl-node"]
    if not paths or paths[0]["sha256"] != DIGEST:
        fail("provenance digest mismatch")

    # 2. Manifest.
    manifest = {}
    with open(os.path.join(HERE, "MANIFEST.sha256")) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            digest, name = line.split(None, 1)
            manifest[name.strip()] = digest
    on_disk = sorted(
        f for f in os.listdir(HERE)
        if f != "MANIFEST.sha256" and os.path.isfile(os.path.join(HERE, f)))
    if sorted(manifest) != on_disk:
        fail("manifest file set mismatch: manifest=%s disk=%s"
             % (sorted(manifest), on_disk))
    for name, digest in manifest.items():
        got = hashlib.sha256(open(os.path.join(HERE, name), "rb").read()).hexdigest()
        if got != digest:
            fail("manifest digest mismatch for " + name)

    # 3. Excerpts regenerate byte-identically.
    excerpt_instrs = {}
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=" + start,
             "--stop-address=" + stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        disk = open(os.path.join(HERE, name)).read()
        if out != disk:
            fail("excerpt mismatch: " + name)
        excerpt_instrs.update(parse_instructions(disk))

    # 4. Fixed samples + 3 seeded random gate spots, vs fresh objdump
    #    and the raw binary.
    def check_sample(va, expected):
        off = va - 0x1000
        raw = data[off:off + len(bytes.fromhex(expected))].hex()
        if raw != expected:
            fail("raw binary mismatch at %#x: %s != %s" % (va, raw, expected))
        if excerpt_instrs.get(va) != expected:
            fail("excerpt bytes mismatch at %#x: %s != %s"
                 % (va, excerpt_instrs.get(va), expected))

    for va, expected in SAMPLES.items():
        check_sample(va, expected)
    rng = random.Random(0x61C1E10)
    spots = rng.sample(sorted(excerpt_instrs), 3)
    for va in spots:
        check_sample(va, excerpt_instrs[va])
    print("gate spots checked:", ", ".join(hex(v) for v in spots))

    # 5. Frames.
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    frames_disk = open(os.path.join(HERE, "frames.txt")).read()
    for line in frames_disk.splitlines():
        if re.match(r"^[0-9a-f]{8} \S+ \S+ FDE ", line):
            if line not in frames:
                fail("FDE line missing from fresh frames dump: " + line)

    # 6. Census reproduces records.json and callers.tsv.
    sys.path.insert(0, HERE)
    import census as census_mod
    calls, tails, hits, slots = census_mod.scan(os.path.join(ROOT, BIN))
    records = json.load(open(os.path.join(HERE, "records.json")))
    if records["artifact_sha256"] != DIGEST:
        fail("records.json digest mismatch")
    for t in census_mod.TARGETS:
        want = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
        if records["census"].get(hex(t)) != want:
            fail("census mismatch in records.json for " + hex(t))
    tsv_lines = open(os.path.join(HERE, "callers.tsv")).read().splitlines()[1:]
    want_rows = set()
    for t in census_mod.TARGETS:
        for v in calls[t]:
            want_rows.add((hex(t), hex(v), "direct_call"))
        for v in tails[t]:
            want_rows.add((hex(t), hex(v), "tail_jump"))
    got_rows = set()
    for line in tsv_lines:
        parts = line.split("\t")
        got_rows.add((parts[0], parts[1], parts[2]))
    if got_rows != want_rows:
        fail("callers.tsv rows mismatch")

    # 7. Model tests.
    test = subprocess.run(
        ["python3", "tests/test_zstd_decompress_cache_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0 or "tests passed" not in test.stdout:
        fail("model tests failed: " + test.stdout + test.stderr)

    # 8. Relocations: no RELATIVE entry points at a packet window.
    for t in census_mod.TARGETS:
        if slots[t]:
            fail("unexpected RELATIVE slot for " + hex(t))
    factory = open(os.path.join(HERE, "factory-61c1ce0.objdump.txt")).read()
    if "64d7438" not in factory:
        fail("factory vtable lea missing from factory excerpt")
    getter = open(os.path.join(HERE, "getter-61c2120.objdump.txt")).read()
    if "6508900" not in getter or "65088f8" not in getter:
        fail("static slot/guard missing from getter excerpt")

    # 9. Key literals.
    create = open(os.path.join(HERE, "create-dctx-628c0b0.objdump.txt")).read()
    if "176f8" not in create:
        fail("malloc size missing from create excerpt")
    ctor = open(os.path.join(HERE, "table-ctor-61c1f30.objdump.txt")).read()
    for frag in ("movq   $0x0,(%rdx)", "movq   $0xffffffffffffffff,0x8(%rdx)",
                 "mov    %rdx,0x10(%rdx)"):
        if frag not in ctor:
            fail("entry-init fragment missing from table-ctor excerpt: " + frag)
    claim = open(os.path.join(HERE, "claim-61c1e10.objdump.txt")).read()
    if "lock cmpxchg" not in claim:
        fail("cmpxchg missing from claim excerpt")
    teardown = open(os.path.join(HERE, "teardown-61c1d60.objdump.txt")).read()
    if "628c1e0" not in teardown:
        fail("freeDCtx call missing from teardown excerpt")
    if "GetCachedZSTDUncompressData" not in json.dumps(records):
        fail("catalogue attribution missing from records.json")

    # 10. Model constants.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import zstd_decompress_cache_115 as model
    if model.table_params(9) != (4, 16, 0x408):
        fail("model table_params mismatch")
    if model.mersenne_step(0x7FFFFFFF) != 0x7FFFFFFF:
        fail("model mersenne_step mismatch")
    if model.cpuid_picker(0, 0) != -1:
        fail("model cpuid_picker mismatch")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
