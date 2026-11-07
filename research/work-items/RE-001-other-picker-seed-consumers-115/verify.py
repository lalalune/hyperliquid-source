"""Packet checker for RE-001-other-picker-seed-consumers-115.

Run from the repository root:
    python3 research/work-items/RE-001-other-picker-seed-consumers-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (fixed samples plus 3 seeded random gate spots);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json (all 11 targets);
7. relocations.txt re-derives from .rela.dyn;
8. vtables.tsv re-derives from .rela.dyn and the typeinfo names;
9. the oneshot path literal and the node descriptor literal re-derive;
10. callers.tsv equals a fresh census.py run;
11. the model test file passes under plain python3.
Prints ALL CHECKS PASSED or the first failure.
"""

import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

EXCERPTS = [
    ("picker-60d5cd0.objdump.txt", "0x60d5cd0", "0x60d5cf0"),
    ("thread-seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
    ("seed-host-5f6b000.objdump.txt", "0x5f6b000", "0x5f6b516"),
    ("seed-host-5f999d0.objdump.txt", "0x5f999d0", "0x5f9a478"),
    ("seed-host-5fca940.objdump.txt", "0x5fca940", "0x5fcabdc"),
    ("seed-host-6063150.objdump.txt", "0x6063150", "0x6063229"),
    ("seed-host-6066b80.objdump.txt", "0x6066b80", "0x6066d61"),
    ("seed-host-6066f20.objdump.txt", "0x6066f20", "0x6067450"),
    ("seed-host-60e5610.objdump.txt", "0x60e5610", "0x60e5a39"),
    ("seed-host-60f4a00.objdump.txt", "0x60f4a00", "0x60f4cb5"),
    ("seed-host-616f960.objdump.txt", "0x616f960", "0x616fb83"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x60D5CD0: "f30f1efa",  # endbr64: picker entry
    0x61C4080: "f30f1efa",  # endbr64: seed getter entry
    0x5F6B000: "f30f1efa",  # endbr64: oneshot builder entry
    0x5F6B06A: "e811902500",  # call seed 0x61c4080 (builder site 1)
    0x5F6B11A: "e8618f2500",  # call seed 0x61c4080 (builder site 2)
    0x5F999D0: "f30f1efa",  # endbr64: oneshot lookup entry
    0x5F9A116: "e8659f2200",  # call seed 0x61c4080 (lookup site)
    0x5FCA940: "f30f1efa",  # endbr64: flag wait entry
    0x5FCAA75: "e806961f00",  # call seed 0x61c4080 (flag wait site)
    0x6063150: "f30f1efa",  # endbr64: SkipListRep slot 0 entry
    0x6063165: "e8160f1600",  # call seed 0x61c4080 (height draw site)
    0x6066B80: "f30f1efa",  # endbr64: randomised descent entry
    0x6066BC9: "e8b2d41500",  # call seed 0x61c4080 (descent site)
    0x6066F20: "f30f1efa",  # endbr64: SkipListRep slot 14 entry
    0x60671B1: "e8cace1500",  # call seed 0x61c4080 (sampler site)
    0x60E5610: "f30f1efa",  # endbr64: ZSTD gate entry
    0x60E56F5: "e886e90d00",  # call seed 0x61c4080 (ZSTD gate site)
    0x60F4A00: "f30f1efa",  # endbr64: bitmap-node ctor entry
    0x60F4B2A: "e851f50c00",  # call seed 0x61c4080 (bitmap site)
    0x616F960: "f30f1efa",  # endbr64: sample-flag ctor entry
    0x616FB33: "e848450500",  # call seed 0x61c4080 (sample-flag site)
}

RELOC_SLOTS = (
    [0x64D26E0, 0x64D25F8] + [0x64D26E8 + i * 8 for i in range(23)] +
    [0x64CCE28, 0x64CCD70] + [0x64CCE30 + i * 8 for i in range(24)]
)


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
    records = json.load(open(os.path.join(HERE, "records.json")))
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    # MANIFEST
    manifest = {}
    for line in open(os.path.join(HERE, "MANIFEST.sha256")):
        parts = line.split()
        if len(parts) == 2:
            manifest[parts[1]] = parts[0]
    for name, want in manifest.items():
        got = hashlib.sha256(open(os.path.join(HERE, name), "rb").read()).hexdigest()
        if got != want:
            fail("manifest mismatch for %s" % name)
    # Excerpt regeneration
    fresh = {}
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=" + start, "--stop-address=" + stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        fresh[name] = out
        saved = open(os.path.join(HERE, name)).read()
        if out != saved:
            fail("excerpt does not regenerate: %s" % name)
    # Sampled instructions byte-for-byte vs fresh objdump and raw binary
    out = "".join(fresh.values())
    for va, want in SAMPLES.items():
        m = re.search(r"^\s*%x:\t([0-9a-f ]+)\t" % va, out, re.M)
        if not m:
            fail("sample %s missing from fresh objdump" % hex(va))
        if m.group(1).replace(" ", "") != want:
            fail("sample %s objdump mismatch: got %s want %s"
                 % (hex(va), m.group(1).replace(" ", ""), want))
        off = va - 0x1000  # .text file offset = VA - 0x1000
        if data[off:off + len(bytes.fromhex(want))].hex() != want:
            fail("sample %s raw binary mismatch" % hex(va))
    # Seeded random gate spots: 3 instructions picked from the excerpts
    candidates = []
    for name, _, _ in EXCERPTS:
        for line in open(os.path.join(HERE, name)):
            m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t\S", line)
            if m:
                candidates.append((int(m.group(1), 16),
                                   m.group(2).replace(" ", "")))
    random.seed(20261107)
    for va, want in random.sample(candidates, 3):
        m = re.search(r"^\s*%x:\t([0-9a-f ]+)\t" % va, out, re.M)
        if not m or m.group(1).replace(" ", "") != want:
            fail("random gate spot %s objdump mismatch" % hex(va))
        off = va - 0x1000
        if data[off:off + len(bytes.fromhex(want))].hex() != want:
            fail("random gate spot %s raw binary mismatch" % hex(va))
        print("gate spot OK: 0x%x (%s)" % (va, want))
    # Frames rows vs fresh objdump frames dump
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    saved = [ln for ln in open(os.path.join(HERE, "frames.txt")).read().splitlines() if ln]
    for row in saved:
        if row not in frames:
            fail("frames row missing from fresh objdump: %s" % row)
    # Census reproduces records.json
    census = subprocess.run(
        [sys.executable, os.path.join(HERE, "census.py"), BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    blocks = {}
    current = None
    for line in census.splitlines():
        m = re.match(r"target (0x[0-9a-f]+)", line)
        if m:
            current = m.group(1)
            blocks[current] = {}
            continue
        m = re.match(r"  direct calls: (.*)", line)
        if m and current:
            blocks[current]["direct_calls"] = [] if m.group(1) == "(none)" else m.group(1).split()
        m = re.match(r"  tail jumps: (.*)", line)
        if m and current:
            blocks[current]["tail_jumps"] = [] if m.group(1) == "(none)" else m.group(1).split()
        m = re.match(r"  qword hits \(file offsets\): (.*)", line)
        if m and current:
            blocks[current]["qword_hits_file_offsets"] = [] if m.group(1) == "(none)" else m.group(1).split()
        m = re.match(r"  RELATIVE slots: (.*)", line)
        if m and current:
            blocks[current]["relative_slots"] = [] if m.group(1) == "(none)" else m.group(1).split()
    cen = records["census"]
    if set(blocks) != set(v["target"] for v in cen.values()):
        fail("census target set mismatch")
    for name, want in cen.items():
        got = blocks[want["target"]]
        if any(got[k] != want[k] for k in
               ("direct_calls", "tail_jumps",
                "qword_hits_file_offsets", "relative_slots")):
            fail("census mismatch for %s" % name)
    # callers.tsv equals a fresh census run
    saved_callers = open(os.path.join(HERE, "callers.tsv")).read()
    if census != saved_callers:
        fail("callers.tsv does not match a fresh census run")
    # Relocations re-derive from .rela.dyn
    RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8
    relocs = {}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if ro in RELOC_SLOTS and (info & 0xFFFFFFFF) == 8:
            relocs[ro] = add
    saved_relocs = {}
    for line in open(os.path.join(HERE, "relocations.txt")):
        parts = line.split()
        if len(parts) == 3:
            saved_relocs[int(parts[0], 16)] = int(parts[2], 16)
    if saved_relocs != relocs:
        fail("relocations mismatch: %r vs %r" % (saved_relocs, relocs))
    # Vtables re-derive
    def cstr(va):
        # .rodata VA == file offset in this binary (verified by readelf).
        end = data.find(b"\x00", va)
        return data[va:end].decode()
    if cstr(relocs[0x64D25F8]) != records["skiplistrep_vtable"]["typeinfo_name"]:
        fail("SkipListRep typeinfo name mismatch")
    if cstr(relocs[0x64CCD70]) != records["leveliterator_vtable"]["typeinfo_name"]:
        fail("LevelIterator typeinfo name mismatch")
    saved_vt = {}
    for line in open(os.path.join(HERE, "vtables.tsv")):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 5 and parts[0].startswith("0x"):
            saved_vt[(parts[0], parts[1])] = parts[3]
    for base, count in ((0x64D26E8, 23), (0x64CCE30, 24)):
        for off in range(0x00, count * 8, 0x08):
            slot = base + off
            key = ("0x%x" % base, "0x%02x" % off)
            if saved_vt.get(key) != "0x%x" % relocs[slot]:
                fail("vtable slot %s %s mismatch" % key)
    # Literals re-derive from the raw binary
    lit = records["literals"]
    if data[0x4376FD] != 0:
        fail("oneshot path pointer byte is not 0x00")
    if cstr(0x4376FE) != lit["oneshot_path_string"]:
        fail("oneshot path string mismatch")
    if struct.unpack_from("<II", data, 0x459A38) != (
            lit["node_descriptor_0x459a38"]["low_u32"],
            lit["node_descriptor_0x459a38"]["high_u32"]):
        fail("node descriptor mismatch")
    # Model tests pass (unittest writes to stderr; require exit 0 and OK)
    tests = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tests",
                                      "test_other_seed_consumers_115.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    if tests.returncode != 0 or "\nOK" not in tests.stderr:
        fail("model tests failed:\n%s%s" % (tests.stdout, tests.stderr))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
