"""Packet checker for RE-001-statistics-shard-record-115.

Run from the repository root:
    python3 research/work-items/RE-001-statistics-shard-record-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (fixed samples plus 3 seeded random gate spots);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json (all 12 targets);
7. relocations.txt re-derives from .rela.dyn;
8. vtables.tsv re-derives from .rela.dyn and the typeinfo names;
9. boundaries.tsv matches the model's generated boundaries;
10. the model test file passes under plain python3.
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
    ("ticker-record-606fba0.objdump.txt", "0x606fba0", "0x606fc59"),
    ("histogram-record-606fef0.objdump.txt", "0x606fef0", "0x606ffce"),
    ("histogram-wrapper-606ffd0.objdump.txt", "0x606ffd0", "0x60700c4"),
    ("thread-seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
    ("record_thunk.txt", "0x606b1c0", "0x606b1cd"),
    ("record.txt", "0x606b130", "0x606b1b3"),
    ("ctor-6071a00.objdump.txt", "0x6071a00", "0x6071b60"),
    ("builder-60716d0.objdump.txt", "0x60716d0", "0x6071952"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x60D5CD0: "f30f1efa",  # endbr64: picker entry
    0x60D5CD7: "0fa2",  # cpuid: leaf 0
    0x60D5CE9: "c1eb18",  # shr $0x18,%ebx: logical-processor count
    0x606FBA8: "81feb1000000",  # cmp $0xb1,%esi: ticker id gate
    0x606FBC4: "e807610600",  # call picker 0x60d5cd0
    0x606FBF1: "f04c0120",  # lock add %r12,(%rax): ticker counter add
    0x606FC20: "e85b441500",  # call seed 0x61c4080 (fallback)
    0x606FEF8: "3c01",  # cmp $0x1,%al: histogram level gate
    0x606FF52: "ff5020",  # call *0x20(%rax): record thunk via slot 0x20
    0x606FFE4: "488d1505ffffff",  # lea 0x606fef0,%rdx: canonical check
    0x6070003: "e8c85c0600",  # call picker 0x60d5cd0 (wrapper)
    0x61C40D5: "ba07690fc7",  # mov $0xc70f6907,%edx: hash seed
    0x606B1C8: "e963ffffff",  # jmp 0x606b130: thunk to record impl
    0x6071A32: "c6472003",  # movb $0x3,0x20(%rdi): level byte 3
    0x6071719: "894808",  # mov %ecx,0x8(%rax): exponent store
}

RELOC_SLOTS = (
    [0x64D2D80, 0x64D2D00] + [0x64D2D88 + i * 8 for i in range(32)] +
    [0x64D2B78, 0x64D2B60] + [0x64D2B80 + i * 8 for i in range(16)]
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
    random.seed(20261106)
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
        end = data.find(b"\x00", va)
        return data[va:end].decode()
    if cstr(relocs[0x64D2D00]) != records["statisticsimpl_vtable"]["typeinfo_name"]:
        fail("StatisticsImpl typeinfo name mismatch")
    if cstr(relocs[0x64D2B60]) != records["histogramimpl_vtable"]["typeinfo_name"]:
        fail("HistogramImpl typeinfo name mismatch")
    saved_vt = {}
    for line in open(os.path.join(HERE, "vtables.tsv")):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 5 and parts[0].startswith("0x"):
            saved_vt[(parts[0], parts[1])] = parts[3]
    for base, count in ((0x64D2D88, 32), (0x64D2B80, 16)):
        for off in range(0x00, count * 8, 0x08):
            slot = base + off
            key = ("0x%x" % base, "0x%02x" % off)
            if saved_vt.get(key) != "0x%x" % relocs[slot]:
                fail("vtable slot %s %s mismatch" % key)
    # Boundaries.tsv matches the model generator
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import statistics_shard_record_115 as model
    rows = []
    for line in open(os.path.join(HERE, "boundaries.tsv")):
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            rows.append(int(parts[1]))
    if rows != model.BOUNDARIES:
        fail("boundaries.tsv does not match the model generator")
    # Model tests pass
    tests = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tests",
                                      "test_statistics_shard_record_115.py")],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    m = re.search(r"(\d+) failed", tests)
    if not m or int(m.group(1)) != 0:
        fail("model tests failed:\n%s" % tests)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
