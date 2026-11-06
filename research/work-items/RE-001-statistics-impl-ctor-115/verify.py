"""Packet checker for RE-001-statistics-impl-ctor-115.

Run from the repository root:
    python3 research/work-items/RE-001-statistics-impl-ctor-115/verify.py

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
9. the packet literals re-read from the binary;
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
    ("ctor-6071a00.objdump.txt", "0x6071a00", "0x6071b60"),
    ("ctor-cleanup-6071952.objdump.txt", "0x6071952", "0x60719f2"),
    ("builder-60716d0.objdump.txt", "0x60716d0", "0x6071952"),
    ("shared_init.txt", "0x606b020", "0x606b07c"),
    ("bucket_count_init.txt", "0x606b080", "0x606b0a2"),
    ("locked_init.txt", "0x606b0c0", "0x606b10a"),
    ("allocator-60d5d50.objdump.txt", "0x60d5d50", "0x60d5db0"),
    ("free-60d5db0.objdump.txt", "0x60d5db0", "0x60d5db9"),
    ("destroyer-606fd30.objdump.txt", "0x606fd30", "0x606fd94"),
    ("noop-dtor-5d89570.objdump.txt", "0x5d89570", "0x5d89575"),
    ("mutex-init-60d50c0.objdump.txt", "0x60d50c0", "0x60d5157"),
    ("mutex-destroy-60d5170.objdump.txt", "0x60d5170", "0x60d5200"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x60716E2: "48c70700000000",  # movq $0x0,(%rdi): entry zeroes *out
    0x6071719: "894808",  # mov %ecx,0x8(%rax): exponent store
    0x6071763: "48895038",  # mov %rdx,0x38(%rax): bucket_count store
    0x607174B: "e800460600",  # call allocator 0x60d5d50
    0x60717FA: "4885ed",  # test %rbp,%rbp: dead-release test
    0x6071A32: "c6472003",  # movb $0x3,0x20(%rdi): level byte 3
    0x6071A4A: "488907",  # mov %rax,(%rdi): StatisticsImpl vtable install
    0x606B096: "48898790030000",  # mov %rax,0x390(%rdi): bucket-count write
    0x606FD39: "48696ff840ce00",  # imul $0xce40,-0x8(%rdi),%rbp (7 bytes shown)
    0x5D89570: "f30f1efa",  # endbr64: no-op dtor entry
    0x60D5D78: "be40000000",  # mov $0x40,%esi: 64-byte alignment
    0x6071952: "4889ef",  # mov %rbp,%rdi: cleanup disposes the string
}

RELOC_SLOTS = [
    0x64D2B78,
    0x64D2B80, 0x64D2B88, 0x64D2B90, 0x64D2B98, 0x64D2BA0, 0x64D2BA8,
    0x64D2BB0, 0x64D2BB8, 0x64D2BC0, 0x64D2BC8, 0x64D2BD0, 0x64D2BD8,
    0x64D2BE0, 0x64D2BE8, 0x64D2BF0, 0x64D2BF8,
    0x64D2B60,
    0x64ED2B8,
    0x64D2D80,
    0x64D2D00,
]


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
            fail("sample %s objdump mismatch" % hex(va))
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
    if set(blocks) != set(cen):
        fail("census target set mismatch")
    for target, want in cen.items():
        got = blocks[target]
        if any(got[k] != want[k] for k in
               ("direct_calls", "tail_jumps",
                "qword_hits_file_offsets", "relative_slots")):
            fail("census mismatch for %s" % target)
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
    if cstr(relocs[0x64D2B60]) != records["record_vtable"]["typeinfo_name"]:
        fail("HistogramImpl typeinfo name mismatch")
    if cstr(relocs[0x64D2D00]) != records["statisticsimpl_vtable"]["typeinfo_name"]:
        fail("StatisticsImpl typeinfo name mismatch")
    saved_vt = {}
    for line in open(os.path.join(HERE, "vtables.tsv")):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 5 and parts[0].startswith("0x"):
            saved_vt[(parts[0], parts[1])] = parts[3]
    for off in range(0x00, 0x80, 0x08):
        slot = 0x64D2B80 + off
        key = ("0x64d2b80", "0x%02x" % off)
        if saved_vt.get(key) != "0x%x" % relocs[slot]:
            fail("vtable slot %s mismatch" % key[1])
    # Literals re-read
    if data[0x4539E0:0x4539F0] != b"StatisticsOption":
        fail("literal at 0x4539e0 mismatch")
    if data[0x97877C] != 0:
        fail("type byte at 0x97877c mismatch")
    # Model tests pass
    tests = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tests",
                                      "test_statistics_impl_ctor_115.py")],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    if "failed" in tests and "0 failed" not in tests:
        fail("model tests failed:\n%s" % tests)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
