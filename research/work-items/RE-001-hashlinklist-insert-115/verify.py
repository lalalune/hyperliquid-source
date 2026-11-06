"""Packet checker for RE-001-hashlinklist-insert-115.

Run from the repository root:
    python3 research/work-items/RE-001-hashlinklist-insert-115/verify.py

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
9. the packet literals re-read from the binary;
10. the model test file passes under pytest.
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
    ("host-605f700.objdump.txt", "0x605f700", "0x605fe21"),
    ("host-cleanup-605f6d6.objdump.txt", "0x605f6d6", "0x605f700"),
    ("ctor-605eb40.objdump.txt", "0x605eb40", "0x605ec19"),
    ("dtor-605ea00.objdump.txt", "0x605ea00", "0x605ea23"),
    ("varint32-61bd4f0.objdump.txt", "0x61bd4f0", "0x61bd53b"),
    ("transform-5e9af30.objdump.txt", "0x5e9af30", "0x5e9b142"),
    ("wyhash-61c38a0.objdump.txt", "0x61c38a0", "0x61c3bb9"),
    ("hex-encode-61c7e30.objdump.txt", "0x61c7e30", "0x61c7fb6"),
    ("index-builder-605f290.objdump.txt", "0x605f290", "0x605f33a"),
    ("index-insert-605f340.objdump.txt", "0x605f340", "0x605f6d5"),
    ("log-gate-5fcef60.objdump.txt", "0x5fcef60", "0x5fcf043"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x605F700: "f30f1efa",  # endbr64: host entry
    0x605F76C: "e87fdd1500",  # call varint32 decoder 0x61bd4f0 (first decode)
    0x605F9CF: "e8cc3e1600",  # call hash64 0x61c38a0
    0x605FB54: "e8e7f7ffff",  # call index insert 0x605f340
    0x605FBAB: "e8e0f6ffff",  # call index builder 0x605f290
    0x605FC81: "e86ad81500",  # call varint32 decoder 0x61bd4f0 (log-path re-decode)
    0x605FCC1: "e86a811600",  # call hex encoder 0x61c7e30
    0x605FD44: "e817f2f6ff",  # call log gate 0x5fcef60
    0x605FE1C: "e9b5f8ffff",  # jmp host cleanup 0x605f6d6
    0x605EB6B: "488d15f6354700",  # lea vtable 0x64d2168: ctor vtable install
    0x61BD4F0: "f30f1efa",  # endbr64: varint32 entry
    0x5E9AF30: "f30f1efa",  # endbr64: canonical transform entry
    0x61C38A0: "f30f1efa",  # endbr64: hash entry
    0x61C38B4: "48b9b8fe6c3923",  # movabs $0xbe4ba423396cfeb8,%rcx (first 7 bytes; objdump wraps the 10-byte instruction)
    0x61C38EF: "48baf979379eb1",  # movabs $0x165667b19e3779f9,%rdx (first 7 bytes; objdump wraps the 10-byte instruction)
}

RELOC_SLOTS = [
    0x64D2160,
    0x64D2168, 0x64D2170, 0x64D2178, 0x64D2180, 0x64D2188, 0x64D2190,
    0x64D2198, 0x64D21A0, 0x64D21A8, 0x64D21B0, 0x64D21B8, 0x64D21C0,
    0x64D21C8, 0x64D21D0, 0x64D21D8, 0x64D21E0, 0x64D21E8, 0x64D21F0,
    0x64D21F8, 0x64D2200, 0x64D2208, 0x64D2210, 0x64D2218,
    0x64D2058,
    0x64D2228,
    0x64D2230, 0x64D2238, 0x64D2240, 0x64D2248, 0x64D2250, 0x64D2258,
    0x64D2260, 0x64D2268, 0x64D2270, 0x64D2278, 0x64D2280, 0x64D2288,
    0x64D2290, 0x64D2298, 0x64D22A0, 0x64D22A8, 0x64D22B0, 0x64D22B8,
    0x64D22C0, 0x64D22C8, 0x64D22D0, 0x64D22D8, 0x64D22E0,
    0x64D2070,
    0x64D3BB8,
    0x64D3BC0, 0x64D3BC8, 0x64D3BD0, 0x64D3BD8, 0x64D3BE0, 0x64D3BE8,
    0x64D3BF0, 0x64D3BF8, 0x64D3C00, 0x64D3C08, 0x64D3C10, 0x64D3C18,
    0x64D3C20, 0x64D3C28, 0x64D3C30, 0x64D3C38, 0x64D3C40, 0x64D3C48,
    0x64D3C50, 0x64D3C58, 0x64D3C60, 0x64D3C68,
    0x64D3AE8,
    0x64ED690,
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
    if cstr(relocs[0x64D2058]) != records["hashlinklistrep_vtable"]["typeinfo_name"]:
        fail("HashLinkListRep typeinfo name mismatch")
    if cstr(relocs[0x64D2070]) != records["factory_vtable"]["typeinfo_name"]:
        fail("HashLinkListRepFactory typeinfo name mismatch")
    if cstr(relocs[0x64D3AE8]) != records["ikst_vtable"]["typeinfo_name"]:
        fail("InternalKeySliceTransform typeinfo name mismatch")
    saved_vt = {}
    for line in open(os.path.join(HERE, "vtables.tsv")):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 5 and parts[0].startswith("0x"):
            saved_vt[(parts[0], parts[1])] = parts[3]
    for base, count in ((0x64D2168, 0xB8), (0x64D2230, 0xB8), (0x64D3BC0, 0xB0)):
        for off in range(0x00, count, 0x08):
            slot = base + off
            key = ("0x%x" % base, "0x%02x" % off)
            if saved_vt.get(key) != "0x%x" % relocs[slot]:
                fail("vtable slot %s %s mismatch" % key)
    if relocs[0x64ED690] != 0x5E9AF30:
        fail("GOT self-reference mismatch")
    # Literals re-read (.rodata VA == file offset)
    fmt = data[0x9638E8:data.find(b"\x00", 0x9638E8)].decode()
    if fmt != "HashLinkedList bucket %zu has more than %d entries. Key to insert: %s":
        fail("log format literal mismatch: %r" % fmt)
    if data[0x43A3E1:data.find(b"\x00", 0x43A3E1)].decode() != "HashLinkListRepFactory":
        fail("factory name literal mismatch")
    if data[0x4394CC:data.find(b"\x00", 0x4394CC)].decode() != "hash_linkedlist":
        fail("factory nickname literal mismatch")
    # Model tests pass under pytest
    tests = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", os.path.join(
            ROOT, "tests", "test_hashlinklist_insert_115.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    if tests.returncode != 0:
        fail("model tests failed:\n%s%s" % (tests.stdout, tests.stderr))
    print("model tests: %s" % tests.stdout.strip().splitlines()[-1])
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
