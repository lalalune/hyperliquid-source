"""Packet checker for RE-001-chain-histogram-snapshot-115.

Run from the repository root:
    python3 research/work-items/RE-001-chain-histogram-snapshot-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (fixed samples plus 3 seeded random gate spots);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json (all 13 targets);
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
    ("host-605feb0.objdump.txt", "0x605feb0", "0x6060199"),
    ("arena-ctor-605dd90.objdump.txt", "0x605dd90", "0x605dfcd"),
    ("index-builder-605f290.objdump.txt", "0x605f290", "0x605f33a"),
    ("index-insert-605f340.objdump.txt", "0x605f340", "0x605f6d5"),
    ("log-gate-5fcef60.objdump.txt", "0x5fcef60", "0x5fcf043"),
    ("size-normalizer-605cfa0.objdump.txt", "0x605cfa0", "0x605cfd6"),
    ("counter-add-605e830.objdump.txt", "0x605e830", "0x605e859"),
    ("thread-seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
    ("bucket_count_init.txt", "0x606b080", "0x606b0a2"),
    ("locked_init.txt", "0x606b0c0", "0x606b10a"),
    ("record_thunk.txt", "0x606b1c0", "0x606b1cd"),
    ("record.txt", "0x606b130", "0x606b1b3"),
    ("tostring_entry.txt", "0x606bc90", "0x606bcd3"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x605FEB0: "f30f1efa",  # endbr64: host entry
    0x605FF06: "e885deffff",  # call arena ctor 0x605dd90
    0x605FF2D: "e85ef3ffff",  # call index builder 0x605f290
    0x606004C: "e86fb10000",  # call record thunk 0x606b1c0
    0x606007D: "e80ebc0000",  # call ToString entry 0x606bc90
    0x6060094: "e8c7eef6ff",  # call log gate 0x5fcef60
    0x605DDB5: "488903",  # mov %rax,(%rbx): Arena vtable install
    0x605CFA4: "b800100000",  # mov $0x1000,%eax: size floor
    0x605E846: "f048017708",  # lock add %rsi,0x8(%rdi): counter add
    0x61C40D5: "ba07690fc7",  # mov $0xc70f6907,%edx: hash seed
    0x605F2A0: "6644894302",  # mov %r8w,0x2(%rbx): divisor store
    0x605F4F3: "4869d2a7410000",  # imul $0x41a7,%rdx,%rdx: hash multiply
    0x5FCF003: "ff5040",  # call *0x40(%rax): log level gate
    0x5FCF039: "ff5028",  # call *0x28(%rax): log emit
    0x606B130: "f30f1efa",  # endbr64: record entry
}

RELOC_SLOTS = [
    0x64D2160,
    0x64D2168, 0x64D2170, 0x64D2178, 0x64D2180, 0x64D2188, 0x64D2190,
    0x64D2198, 0x64D21A0, 0x64D21A8, 0x64D21B0, 0x64D21B8, 0x64D21C0,
    0x64D21C8, 0x64D21D0, 0x64D21D8, 0x64D21E0, 0x64D21E8, 0x64D21F0,
    0x64D21F8, 0x64D2200, 0x64D2208, 0x64D2210, 0x64D2218,
    0x64D2058,
    0x64D1FB0,
    0x64D1FB8, 0x64D1FC0, 0x64D1FC8, 0x64D1FD0, 0x64D1FD8,
    0x64D1F98,
    0x64D2088,
    0x64D2090, 0x64D2098, 0x64D20A0, 0x64D20A8, 0x64D20B0, 0x64D20B8,
    0x64D20C0, 0x64D20C8, 0x64D20D0, 0x64D20D8, 0x64D20E0,
    0x64D2010,
    0x64D2B78,
    0x64D2B88, 0x64D2B90, 0x64D2BA0, 0x64D2BB0,
    0x64D2B60,
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
    if cstr(relocs[0x64D1F98]) != records["arena_vtable"]["typeinfo_name"]:
        fail("Arena typeinfo name mismatch")
    if cstr(relocs[0x64D2010]) != records["fulllistiterator_vtable"]["typeinfo_name"]:
        fail("FullListIterator typeinfo name mismatch")
    if cstr(relocs[0x64D2B60]) != records["histogramimpl_vtable"]["typeinfo_name"]:
        fail("HistogramImpl typeinfo name mismatch")
    saved_vt = {}
    for line in open(os.path.join(HERE, "vtables.tsv")):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 5 and parts[0].startswith("0x"):
            saved_vt[(parts[0], parts[1])] = parts[3]
    for base, count in ((0x64D2168, 0xB8), (0x64D1FB8, 0x28), (0x64D2090, 0x58)):
        for off in range(0x00, count, 0x08):
            slot = base + off
            key = ("0x%x" % base, "0x%02x" % off)
            if saved_vt.get(key) != "0x%x" % relocs[slot]:
                fail("vtable slot %s %s mismatch" % key)
    for off, slot in ((0x10, 0x64D2B90), (0x20, 0x64D2BA0), (0x30, 0x64D2BB0)):
        key = ("0x64d2b80", "0x%02x" % off)
        if saved_vt.get(key) != "0x%x" % relocs[slot]:
            fail("HistogramImpl vtable slot %s mismatch" % key[1])
    # Literals re-read (.rodata VA == file offset)
    fmt = data[0x9641A8:data.find(b"\x00", 0x9641A8)].decode()
    if fmt != "hashLinkedList Entry distribution among buckets: %s":
        fail("log format literal mismatch: %r" % fmt)
    if data[0x453950:0x453960] != struct.pack("<QQ", 1, 2):
        fail("boundaries seed literal mismatch")
    # Model tests pass
    tests = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tests",
                                      "test_chain_histogram_snapshot_115.py")],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    m = re.search(r"FAILED (\d+)", tests)
    if not m or int(m.group(1)) != 0:
        fail("model tests failed:\n%s" % tests)
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
