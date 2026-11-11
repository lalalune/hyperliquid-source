"""Packet checker for RE-001-plain-table-index-115.

Run from the repository root:
    python3 research/work-items/RE-001-plain-table-index-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically (fresh and re-shipped);
4. sampled instructions match a fresh objdump run and the raw binary
   (fixed samples plus 3 seeded random gate spots);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json (all 18 targets);
7. relocations.txt re-derives from .rela.dyn;
8. vtables.tsv re-derives from .rela.dyn and the typeinfo name;
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
    ("host-6198900.objdump.txt", "0x6198900", "0x6198ce2"),
    ("host-cleanup-6198ce2.objdump.txt", "0x6198ce2", "0x6198d34"),
    ("host-6198d40.objdump.txt", "0x6198d40", "0x6198f4d"),
    ("subrec-6198790.objdump.txt", "0x6198790", "0x6198853"),
    ("pushback-61985f0.objdump.txt", "0x61985f0", "0x6198775"),
    ("throwstub-6198776.objdump.txt", "0x6198776", "0x6198790"),
    ("bucket-count-6198230.objdump.txt", "0x6198230", "0x6198283"),
    ("gather-6198290.objdump.txt", "0x6198290", "0x6198364"),
    ("serializer-6198370.objdump.txt", "0x6198370", "0x61985e2"),
    ("varint-enc-61bd410.objdump.txt", "0x61bd410", "0x61bd4e9"),
    ("log-5fceda0.objdump.txt", "0x5fceda0", "0x5fcee93"),
    ("record.txt", "0x606b130", "0x606b1b3"),
    ("record_thunk.txt", "0x606b1c0", "0x606b1cd"),
    ("bucket_index.txt", "0x606afa0", "0x606b013"),
    ("percentile.txt", "0x606b260", "0x606b4fe"),
    ("median.txt", "0x606b500", "0x606b511"),
    ("average.txt", "0x606b540", "0x606b5b9"),
    ("stddev.txt", "0x606b5d0", "0x606b6ae"),
    ("renderer.txt", "0x606b6f0", "0x606bc8d"),
    ("tostring_entry.txt", "0x606bc90", "0x606bcd3"),
    ("hex-encode-61c7e30.objdump.txt", "0x61c7e30", "0x61c7fb6"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x6198900: "f30f1efa",  # endbr64: record host entry
    0x61989F1: "ba8d010000",  # mov $0x18d,%edx (hash seed 397)
    0x61989F6: "e8a5aa0200",  # call rocksdb::Hash 0x61c34a0
    0x6198AE7: "e8d426edff",  # call record thunk 0x606b1c0 (record host)
    0x6198E2A: "e89123edff",  # call record thunk 0x606b1c0 (dump host)
    0x6198E3A: "e8512eedff",  # call ToString 0x606bc90
    0x6198E60: "e83b5fe3ff",  # call log dispatcher 0x5fceda0
    0x619843E: "e8cd4f0200",  # call varint encoder 0x61bd410
    0x6198230: "f30f1efa",  # endbr64: bucket-count entry
    0x6198290: "f30f1efa",  # endbr64: gather entry
    0x6198370: "f30f1efa",  # endbr64: serializer entry
    0x61BD410: "f30f1efa",  # endbr64: varint encoder entry
    0x5FCEDA0: "f30f1efa",  # endbr64: log dispatcher entry
    0x6198790: "f30f1efa",  # endbr64: subrec append entry
    0x606B1C0: "f30f1efa",  # endbr64: record thunk entry
}

RELOC_SLOTS = [
    0x64D2B78,  # HistogramImpl vtable -0x8: typeinfo -> 0x64d2b58
    0x64D2B80, 0x64D2B88, 0x64D2B90, 0x64D2B98, 0x64D2BA0, 0x64D2BA8,
    0x64D2BB0, 0x64D2BB8, 0x64D2BC0, 0x64D2BC8, 0x64D2BD0, 0x64D2BD8,
    0x64D2BE0, 0x64D2BE8, 0x64D2BF0, 0x64D2BF8,  # 16 vtable slots
    0x64D2B60,  # HistogramImpl typeinfo +0x8: name -> 0x9753f0
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
        if len(parts) == 2 and parts[0].startswith("0x"):
            saved_relocs[int(parts[0], 16)] = int(parts[1], 16)
    if saved_relocs != relocs:
        fail("relocations mismatch: %r vs %r" % (saved_relocs, relocs))
    # Vtables re-derive
    secs = {}
    out = subprocess.run(["readelf", "-S", "-W", os.path.join(ROOT, BIN)],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+"
                     r"([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            secs[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16),
                                int(m.group(4), 16))

    def read_vaddr(addr, n):
        for v, o, s in secs.values():
            if v <= addr < v + s:
                return data[o + (addr - v): o + (addr - v) + n]
        raise ValueError("address %#x not in any section" % addr)

    def cstr(va):
        out = bytearray()
        cur = va
        while True:
            b = read_vaddr(cur, 1)[0]
            if b == 0:
                return bytes(out).decode("latin1")
            out.append(b)
            cur += 1

    if cstr(relocs[0x64D2B60]) != records["histogram_typeinfo_name"]:
        fail("histogram typeinfo name mismatch")
    saved_vt = {}
    for line in open(os.path.join(HERE, "vtables.tsv")):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 4 and parts[0].startswith("0x"):
            saved_vt[(parts[0], parts[1])] = parts[3]
    for off in range(0x00, 0x80, 0x08):
        slot = 0x64D2B80 + off
        key = ("0x%x" % 0x64D2B80, "0x%02x" % off)
        if saved_vt.get(key) != "0x%x" % relocs[slot]:
            fail("vtable slot %s %s mismatch" % key)
    if relocs[0x64D2B78] != 0x64D2B58:
        fail("histogram vtable typeinfo pointer mismatch")
    # Literals re-read from the binary
    if cstr(0x957830) != "[%s:101] Number of Keys per prefix Histogram: %s":
        fail("histogram log format mismatch")
    if cstr(0x9577F8) != "[%s:202] hash table size: %u, suffix_map length %u":
        fail("hash-table-size log format mismatch")
    if cstr(0x958120) != "[%s:156] Reserving %u bytes for plain table's sub_index":
        fail("reserve log format mismatch")
    if cstr(0x9577D0) != "table/plain/plain_table_index.cc":
        fail("source file literal mismatch")
    if read_vaddr(0x9577C8, 8) != b"rocksdb/":
        fail("rocksdb/ prefix mismatch")
    if cstr(0x9663A0) != "Count: %lu Average: %.4f  StdDev: %.2f\n":
        fail("count format mismatch")
    if cstr(0x964D10) != "Min: %lu  Median: %.4f  Max: %lu\n":
        fail("min/max format mismatch")
    if cstr(0x959298) != ("Percentiles: P50: %.2f P75: %.2f P99: %.2f "
                          "P99.9: %.2f P99.99: %.2f\n"):
        fail("percentiles format mismatch")
    if cstr(0x966D98) != "%c %7lu, %7lu ] %8lu %7.3f%% %7.3f%% ":
        fail("bucket-row format mismatch")
    if read_vaddr(0x959B38, 55) != b"-" * 54 + b"\n":
        fail("dashes separator mismatch")
    for va, want in ((0x4592B0, 1.0), (0x459498, 100.0), (0x4593D0, 5.0),
                     (0x459490, 0.5), (0x459360, 9.223372036854776e18),
                     (0x459950, 50.0), (0x459C50, 75.0), (0x459258, 99.0),
                     (0x459CE8, 99.9), (0x459080, 99.99)):
        if struct.unpack("<d", read_vaddr(va, 8))[0] != want:
            fail("double at 0x%x mismatch" % va)
    # Boundaries: the vector at 0x6505d20 lives in .bss (NOBITS), so
    # its values are not in the file — they are generated once at
    # static-init time (0x606c140, registered in .init_array). Check
    # the binary-grounded inputs, then re-derive the 109 values with
    # the generator transcribed from #3371's tools/histogram_stats_115.py
    # (generate_boundaries + _truncate_boundary) and compare to the TSV.
    seed0, seed1 = struct.unpack("<QQ", read_vaddr(0x453950, 16))
    if (seed0, seed1) != (1, 2):
        fail("boundary seeds mismatch: %r" % ((seed0, seed1),))
    init_addend = None
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if ro == 0x63F3978 and (info & 0xFFFFFFFF) == 8:
            init_addend = add
    if init_addend != 0x606C140:
        fail("boundary static-init registration mismatch: %r" % init_addend)

    def truncate_boundary(value):
        if value <= 109:
            return value
        factor = 1
        current = value
        while True:
            previous = current
            factor *= 10
            current //= 10
            if previous <= 1099:
                break
        return factor * current

    def generate_boundaries():
        boundaries = [seed0, seed1]
        cur = float(seed1) * 1.5
        while True:
            if cur < float(1 << 63):
                pushed = int(cur)
            else:
                pushed = (int(cur - float(1 << 63)) ^ (1 << 63)) & ((1 << 64) - 1)
            boundaries.append(truncate_boundary(pushed))
            cur = cur * 1.5
            if (1 << 64) < cur:
                break
        return boundaries

    rows = []
    with open(os.path.join(HERE, "boundaries.tsv")) as handle:
        handle.readline()
        for line in handle:
            index, value = line.split("\t")
            rows.append((int(index), int(value)))
    derived = generate_boundaries()
    if [value for _, value in rows] != derived:
        fail("boundaries.tsv does not match the re-derived generator output")
    if len(derived) != 109 or derived[0] != 1 or derived[-1] != 13000000000000000000:
        fail("derived boundaries shape mismatch")
    # Model tests pass under pytest
    tests = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", os.path.join(
            ROOT, "tests", "test_plain_table_index_115.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    if tests.returncode != 0:
        fail("model tests failed:\n%s%s" % (tests.stdout, tests.stderr))
    print("model tests: %s" % tests.stdout.strip().splitlines()[-1])
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
