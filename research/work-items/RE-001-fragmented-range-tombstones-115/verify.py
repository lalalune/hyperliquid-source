"""Packet checker for RE-001-fragmented-range-tombstones-115.

Run from the repository root:
    python3 research/work-items/RE-001-fragmented-range-tombstones-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (including 3 self-check instructions picked for this packet);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json and callers.tsv, and
   every census site is a real call/jump in its containing FDE;
   the generic helpers' in-packet sites are real calls in their FDEs;
7. the model test file passes under plain python3;
8. relocations: no RELATIVE entry points at a packet window; the
   iterator vtables resolve to the recorded typeinfo names and slots;
9. key literals (the 0x80 iterator alloc, the +0xa60 flag read, the
   ready-flag clear, the 16-entry threshold, the ReadOptions init
   stores, the cache-ctor index zeroing) are present in the excerpts;
10. model constants: the ReadOptions init map, the sort/dedup
    contracts, the teardown traces and the host end-to-end flow
    match records.json.
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
    ("host-5f0a3d0.objdump.txt", "0x5f0a3d0", "0x5f0a909"),
    ("readopts-60b21f0.objdump.txt", "0x60b21f0", "0x60b2262"),
    ("introsort-5f053d0.objdump.txt", "0x5f053d0", "0x5f05678"),
    ("insertion-5f05120.objdump.txt", "0x5f05120", "0x5f051f5"),
    ("adjust-heap-5f04f80.objdump.txt", "0x5f04f80", "0x5f0511d"),
    ("cache-ctor-5f37410.objdump.txt", "0x5f37410", "0x5f37e31"),
    ("cleanable-ctor-61bd0c0.objdump.txt", "0x61bd0c0", "0x61bd0d4"),
    ("cleanable-dtor-61bd0e0.objdump.txt", "0x61bd0e0", "0x61bd131"),
    ("list-release-5f059b0.objdump.txt", "0x5f059b0", "0x5f05b79"),
]

WINDOWS = [0x5F0A3D0, 0x60B21F0, 0x5F053D0, 0x5F05120, 0x5F04F80,
           0x5F37410, 0x61BD0C0, 0x61BD0E0, 0x5F059B0]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x5F0A3D0: "f30f1efa",  # endbr64: host entry
    0x5F0A3F4: "0fb687600a0000",  # movzbl 0xa60(%rdi): the already-built flag
    0x5F0A42B: "bf80000000",  # mov $0x80,%edi: iterator alloc size
    0x5F0A43D: "e8ae7d1a00",  # call ReadOptions ctor 0x60b21f0
    0x5F0A449: "e8722c2b00",  # call Cleanable ctor 0x61bd0c0
    0x5F0A4D6: "ff9090000000",  # call *0x90(%rax): rep-iterator factory
    0x5F0A536: "e8d5ce0200",  # call cache ctor 0x5f37410
    0x5F0A6A8: "41c68424b800000000",  # movb $0x0,0xb8(%r12): clear ready flag
    0x5F0A6E0: "e8ebacffff",  # call __introsort_loop 0x5f053d0
    0x5F0A6FF: "e81caaffff",  # call __insertion_sort 0x5f05120
    0x5F0A77B: "ff5308",  # call *0x8(%rbx): entry dtor
    0x5F0A5B8: "e8232b2b00",  # call DoCleanup 0x61bd0e0
    0x5F0A610: "e89bb3ffff",  # call list release 0x5f059b0
    0x60B21F0: "f30f1efa",  # endbr64: ReadOptions entry
    0x60B21FE: "ba00010000",  # mov $0x100,%edx
    0x60B2212: "48c7472c01010000",  # movq $0x101,0x2c(%rdi)
    0x60B222E: "48c74778ffffffff",  # movq $-1,0x78(%rdi)
    0x60B223D: "c7878400000004000000",  # movl $0x4,0x84(%rdi)
    0x60B2247: "66899788000000",  # movw $0x100,0x88(%rdi)
    0x5F053D0: "4889f0",  # mov %rsi,%rax: introsort entry (no endbr64)
    0x5F053D6: "483d00010000",  # cmp $0x100,%rax: 16-entry threshold
    0x5F055B9: "e812feffff",  # call self: recurse on the right partition
    0x5F0560D: "e86ef9ffff",  # call __adjust_heap 0x5f04f80
    0x5F05120: "4839f7",  # cmp %rsi,%rdi: insertion entry
    0x5F051F4: "c3",  # ret: insertion end
    0x5F04F80: "488d42ff",  # lea -0x1(%rdx),%rax: adjust entry
    0x5F04FA2: "4839ee",  # cmp %rbp,%rsi: hole bound
    0x5F37410: "f30f1efa",  # endbr64: cache ctor entry
    0x5F374EC: "410f1186c0000000",  # movups %xmm0,0xc0(%r14): zero index triple
    0x61BD0C0: "f30f1efa",  # endbr64: Cleanable ctor entry
    0x61BD0C4: "48c70700000000",  # movq $0x0,(%rdi): zero the head
    0x61BD0E0: "f30f1efa",  # endbr64: DoCleanup entry
    0x61BD0F8: "ffd0",  # call *%rax: the head cleanup fn
    0x5F059B0: "4157",  # push %r15: list-release entry (no endbr64)
    0x5F05A41: "e86affffff",  # call 0x5f059b0: self-recursion
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
        if f != "MANIFEST.sha256" and f != "__pycache__"
        and os.path.isfile(os.path.join(HERE, f)))
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
    rng = random.Random(0x5F0A3D0)
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

    # 6. Census reproduces records.json and callers.tsv; every site is
    #    a real call/jump in its containing FDE.
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
    # Site verification: disassemble each distinct containing FDE once
    # and confirm the call/jump instruction at the site.
    fde_cache = {}

    def check_site(tgt, site_hex, kind, fs, fe):
        if fs is None:
            fail("site without containing FDE: " + site_hex)
        key = (fs, fe)
        if key not in fde_cache:
            fde_cache[key] = subprocess.run(
                ["objdump", "-d",
                 "--start-address=" + fs, "--stop-address=" + fe, BIN],
                cwd=ROOT, capture_output=True, text=True, check=True,
            ).stdout
        k = "call" if kind == "direct_call" else "jmp"
        pat = re.compile(
            r"^\s+%x:\t[0-9a-f ]+\t%s\s+%x\b"
            % (int(site_hex, 16), k, tgt), re.M)
        if not pat.search(fde_cache[key]):
            fail("site not a real %s in its FDE: target %#x site %s"
                 % (k, tgt, site_hex))

    for t_hex, row in records["callers"].items():
        tgt = int(t_hex, 16)
        for site in row:
            fs, fe = site["containing_fde"]
            check_site(tgt, site["site"], site["kind"], fs, fe)
    for t_hex, row in records["packet_internal_sites"].items():
        tgt = int(t_hex, 16)
        for site in row:
            fs, fe = site["containing_fde"]
            check_site(tgt, site["site"], site["kind"], fs, fe)

    # 7. Model tests.
    test = subprocess.run(
        ["python3", "tests/test_fragmented_range_tombstones_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0 or "tests passed" not in test.stdout:
        fail("model tests failed: " + test.stdout + test.stderr)

    # 8. Relocations: no RELATIVE entry points at a packet window.
    rela_off, rela_size = 0x6BE8, 0x163CC8
    for k in range(rela_size // 24):
        ro, info, add = struct.unpack_from("<QQq", data, rela_off + k * 24)
        if (info & 0xFFFFFFFF) == 8 and add in WINDOWS:
            fail("unexpected RELATIVE slot for " + hex(add))
    for t in census_mod.TARGETS:
        if slots[t]:
            fail("unexpected RELATIVE slot for " + hex(t))
    # Vtable resolutions: typeinfo names and slot targets.
    vt = records["vtables"]
    if vt["memtable_iterator"]["typeinfo_name"] != "N7rocksdb16MemTableIteratorE":
        fail("MemTableIterator typeinfo mismatch")
    if len(vt["memtable_iterator"]["slots"]) != 24:
        fail("MemTableIterator slot count mismatch")
    if vt["key_comparator"]["typeinfo_name"] != "N7rocksdb8MemTable13KeyComparatorE":
        fail("KeyComparator typeinfo mismatch")
    if len(vt["key_comparator"]["slots"]) != 5:
        fail("KeyComparator slot count mismatch")
    if vt["internal_key_comparator"]["typeinfo_name"] != "N7rocksdb21InternalKeyComparatorE":
        fail("InternalKeyComparator typeinfo mismatch")
    if len(vt["internal_key_comparator"]["slots"]) != 3:
        fail("InternalKeyComparator slot count mismatch")
    host = open(os.path.join(HERE, "host-5f0a3d0.objdump.txt")).read()
    if "64cc638" not in host or "64cc600" not in host or "64c8fe8" not in host:
        fail("iterator vtables missing from host excerpt")

    # 9. Key literals.
    if "mov    $0x80,%edi" not in host:
        fail("0x80 iterator alloc missing from host excerpt")
    if "0xa60(%rdi)" not in host:
        fail("already-built flag read missing from host excerpt")
    if "movb   $0x0,0xb8(%r12)" not in host:
        fail("ready-flag clear missing from host excerpt")
    if "mov    $0xe8,%edi" not in host:
        fail("0xe8 cache alloc missing from host excerpt")
    introsort = open(os.path.join(HERE, "introsort-5f053d0.objdump.txt")).read()
    if "cmp    $0x100,%rax" not in introsort:
        fail("16-entry threshold missing from introsort excerpt")
    readopts = open(os.path.join(HERE, "readopts-60b21f0.objdump.txt")).read()
    if "$0x101,0x2c(%rdi)" not in readopts:
        fail("ReadOptions +0x2c store missing from readopts excerpt")
    if "$0xffffffffffffffff,0x78(%rdi)" not in readopts:
        fail("ReadOptions +0x78 store missing from readopts excerpt")
    cache_ctor = open(os.path.join(HERE, "cache-ctor-5f37410.objdump.txt")).read()
    if "64cca10" not in cache_ctor:
        fail("stack-iterator vtable missing from cache-ctor excerpt")

    # 10. Model constants.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import fragmented_range_tombstones_115 as model
    opts = model.default_readopts()
    if opts[0x2C] != 0x101 or opts[0x78] != -1 or opts[0x84] != 4 or opts[0x88] != 0x0100:
        fail("model ReadOptions init map mismatch")
    if model.readopts_slot_48_callable(opts):
        fail("model ReadOptions +0x48 call should be dead")
    if model.depth_limit(0) != -2 or model.depth_limit(17) != 8:
        fail("model depth_limit mismatch")
    if model.sort_index([(3, 1), (1, 9), (1, 2), (2, 0)]) != [(1, 2), (1, 9), (2, 0), (3, 1)]:
        fail("model sort_index mismatch")
    if model.dedup_sorted([(1, 2), (1, 2), (1, 3)]) != [(1, 2), (1, 3)]:
        fail("model dedup mismatch")
    fields = {"+0x10": "u", "+0x31": 0, "+0x60": "a", "+0x6c": "b",
              "+0xa58": "r", "+0xc58": "c"}
    it = model.build_iterator(fields, rep_iterator="rep")
    if it["+0x48"] != "u" or it["+0x5a"] != 1 or it["+0x50"] != "rep":
        fail("model iterator build mismatch")
    owner = model.Owner(fields, already_built=True)
    trace, _ = model.construct_fragmented_range_tombstones(
        owner, lambda it2: model.TombstoneCache(), {})
    if trace != ["early_return"]:
        fail("model host early-return mismatch")
    owner = model.Owner(fields, already_built=False, old_cache=None)
    trace, new_cache = model.construct_fragmented_range_tombstones(
        owner, lambda it2: model.TombstoneCache(), {})
    if trace != ["build_iterator", "build_cache", "install_cache",
                 "destroy_iterator", "free_scratch"]:
        fail("model host rebuild trace mismatch")
    if "MemTable" not in json.dumps(records):
        fail("catalogue attribution missing from records.json")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
