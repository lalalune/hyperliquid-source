"""Packet checker for RE-001-range-tombstone-cache-115.

Run from the repository root:
    python3 research/work-items/RE-001-range-tombstone-cache-115/verify.py

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
8. relocations: no RELATIVE entry points at a packet window;
   the vtable leas and the atomicity-selector global are present;
9. key literals (the 0xc8 alloc, the slot stride, the ready-flag
   store, the 0x40 stride, the TLS record, the seed constant, the
   packed release qword) are present in the excerpts;
10. model constants: the shard mask, the LCG step, the counted-base
    release, the cache count/total, the host end-to-end flow and the
    shard-pointer TLS record match records.json.
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
    ("host-5f0a9c0.objdump.txt", "0x5f0a9c0", "0x5f0b04c"),
    ("shard-605e170.objdump.txt", "0x605e170", "0x605e20d"),
    ("picker-60d5cd0.objdump.txt", "0x60d5cd0", "0x60d5cf0"),
    ("seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
    ("ctor-a-5f31380.objdump.txt", "0x5f31380", "0x5f3146f"),
    ("ctor-b-5f315a0.objdump.txt", "0x5f315a0", "0x5f316ce"),
    ("cache-ctor-5f37410.objdump.txt", "0x5f37410", "0x5f37e31"),
    ("cleanable-ctor-61bd0c0.objdump.txt", "0x61bd0c0", "0x61bd0d4"),
    ("cleanable-dtor-61bd0e0.objdump.txt", "0x61bd0e0", "0x61bd131"),
    ("release-5d350c0.objdump.txt", "0x5d350c0", "0x5d35145"),
    ("list-release-5f059b0.objdump.txt", "0x5f059b0", "0x5f05b79"),
]

WINDOWS = [0x5F0A9C0, 0x605E170, 0x60D5CD0, 0x61C4080, 0x5F31380,
           0x5F315A0, 0x5F37410, 0x61BD0C0, 0x61BD0E0, 0x5D350C0, 0x5F059B0]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x5F0A9C0: "f30f1efa",  # endbr64: host entry
    0x5F0A9EF: "bfc8000000",  # mov $0xc8,%edi: flag-path alloc size
    0x5F0AA15: "e866690200",  # call ctor A 0x5f31380
    0x5F0AA40: "e88bb21c00",  # call picker 0x60d5cd0
    0x5F0AA59: "41d3e6",  # shl %cl,%r14d: the mask shift
    0x5F0AA66: "49c1e604",  # shl $0x4,%r14: 16-byte slot stride
    0x5F0AB05: "e8966a0200",  # call ctor B 0x5f315a0
    0x5F0AB18: "e8a3a5e2ff",  # call _M_release 0x5d350c0
    0x5F0AC12: "e8f9c70200",  # call cache ctor 0x5f37410
    0x5F0AD57: "c6403001",  # movb $0x1,0x30(%rax): set the ready flag
    0x605E170: "f30f1efa",  # endbr64: shard helper entry
    0x605E1A1: "48c1e006",  # shl $0x6,%rax: 0x40 stride
    0x605E1B5: "488d80f8fbffff",  # lea -0x408(%rax): TLS record
    0x60D5CD0: "f30f1efa",  # endbr64: picker entry
    0x60D5CD7: "0fa2",  # cpuid
    0x60D5CE9: "c1eb18",  # shr $0x18,%ebx: EBX>>24
    0x61C4080: "f30f1efa",  # endbr64: seed entry
    0x61C40D5: "ba07690fc7",  # mov $0xc70f6907,%edx: the hash seed
    0x5F31380: "f30f1efa",  # endbr64: ctor A entry
    0x5F313CC: "4883c010",  # add $0x10,%rax: vtable +0x10
    0x5F315A0: "f30f1efa",  # endbr64: ctor B entry
    0x5F31603: "f3410f6f1f",  # movdqu (%r15),%xmm3: shared_ptr copy
    0x5F37410: "f30f1efa",  # endbr64: cache ctor entry
    0x5F37450: "488d4758",  # lea 0x58(%rdi),%rax: &cache+0x58
    0x5F37A40: "498386d800000001",  # addq $0x1,0xd8(%r14): entry count
    0x61BD0C0: "f30f1efa",  # endbr64: Cleanable ctor entry
    0x61BD0C4: "48c70700000000",  # movq $0x0,(%rdi): zero the head
    0x61BD0E0: "f30f1efa",  # endbr64: DoCleanup entry
    0x61BD0F8: "ffd0",  # call *%rax: the head cleanup fn
    0x5D350C0: "f30f1efa",  # endbr64: _M_release entry
    0x5D350C4: "48b80100000001000000",  # movabs $0x100000001,%rax
    0x5D35101: "f00fc101",  # lock xadd %eax,(%rcx): atomic decrement
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
    rng = random.Random(0x5F0A9C0)
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
        ["python3", "tests/test_range_tombstone_cache_115.py"],
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
    host = open(os.path.join(HERE, "host-5f0a9c0.objdump.txt")).read()
    if "64cc638" not in host or "64ed290" not in host:
        fail("list vtable / atomicity global missing from host excerpt")
    ctor_a = open(os.path.join(HERE, "ctor-a-5f31380.objdump.txt")).read()
    ctor_b = open(os.path.join(HERE, "ctor-b-5f315a0.objdump.txt")).read()
    if "64ccae0" not in ctor_a or "64ccae0" not in ctor_b:
        fail("iterator vtable missing from ctor excerpts")
    if "64ed290" not in ctor_b:
        fail("atomicity global missing from ctor B excerpt")

    # 9. Key literals.
    if "mov    $0xc8,%edi" not in host:
        fail("0xc8 alloc missing from host excerpt")
    if "shl    $0x4,%r14" not in host:
        fail("16-byte slot stride missing from host excerpt")
    if "movb   $0x1,0x30(%rax)" not in host:
        fail("ready-flag store missing from host excerpt")
    shard = open(os.path.join(HERE, "shard-605e170.objdump.txt")).read()
    if "shl    $0x6,%rax" not in shard:
        fail("0x40 stride missing from shard excerpt")
    if "-0x408(%rax)" not in shard:
        fail("TLS record missing from shard excerpt")
    seed = open(os.path.join(HERE, "seed-61c4080.objdump.txt")).read()
    if "0xc70f6907" not in seed:
        fail("seed constant missing from seed excerpt")
    release = open(os.path.join(HERE, "release-5d350c0.objdump.txt")).read()
    if "0x100000001" not in release:
        fail("packed release qword missing from release excerpt")
    cache_ctor = open(os.path.join(HERE, "cache-ctor-5f37410.objdump.txt")).read()
    if "64cca10" not in cache_ctor:
        fail("stack-iterator vtable missing from cache-ctor excerpt")

    # 10. Model constants.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import range_tombstone_cache_115 as model
    if model.pick_shard(9, 3) != 1 or model.pick_shard(5, 3) != 5:
        fail("model pick_shard mismatch")
    if model.mersenne_step(1) != 0x41A7:
        fail("model mersenne_step(1) mismatch")
    if model.mersenne_step(0x7FFFFFFF) != 0x7FFFFFFF:
        fail("model mersenne_step(0x7fffffff) mismatch")
    cb = model.CountedBase()
    if cb.packed() != 0x100000001 or cb.release() is not True:
        fail("model CountedBase fast path mismatch")
    cache = model.TombstoneCache([("a", 4), ("b", 6)])
    if cache.count_d8 != 2 or cache.total_size_e0 != 10:
        fail("model cache count/total mismatch")
    owner = model.Owner(3, 8)
    it, tr = owner.new_range_tombstone_iterator_internal(
        [("k", 1)], 7, False, {"plus8": 1}, None, 0,
        8, 0x08000000, b"\x00" * 8)
    if "build_cache" not in tr or "install_cache" not in tr:
        fail("model host build flow mismatch")
    it2, tr2 = owner.new_range_tombstone_iterator_internal(
        [("k", 1)], 7, False, {"plus8": 1}, None, 0,
        8, 0x08000000, b"\x00" * 8)
    if tr2[1] != "locker_claim" or "ready_ctor_b" not in tr2:
        fail("model host reuse flow mismatch")
    if it2["cache"] is not it["cache"]:
        fail("model host reuse cache mismatch")
    st = model.ShardTable40(3, 8)
    slot_ptr, rec = st.shard_pointer(5, None, b"\x00" * 8)
    if slot_ptr != "slot5" or rec != (5 | (1 << 3)):
        fail("model shard-pointer mismatch")
    if "MemTable" not in json.dumps(records):
        fail("catalogue attribution missing from records.json")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
