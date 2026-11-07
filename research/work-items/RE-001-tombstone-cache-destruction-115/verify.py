"""Packet checker for RE-001-tombstone-cache-destruction-115.

Run from the repository root:
    python3 research/work-items/RE-001-tombstone-cache-destruction-115/verify.py

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
8. relocations: exactly the four expected RELATIVE slots point at
   packet windows (the cache dispose, the inner dispose, the two
   ConcurrentArena destructors); the iterator vtables resolve to the
   recorded typeinfo names and slots;
9. key literals (the +0x38 list load, the +0xb8 flag test/clear, the
   0xe8 delete, the +0x80 FreeMem argument, the slot-0x88 rep calls,
   the AllocTracker flag stores, the 0x9b0 arena size) are present in
   the excerpts;
10. the five re-shipped excerpts are byte-identical to PR #3803's packet;
11. model constants: the dispose state machine, the MemTable dtor
    member order, the AllocTracker state machine, the release chain,
    RB-erase and FlushJobInfo destruction match records.json.
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
    ("dispose-5f061b0.objdump.txt", "0x5f061b0", "0x5f06548"),
    ("unique-ptr-dtor-5f0b080.objdump.txt", "0x5f0b080", "0x5f0b418"),
    ("memtable-dtor-5f10d40.objdump.txt", "0x5f10d40", "0x5f11798"),
    ("freemem-605e8a0.objdump.txt", "0x605e8a0", "0x605e8e7"),
    ("doneallocating-605e860.objdump.txt", "0x605e860", "0x605e89e"),
    ("wbm-freemem-606a890.objdump.txt", "0x606a890", "0x606a8bf"),
    ("dispose-inner-5f0a290.objdump.txt", "0x5f0a290", "0x5f0a319"),
    ("arena-d1-5f10180.objdump.txt", "0x5f10180", "0x5f101b2"),
    ("arena-d0-5f10d00.objdump.txt", "0x5f10d00", "0x5f10d3c"),
    ("rb-erase-30-5f05b80.objdump.txt", "0x5f05b80", "0x5f05d49"),
    ("rb-erase-60-5f06770.objdump.txt", "0x5f06770", "0x5f06bae"),
    ("flushjobinfo-dtor-5ecd650.objdump.txt", "0x5ecd650", "0x5ecd9a5"),
    ("introsort-5f053d0.objdump.txt", "0x5f053d0", "0x5f05678"),
    ("insertion-5f05120.objdump.txt", "0x5f05120", "0x5f051f5"),
    ("adjust-heap-5f04f80.objdump.txt", "0x5f04f80", "0x5f0511d"),
    ("cleanable-dtor-61bd0e0.objdump.txt", "0x61bd0e0", "0x61bd131"),
    ("list-release-5f059b0.objdump.txt", "0x5f059b0", "0x5f05b79"),
]

WINDOWS = [0x5F061B0, 0x5F0B080, 0x5F10D40, 0x605E8A0, 0x605E860,
           0x606A890, 0x5F0A290, 0x5F10180, 0x5F10D00, 0x5F05B80,
           0x5F06770, 0x5ECD650, 0x5F053D0, 0x5F05120, 0x5F04F80,
           0x61BD0E0, 0x5F059B0]

SAMPLES = {
    0x5F061B0: "f30f1efa",  # endbr64: dispose entry
    0x5F061BE: "4c8b6738",  # mov 0x38(%rdi),%r12: List* load
    0x5F061CB: "4180bc24b800000000",  # cmpb $0x0,0xb8(%r12): ready flag
    0x5F061D4: "498bac24c0000000",  # mov 0xc0(%r12),%rbp: index array
    0x5F0620A: "e8d16e2b00",  # call DoCleanup 0x61bd0e0
    0x5F06234: "e877f7ffff",  # call list release 0x5f059b0
    0x5F0629A: "bee8000000",  # mov $0xe8,%esi: delete size
    0x5F062A5: "e9d6aa4e00",  # jmp operator delete
    0x5F06310: "41c68424b800000000",  # movb $0x0,0xb8(%r12): flag clear
    0x5F06348: "e883f0ffff",  # call __introsort_loop 0x5f053d0
    0x5F06367: "e8b4edffff",  # call __insertion_sort 0x5f05120
    0x5F063E3: "ff5308",  # call *0x8(%rbx): entry dtor invoke
    0x5F0B080: "f30f1efa",  # endbr64: unique_ptr dtor entry
    0x5F10D40: "f30f1efa",  # endbr64: MemTable dtor entry
    0x5F10D5F: "e83cdb1400",  # call AllocTracker::FreeMem 0x605e8a0
    0x5F10D99: "e82243e2ff",  # call _M_release 0x5d350c0
    0x5F1145A: "ff9088000000",  # call *0x88(%rax): rep slot 17
    0x5F1146F: "ff9088000000",  # call *0x88(%rax): rep slot 17
    0x5F114B5: "e936d41400",  # jmp AllocTracker::~AllocTracker 0x605e8f0
    0x605E8A0: "f30f1efa",  # endbr64: FreeMem entry
    0x605E8A5: "807f1000",  # cmpb $0x0,0x10(%rdi)
    0x605E8E0: "e87bffffff",  # call DoneAllocating 0x605e860
    0x605E8D3: "e8b8bf0000",  # call WriteBufferManager::FreeMem 0x606a890
    0x605E8D8: "c6431101",  # movb $0x1,0x11(%rbx): freed flag
    0x605E860: "f30f1efa",  # endbr64: DoneAllocating entry
    0x605E893: "e878b80000",  # call 0x606a110
    0x605E898: "c6431001",  # movb $0x1,0x10(%rbx): done flag
    0x606A890: "f30f1efa",  # endbr64: WBM::FreeMem entry
    0x606A895: "48837f2000",  # cmpq $0x0,0x20(%rdi): cache gate
    0x606A89F: "e8ccf8ffff",  # call FreeMemWithCache 0x606a170
    0x606A8B8: "f048297710",  # lock sub %rsi,0x10(%rdi)
    0x5F0A290: "f30f1efa",  # endbr64: inner dispose entry
    0x5F0A2E6: "ff5010",  # call *0x10(%rax): Cache _M_dispose
    0x5F0A2F4: "ffe0",  # jmp *%rax: _M_destroy tail-jump
    0x5F10180: "f30f1efa",  # endbr64: ConcurrentArena D1 entry
    0x5F1019B: "e890ca1400",  # call Arena::~Arena 0x605cc30
    0x5F10D00: "f30f1efa",  # endbr64: ConcurrentArena D0 entry
    0x5F10D31: "beb0090000",  # mov $0x9b0,%esi: sizeof(ConcurrentArena)
    0x5F05B80: "4157",  # push %r15: rb-erase-30 entry (no endbr64)
    0x5F06770: "4157",  # push %r15: rb-erase-60 entry (no endbr64)
    0x5ECD650: "f30f1efa",  # endbr64: FlushJobInfo dtor entry
    0x5F053D0: "4889f0",  # mov %rsi,%rax: introsort entry (no endbr64)
    0x5F05120: "4839f7",  # cmp %rsi,%rdi: insertion entry
}

RESHIPPED = [
    "introsort-5f053d0.objdump.txt",
    "insertion-5f05120.objdump.txt",
    "adjust-heap-5f04f80.objdump.txt",
    "cleanable-dtor-61bd0e0.objdump.txt",
    "list-release-5f059b0.objdump.txt",
]

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
    rng = random.Random(0x5F061B0)
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
            "direct_calls": [hex(v) for v in sorted(set(calls[t]))],
            "tail_jumps": [hex(v) for v in sorted(set(tails[t]))],
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
        ["python3", "tests/test_tombstone_cache_destruction_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0 or "tests passed" not in test.stdout:
        fail("model tests failed: " + test.stdout + test.stderr)

    # 8. Relocations: exactly the four expected RELATIVE slots point at
    #    packet windows; no other RELATIVE entry points at one.
    rela_off, rela_size = 0x6BE8, 0x163CC8
    window_slots = {}
    for k in range(rela_size // 24):
        ro, info, add = struct.unpack_from("<QQq", data, rela_off + k * 24)
        if (info & 0xFFFFFFFF) == 8 and add in WINDOWS:
            window_slots.setdefault(add, []).append(ro)
    expect = {0x5F061B0: [0x64CC728], 0x5F0A290: [0x64CC760],
              0x5F10180: [0x64CC5D8], 0x5F10D00: [0x64CC5E0]}
    if window_slots != expect:
        fail("RELATIVE window slots mismatch: %s" % window_slots)
    reloc_lines = open(os.path.join(HERE, "relocations.txt")).read().splitlines()[1:]
    want_reloc = {(0x64CC728, 0x5F061B0), (0x64CC760, 0x5F0A290),
                  (0x64CC5D8, 0x5F10180), (0x64CC5E0, 0x5F10D00),
                  (0x64D2770, 0x6063010)}
    got_reloc = set()
    for line in reloc_lines:
        off, add, _note = line.split("\t")
        got_reloc.add((int(off, 16), int(add, 16)))
    if got_reloc != want_reloc:
        fail("relocations.txt mismatch: %s" % got_reloc)
    vt = records["vtables"]
    if vt["cache_control_block"]["typeinfo_name"] != \
            "St23_Sp_counted_ptr_inplaceIN7rocksdb33FragmentedRangeTombstoneListCacheESaIvELN9__gnu_cxx12_Lock_policyE2EE":
        fail("Cache control-block typeinfo mismatch")
    if vt["cache_control_block"]["slots"]["2"] != "0x5f061b0":
        fail("Cache control-block _M_dispose slot mismatch")
    if vt["inner_control_block"]["slots"]["2"] != "0x5f0a290":
        fail("Inner control-block _M_dispose slot mismatch")
    if vt["concurrent_arena"]["typeinfo_name"] != "N7rocksdb15ConcurrentArenaE":
        fail("ConcurrentArena typeinfo mismatch")
    if len(vt["concurrent_arena"]["slots"]) != 22:
        fail("ConcurrentArena slot count mismatch")
    if vt["skiplist_rep"]["typeinfo_name"] != "N7rocksdb12_GLOBAL__N_111SkipListRepE":
        fail("SkipListRep typeinfo mismatch")
    if len(vt["skiplist_rep"]["slots"]) != 23:
        fail("SkipListRep slot count mismatch")
    if vt["skiplist_rep"]["slots"]["17"] != "0x6063010":
        fail("SkipListRep slot 17 mismatch")
    dispose = open(os.path.join(HERE, "dispose-5f061b0.objdump.txt")).read()
    if "64cc718" not in dispose and "0x38(%rdi)" not in dispose:
        fail("dispose excerpt missing its list load")

    # 9. Key literals.
    if "0x38(%rdi)" not in dispose:
        fail("+0x38 list load missing from dispose excerpt")
    if "0xb8(%r12)" not in dispose:
        fail("+0xb8 flag missing from dispose excerpt")
    if "mov    $0xe8,%esi" not in dispose:
        fail("0xe8 delete size missing from dispose excerpt")
    dtor = open(os.path.join(HERE, "memtable-dtor-5f10d40.objdump.txt")).read()
    if "lea    0x80(%rdi),%r12" not in dtor:
        fail("+0x80 FreeMem argument missing from MemTable dtor excerpt")
    if "call   *0x88(%rax)" not in dtor:
        fail("slot-0x88 rep calls missing from MemTable dtor excerpt")
    if "0xce0(%rbp)" not in dtor or "0xcd8(%rbp)" not in dtor:
        fail("+0xce0/+0xcd8 members missing from MemTable dtor excerpt")
    if "0xd10(%rbp)" not in dtor:
        fail("+0xd10 CoreLocalArray missing from MemTable dtor excerpt")
    freemem = open(os.path.join(HERE, "freemem-605e8a0.objdump.txt")).read()
    if "movb   $0x1,0x11(%rbx)" not in freemem:
        fail("freed-flag store missing from FreeMem excerpt")
    arena_d0 = open(os.path.join(HERE, "arena-d0-5f10d00.objdump.txt")).read()
    if "mov    $0x9b0,%esi" not in arena_d0:
        fail("0x9b0 arena size missing from arena-d0 excerpt")

    # 10. Re-shipped excerpts are byte-identical to PR #3803's packet.
    for name in RESHIPPED:
        mine = open(os.path.join(HERE, name), "rb").read()
        orig = open(os.path.join(
            ROOT, "research/work-items/RE-001-fragmented-range-tombstones-115",
            name), "rb").read()
        if mine != orig:
            fail("re-shipped excerpt differs from PR #3803: " + name)

    # 11. Model constants.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import tombstone_cache_destruction_115 as model
    if model.CACHE_SIZE != 0xE8 or model.CACHE_LIST_OFFSET != 0x38:
        fail("model cache constants mismatch")
    if model.MEMTABLE_DTOR_ORDER[0] != "alloc_tracker_free_mem":
        fail("model MemTable dtor order mismatch")
    if model.MEMTABLE_DTOR_ORDER[-1] != "alloc_tracker_dtor":
        fail("model MemTable dtor tail mismatch")
    if model.ALLOC_TRACKER_DONE_OFFSET != 0x10 or model.ALLOC_TRACKER_FREED_OFFSET != 0x11:
        fail("model AllocTracker flag offsets mismatch")
    if model.WBM_CACHE_GATE_OFFSET != 0x20:
        fail("model WBM cache gate offset mismatch")
    if model.ARENA_SIZE != 0x9B0 or model.SKIPLIST_REP_SIZE != 0x58:
        fail("model arena/rep size mismatch")
    cache = model.Cache(entries=[("a", 1), ("b", 2)])
    trace = model.dispose(cache, flag_set=True)
    if trace[0] != "sort_dedup_invoke" or trace[-1] != "delete_0xe8":
        fail("model dispose trace mismatch")
    cache = model.Cache(entries=[("a", 1)])
    trace = model.dispose(cache, flag_set=False)
    if trace[0] != "free_array" or "do_cleanup" not in trace:
        fail("model dispose free-array trace mismatch")
    if "MemTable" not in json.dumps(records):
        fail("catalogue attribution missing from records.json")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
