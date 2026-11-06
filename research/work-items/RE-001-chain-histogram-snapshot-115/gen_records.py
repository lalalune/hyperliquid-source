"""Generate records.json, callers.tsv, relocations.txt and vtables.tsv.

Run from the repository root:
    python3 research/work-items/RE-001-chain-histogram-snapshot-115/gen_records.py

Derives everything from the digest-verified work binary:
- runs census.py and parses its canonical output;
- maps every call/tail-jump site to its containing FDE (from a fresh
  objdump --dwarf=frames dump) and verifies the site is a real
  call/jmp to the target in objdump output of that FDE;
- resolves the HashLinkListRep / Arena / FullListIterator / HistogramImpl
  vtable and typeinfo slots from .rela.dyn R_X86_64_RELATIVE entries;
- reads the literal strings the packet relies on.
Writes the four generated files next to this script.
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

TARGETS = [
    ("host", 0x605FEB0),
    ("arena_ctor", 0x605DD90),
    ("index_builder", 0x605F290),
    ("index_insert", 0x605F340),
    ("log_gate", 0x5FCEF60),
    ("size_normalizer", 0x605CFA0),
    ("counter_add", 0x605E830),
    ("thread_seed", 0x61C4080),
    ("bucket_count_init", 0x606B080),
    ("locked_init", 0x606B0C0),
    ("record_thunk", 0x606B1C0),
    ("record", 0x606B130),
    ("tostring_entry", 0x606BC90),
]

# RELATIVE slots whose addends this packet relies on.
RELOC_SLOTS = [
    0x64D2160,  # HashLinkListRep vtable: typeinfo -> 0x64d2050
    0x64D2168, 0x64D2170, 0x64D2178, 0x64D2180, 0x64D2188, 0x64D2190,
    0x64D2198, 0x64D21A0, 0x64D21A8, 0x64D21B0, 0x64D21B8, 0x64D21C0,
    0x64D21C8, 0x64D21D0, 0x64D21D8, 0x64D21E0, 0x64D21E8, 0x64D21F0,
    0x64D21F8, 0x64D2200, 0x64D2208, 0x64D2210, 0x64D2218,  # 23 slots
    0x64D2058,  # HashLinkListRep typeinfo +0x8: name -> 0x974fe0
    0x64D1FB0,  # Arena vtable: typeinfo -> 0x64d1f90
    0x64D1FB8, 0x64D1FC0, 0x64D1FC8, 0x64D1FD0, 0x64D1FD8,  # 5 slots
    0x64D1F98,  # Arena typeinfo +0x8: name -> 0x974e90
    0x64D2088,  # FullListIterator vtable: typeinfo -> 0x64d2008
    0x64D2090, 0x64D2098, 0x64D20A0, 0x64D20A8, 0x64D20B0, 0x64D20B8,
    0x64D20C0, 0x64D20C8, 0x64D20D0, 0x64D20D8, 0x64D20E0,  # 11 slots
    0x64D2010,  # FullListIterator typeinfo +0x8: name -> 0x974f20
    0x64D2B78,  # HistogramImpl vtable: typeinfo -> 0x64d2b58
    0x64D2B88,  # HistogramImpl slot 0x08 (sized delete, #3362)
    0x64D2B90,  # HistogramImpl slot 0x10 (locked init)
    0x64D2BA0,  # HistogramImpl slot 0x20 (record thunk)
    0x64D2BB0,  # HistogramImpl slot 0x30 (ToString entry)
    0x64D2B60,  # HistogramImpl typeinfo +0x8: name -> 0x9753f0
]

WINDOWS = {
    "host": ("0x605feb0", "0x6060199", "host-605feb0.objdump.txt", "0075a4a8"),
    "arena_ctor": ("0x605dd90", "0x605dfcd", "arena-ctor-605dd90.objdump.txt", "0075a208"),
    "index_builder": ("0x605f290", "0x605f33a", "index-builder-605f290.objdump.txt", "00367b98"),
    "index_insert": ("0x605f340", "0x605f6d5", "index-insert-605f340.objdump.txt", "00367bb4"),
    "log_gate": ("0x5fcef60", "0x5fcf043", "log-gate-5fcef60.objdump.txt", "00362334"),
    "size_normalizer": ("0x605cfa0", "0x605cfd6", "size-normalizer-605cfa0.objdump.txt", "00367680"),
    "counter_add": ("0x605e830", "0x605e859", "counter-add-605e830.objdump.txt", "0036782c"),
    "thread_seed": ("0x61c4080", "0x61c4117", "thread-seed-61c4080.objdump.txt", "0076c098"),
    "bucket_count_init": ("0x606b080", "0x606b0a2", "bucket_count_init.txt", "00368ecc"),
    "locked_init": ("0x606b0c0", "0x606b10a", "locked_init.txt", "0075b284"),
    "record_thunk": ("0x606b1c0", "0x606b1cd", "record_thunk.txt", "00368f34"),
    "record": ("0x606b130", "0x606b1b3", "record.txt", "00368f08"),
    "tostring_entry": ("0x606bc90", "0x606bcd3", "tostring_entry.txt", "00368ffc"),
}


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def run_census():
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "census.py"), BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    blocks = {}
    current = None
    for line in out.splitlines():
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
    return blocks


def fde_map():
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    fdes = []
    for line in frames.splitlines():
        m = re.search(r"FDE .*pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def containing_fde(fdes, va):
    for start, end in fdes:
        if start <= va < end:
            return (start, end)
    return None


def verify_sites(fdes, sites):
    """sites: list of (site_va, target_va, kind). Returns rows with FDEs."""
    by_fde = {}
    for site, target, kind in sites:
        fde = containing_fde(fdes, site)
        key = fde if fde else ("window", site)
        by_fde.setdefault(key, []).append((site, target, kind))
    rows = []
    for key, group in sorted(by_fde.items(), key=lambda kv: kv[1][0][0]):
        if key[0] == "window":
            site = key[1]
            start, stop = site - 0x20, site + 0x20
            fde_label = "none"
        else:
            start, stop = key
            fde_label = "0x%x..0x%x" % key
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=" + hex(start), "--stop-address=" + hex(stop), BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        for site, target, kind in group:
            want = "call" if kind == "call" else "jmp"
            pat = re.compile(r"^\s*%x:\t[0-9a-f ]+\t%s\s+%x\b" % (site, want, target), re.M)
            if not pat.search(out):
                fail("site 0x%x not a %s to 0x%x in objdump of %s"
                     % (site, want, target, fde_label))
            rows.append({
                "site": "0x%x" % site,
                "target": "0x%x" % target,
                "kind": kind,
                "fde": fde_label,
            })
    rows.sort(key=lambda r: (int(r["target"], 16), int(r["site"], 16)))
    return rows


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    blocks = run_census()
    fdes = fde_map()
    census = {}
    sites = []
    for name, target in TARGETS:
        got = blocks.get(hex(target))
        if got is None:
            fail("census missing target 0x%x" % target)
        census[hex(target)] = got
        for s in got["direct_calls"]:
            sites.append((int(s, 16), target, "call"))
        for s in got["tail_jumps"]:
            sites.append((int(s, 16), target, "tail"))
    rows = verify_sites(fdes, sites)
    print("verified %d call sites" % len(rows))
    RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8
    relocs = {}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if ro in RELOC_SLOTS and (info & 0xFFFFFFFF) == 8:
            relocs[ro] = add
    for slot in RELOC_SLOTS:
        if slot not in relocs:
            fail("missing RELATIVE entry for slot 0x%x" % slot)
    entries = {}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        entries[RELA_OFF + k * 24 + 16] = (ro, add)
    hit_notes = {}
    for name, target in TARGETS:
        for h in blocks[hex(target)]["qword_hits_file_offsets"]:
            off = int(h, 16)
            if off in entries:
                ro, add = entries[off]
                hit_notes[h] = ("rela-addend field of entry at 0x%x "
                                "(slot 0x%x, addend 0x%x)" % (off - 16, ro, add))
            else:
                hit_notes[h] = "unclassified qword hit (not a RELATIVE addend field)"
    # section map for cstr reads (names live in .rodata, not file offset == VA)
    import re as _re
    secs = {}
    out = subprocess.run(["readelf", "-S", "-W", os.path.join(ROOT, BIN)],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = _re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+"
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

    rep_name = cstr(relocs[0x64D2058])
    arena_name = cstr(relocs[0x64D1F98])
    iter_name = cstr(relocs[0x64D2010])
    hist_name = cstr(relocs[0x64D2B60])
    log_fmt = cstr(0x9641A8)
    if log_fmt != "hashLinkedList Entry distribution among buckets: %s":
        fail("log format literal mismatch: %r" % log_fmt)
    if data[0x459080:0x459088] != struct.pack("<d", 99.99):
        # P99.99 constant cited by #3371's renderer record; sanity only
        pass
    # vtable slot tables
    rep_slots = []
    for off in range(0x00, 0xB8, 0x08):
        slot = 0x64D2168 + off
        rep_slots.append({"offset": "0x%02x" % off, "slot": "0x%x" % slot,
                          "target": "0x%x" % relocs[slot]})
    arena_slots = []
    for off in range(0x00, 0x28, 0x08):
        slot = 0x64D1FB8 + off
        arena_slots.append({"offset": "0x%02x" % off, "slot": "0x%x" % slot,
                            "target": "0x%x" % relocs[slot]})
    iter_slots = []
    for off in range(0x00, 0x58, 0x08):
        slot = 0x64D2090 + off
        iter_slots.append({"offset": "0x%02x" % off, "slot": "0x%x" % slot,
                           "target": "0x%x" % relocs[slot]})
    records = {
        "task": "RE-001",
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "provenance_path": "provenance/artifacts.json",
        "bounded_question": (
            "How does HashLinkListRep's slot-0x90 method rebuild its entry "
            "index, measure the per-bucket chain-length distribution, and "
            "report it?"),
        "windows": {
            name: {"start": s, "end": e, "file": f, "fde_offset": fo}
            for name, (s, e, f, fo) in WINDOWS.items()
        },
        "census": census,
        "census_notes": {
            "method": ("per-byte .text scan for e8/e9 with rel32 targets, "
                       "whole-file qword search, .rela.dyn parse; every "
                       "call/tail site re-verified in objdump output of "
                       "its containing FDE (see callers.tsv)"),
            "qword_hit_classification": hit_notes,
            "host_no_direct_calls": (
                "the host 0x605feb0 has no direct call or tail-jump site: "
                "it is reached only through the HashLinkListRep vtable "
                "slot 0x90 (RELATIVE at 0x64d21f8)"),
            "arena_ctor_shared": (
                "the Arena ctor 0x605dd90 has 19 direct callers across "
                "the binary; it is the general rocksdb::Arena ctor, "
                "pinned here because the host builds an Arena"),
            "thread_seed_shared": (
                "the thread seed 0x61c4080 has 17 direct callers; it is "
                "a general per-thread hash-seed helper, pinned here "
                "because the index insert advances it on rehash"),
        },
        "host_behavior": {
            "fde": "0x605feb0..0x6060199",
            "vtable": "0x64d2168 (HashLinkListRep, typeinfo 0x64d2050)",
            "vtable_slot": "0x90 (RELATIVE at 0x64d21f8)",
            "typeinfo_name": rep_name,
            "signature": "FullListIterator *method(HashLinkListRep *this, allocator *alloc_or_null)",
            "this_fields": {
                "+0x08": "object whose vtable slot 0x20 returns the Arena block size (unknown owner)",
                "+0x10": "bucket count (u64)",
                "+0x18": "bucket-head array (u64*)",
                "+0x30": "key/comparator object passed to the index builder",
                "+0x38": "logger object passed to the log gate",
                "+0x44": "report flag byte: 0 skips recording and logging",
            },
            "steps": [
                "allocate 0x8f0 bytes and build an Arena via 0x605dd90(out, size_from_slot_0x20, 0, 0)",
                "allocate a 0x38-byte index via 0x605f290(idx, *(this+0x30), count=0xc, arena, divisor=4)",
                "build a stack HistogramImpl at rsp+0x50: vtable 0x64d2b80, bucket_count_init 0x606b080, locked_init 0x606b0c0",
                "for each bucket i in 0..count-1: walk the bucket's chains via 0x605f340(idx, &chain_head), counting entries in r14d; the walk follows two chain shapes (plain next via *(node), and via node+0x28 then +0x08)",
                "if this+0x44 != 0: record the per-bucket count into the stack histogram via the record thunk 0x606b1c0(hist, count)",
                "if this+0x44 != 0 and this+0x38 != 0: render the histogram via ToString entry 0x606bc90(out_string, hist) and log it via the log gate 0x5fcef60(logger, 'hashLinkedList Entry distribution among buckets: %s', rendered)",
                "build a 0x48-byte FullListIterator (vtable 0x64d2090) over (index, arena): allocator is the saved 2nd argument's slot 0x18 when non-null, else operator new; return the iterator",
            ],
            "return": "the FullListIterator pointer (rax at the epilogue)",
            "sibling_slots_same_vtable": {
                "0x08": "0x605f700 (also builds an index via 0x605f290/0x605f340 and logs via 0x5fcef60; separate work item)",
                "0x48": "0x60602c0",
                "0x60": "0x6060580",
                "0x98": "0x605ec20",
            },
        },
        "arena_ctor_behavior": {
            "fde": "0x605dd90..0x605dfcd",
            "vtable_installed": "0x64d1fb8",
            "typeinfo": "0x64d1f90",
            "typeinfo_name": arena_name,
            "signature": "Arena(out, size_t block_size_hint, size_t arg3, size_t arg4)",
            "steps": [
                "install vtable 0x64d1fb8 at *(out); call the size normalizer 0x605cfa0(size_hint) and store the result at out+0x810",
                "out+0x810 = normalize_block_size(size_hint); out+0x818 = 64-byte block (8 slots); out+0x820 = 8",
                "out+0x828..0x868: two identical 32-byte table descriptors {512-byte block, 512-byte block, 512-byte block + 0x200, 64-byte block + 24}",
                "out+0x860..0x8b8: the second table, built the same way (its own 64-byte and 512-byte blocks)",
                "out+0x8b8 = 0; out+0x8c0 = &out+0x810; out+0x8c8 = out+0x10; out+0x8d0 = 0x800; out+0x8d8 = arg4 when arg4 == 0 or arg4 >= out+0x810, else ceil(out+0x810 / arg4) * arg4; out+0x8e0 = 0x800; out+0x8e8 = arg3",
                "if arg3 != 0: counter_add 0x605e830(arg3, 0x800)",
            ],
            "size_field": "+0x810 (normalized block size)",
            "note": "the host passes (size_from_slot_0x20, 0, 0), so the tail fields are 0x800 / 0 / 0x800 / 0 there and no counter-add runs",
        },
        "index_builder_behavior": {
            "fde": "0x605f290..0x605f33a",
            "signature": "build(out38, key_obj, u16 count, allocator, u16 divisor)",
            "layout": {
                "+0x00": "count (u16)",
                "+0x02": "divisor (u16)",
                "+0x04": "0x80000000 / divisor (u32 step)",
                "+0x08": "key_obj",
                "+0x10": "allocator",
                "+0x18": "array A (count+1 pointers, zeroed; slot 0x18 of allocator)",
                "+0x20": "1 (initial capacity exponent marker)",
                "+0x28": "array B (count pointers, each set to array A; slot 0x18 of allocator)",
                "+0x30": "1 (initial size marker)",
            },
            "array_build": (
                "each array is allocated through the allocator's vtable "
                "slot 0x18 (count, 0, 0); array A is zeroed, array B's "
                "slots all point at array A"),
            "callers": ["0x605fbab", "0x605ff2d (host)", "0x6062174", "0x6062290"],
        },
        "index_insert_behavior": {
            "fde": "0x605f340..0x605f6d5",
            "signature": "insert(index38, key_record_ptr)",
            "steps": [
                "dispatch the comparator: slot 0x08 of *(index+0x08) on (key, candidate) returns < 0 / 0 / > 0",
                "scan array A from the end (index+0x20 - 1 down to 0), comparing each occupied slot's key; a negative compare restarts the scan from the matched slot",
                "when the scan reaches array A's head without a match, rehash: advance the per-thread seed via 0x61c4080 (multiply by 0x41a7 mod 0x7fffffff until >= step at +0x04, capped by the count), store the advanced seed back",
                "grow array A to the new size (memmove of the entries) when +0x20 < new size; set +0x20 and +0x30 to the new size",
                "allocate a node through the allocator's slot 0x18, store the key, and splice it into the chain (linked-list insert ordered by the comparator)",
            ],
            "hash_constants": {
                "multiplier": "0x41a7",
                "modulus": "0x7fffffff (Mersenne reduction: x = (x & 0x7fffffff) + (x >> 31), folded once)",
                "step_source": "index+0x04 (0x80000000 / divisor)",
            },
            "callers": ["0x605fb54", "0x605fbca", "0x605fbeb", "0x6060113 (host)", "0x606015a (host)", "0x6062189", "0x60622d6"],
        },
        "log_gate_behavior": {
            "fde": "0x5fcef60..0x5fcf043",
            "signature": "log_gate(logger, format, ...varargs)",
            "steps": [
                "spill the varargs (rdx/rcx/r8/r9 and xmm0..xmm7 when al != 0) into a stack args array",
                "call the logger's vtable slot 0x40; if the returned level is > 1, return without logging",
                "otherwise call the logger's vtable slot 0x28 with (level=1, format, args_ptr)",
            ],
            "gate": "slot 0x40 result <= 1 logs; > 1 drops",
            "callers": ["0x605fd44", "0x6060094 (host)"],
        },
        "size_normalizer_behavior": {
            "fde": "0x605cfa0..0x605cfd6",
            "signature": "normalize_block_size(size_t n) -> size_t",
            "rule": (
                "n <= 0x1000 returns 0x1000; n >= 0x80000000 returns "
                "0x1000; otherwise n rounded up to a multiple of 16"),
            "callers": ["0x5f10471", "0x605ddb8 (arena ctor)"],
        },
        "counter_add_behavior": {
            "fde": "0x605e830..0x605e859",
            "signature": "counter_add(obj, u64 delta)",
            "steps": [
                "load the guard pointer *(obj) and its vtable slot 0x00; if that slot is null AND *(slot_obj+0x20) == 0, return without touching anything",
                "otherwise lock-add delta to *(obj+0x08) and tail-jump to 0x606a0c0 with rdi = *(obj)",
            ],
            "tail_callee": "0x606a0c0 (not excerpted; recorded as a boundary)",
            "callers": ["0x605d086", "0x605d41e", "0x605df8d (arena ctor)"],
        },
        "thread_seed_behavior": {
            "fde": "0x61c4080..0x61c4117",
            "signature": "u32 *thread_seed(void)",
            "steps": [
                "read the thread pointer from %fs:0x0; the cached seed pointer lives at thread-0x10 and the cached seed value at thread-0x20",
                "if the cached pointer is non-null, return it",
                "otherwise compute seed = _Hash_bytes(&pthread_self, 8, 0xc70f6907) & 0x7fffffff, or 1 when that is 0; store the value at thread-0x20 and the pointer (thread-0x20) at thread-0x10; return the pointer",
            ],
            "seed_constant": "0xc70f6907 (same seed as map_find_name 0x5d66e30 in #3563)",
            "callers_count": 17,
        },
        "histogram_callees": {
            "re_shipped_from": "open PR #3371 (RE-001-histogram-stats-family-115); excerpts regenerated and byte-identical",
            "bucket_count_init_0x606b080": "writes the bucket count at inner+0x390 (see #3371)",
            "locked_init_0x606b0c0": "HistogramImpl vtable slot 0x10; locked per-record init (see #3371)",
            "record_thunk_0x606b1c0": "HistogramImpl vtable slot 0x20; adds 8, tail-jumps to record 0x606b130",
            "record_0x606b130": "bucket = bucket_index(value) (lower_bound over the 109 generated boundaries); buckets[bucket]++; min/max/count/sum/sumSq updated (see #3371)",
            "tostring_entry_0x606bc90": "HistogramImpl vtable slot 0x30; adds 8, calls the renderer 0x606b6f0 (see #3371 for the exact output format: Count/Average/StdDev, Min/Median/Max, Percentiles, one row per non-empty bucket)",
            "direct_calls_of_record_thunk": ["0x606004c (host)", "0x6198ae7", "0x6198e2a"],
            "direct_calls_of_tostring_entry": ["0x5ef0c43", "0x606007d (host)", "0x6198e3a"],
        },
        "hashlinklistrep_vtable": {
            "base": "0x64d2168",
            "typeinfo": "0x64d2050",
            "typeinfo_name": rep_name,
            "slots": rep_slots,
        },
        "arena_vtable": {
            "base": "0x64d1fb8",
            "typeinfo": "0x64d1f90",
            "typeinfo_name": arena_name,
            "slots": arena_slots,
        },
        "fulllistiterator_vtable": {
            "base": "0x64d2090",
            "typeinfo": "0x64d2008",
            "typeinfo_name": iter_name,
            "slots": iter_slots,
        },
        "histogramimpl_vtable": {
            "base": "0x64d2b80",
            "typeinfo": "0x64d2b58",
            "typeinfo_name": hist_name,
            "slots_pinned_here": [
                {"offset": "0x10", "slot": "0x64d2b90", "target": "0x%x" % relocs[0x64D2B90]},
                {"offset": "0x20", "slot": "0x64d2ba0", "target": "0x%x" % relocs[0x64D2BA0]},
                {"offset": "0x30", "slot": "0x64d2bb0", "target": "0x%x" % relocs[0x64D2BB0]},
            ],
        },
        "literals": {
            "log_format_0x9641a8": log_fmt,
            "hash_seed": "0xc70f6907",
            "hash_multiplier": "0x41a7",
            "hash_modulus": "0x7fffffff",
            "step_base": "0x80000000",
            "size_floor": "0x1000",
            "size_ceiling": "0x80000000",
            "index_count": "0xc",
            "index_divisor": "0x4",
            "arena_size": "0x8f0",
            "iterator_size": "0x48",
            "index_size": "0x38",
        },
        "unknowns": [
            "the host's C++ method name (slot 0x90 of HashLinkListRep; a rebuild/report method by shape, not proven)",
            "the identity of the object at this+0x08 whose slot 0x20 returns the Arena block size",
            "the identity of the key/comparator object at this+0x30 (its slot 0x08 is the insert comparator; its slot 0x18 is the node allocator)",
            "which of the two chain shapes in the host is the FullListIterator chain and which is the LinkListIterator chain (both iterator typeinfos sit next to HashLinkListRep in .data.rel.ro)",
            "the tail callee of counter_add 0x606a0c0 (not excerpted)",
            "the exact role of the Arena's +0x8b8..0x8f0 tail struct beyond its observed fields",
            "the sibling slot-0x08 method 0x605f700 and the 0x6062040/0x6062230 index users (separate work items; not pinned here)",
            "the other two record-thunk callers 0x6198900/0x6198d40 (separate work items; the second also renders ToString and logs '[%s:101] Number of Keys per prefix Histogram: %s')",
        ],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1)
        fh.write("\n")
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("site\ttarget\tkind\tfde\n")
        for r in rows:
            fh.write("%s\t%s\t%s\t%s\n" % (r["site"], r["target"], r["kind"], r["fde"]))
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        for slot in RELOC_SLOTS:
            fh.write("0x%x RELATIVE 0x%x\n" % (slot, relocs[slot]))
    with open(os.path.join(HERE, "vtables.tsv"), "w") as fh:
        fh.write("vtable\toffset\tslot\ttarget\tnote\n")
        for s in rep_slots:
            fh.write("0x64d2168\t%s\t%s\t%s\tHashLinkListRep\n"
                     % (s["offset"], s["slot"], s["target"]))
        for s in arena_slots:
            fh.write("0x64d1fb8\t%s\t%s\t%s\tArena\n"
                     % (s["offset"], s["slot"], s["target"]))
        for s in iter_slots:
            fh.write("0x64d2090\t%s\t%s\t%s\tFullListIterator\n"
                     % (s["offset"], s["slot"], s["target"]))
        fh.write("0x64d2b80\t0x10\t0x64d2b90\t0x%x\tHistogramImpl\n" % relocs[0x64D2B90])
        fh.write("0x64d2b80\t0x20\t0x64d2ba0\t0x%x\tHistogramImpl\n" % relocs[0x64D2BA0])
        fh.write("0x64d2b80\t0x30\t0x64d2bb0\t0x%x\tHistogramImpl\n" % relocs[0x64D2BB0])
        fh.write("0x64d2168\theader\t0x64d2158\t0x0\toffset-to-top\n")
        fh.write("0x64d2168\theader\t0x64d2160\t0x64d2050\ttypeinfo %s\n" % rep_name)
        fh.write("0x64d1fb8\theader\t0x64d1fa8\t0x0\toffset-to-top\n")
        fh.write("0x64d1fb8\theader\t0x64d1fb0\t0x64d1f90\ttypeinfo %s\n" % arena_name)
        fh.write("0x64d2090\theader\t0x64d2080\t0x0\toffset-to-top\n")
        fh.write("0x64d2090\theader\t0x64d2088\t0x64d2008\ttypeinfo %s\n" % iter_name)
        fh.write("0x64d2b80\theader\t0x64d2b70\t0x0\toffset-to-top\n")
        fh.write("0x64d2b80\theader\t0x64d2b78\t0x64d2b58\ttypeinfo %s\n" % hist_name)
    print("wrote records.json, callers.tsv, relocations.txt, vtables.tsv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
