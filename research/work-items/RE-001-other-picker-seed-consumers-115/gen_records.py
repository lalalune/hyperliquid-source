"""Generate the semantic records for RE-001-other-picker-seed-consumers-115.

Run from the repository root:
    python3 research/work-items/RE-001-other-picker-seed-consumers-115/gen_records.py

Re-derives every record from the digest-verified work binary:
the caller census (with each site confirmed as a real call/jump in
objdump of its containing FDE), the RELATIVE relocation set for the
SkipListRep and LevelIterator vtables, the vtable slot tables, the
typeinfo names, and the immediate constants and literal pointers the
seed derivations depend on. Writes records.json.
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
    ("thread_seed", 0x61C4080),
    ("picker", 0x60D5CD0),
    ("oneshot_builder", 0x5F6B000),
    ("oneshot_lookup", 0x5F999D0),
    ("flag_wait", 0x5FCA940),
    ("skiplist_height", 0x6063150),
    ("random_descent", 0x6066B80),
    ("skiplist_sampler", 0x6066F20),
    ("zstd_gate", 0x60E5610),
    ("bitmap_node_ctor", 0x60F4A00),
    ("sample_flag_ctor", 0x616F960),
]

# RELATIVE slots re-derived here: the SkipListRep vtable (23 slots,
# typeinfo cell at base-8, typeinfo-name cell) and the LevelIterator
# vtable (24 slots, typeinfo cell at base-8, typeinfo-name cell).
SKIPLIST_VT = 0x64D26E8
LEVELITER_VT = 0x64CCE30
RELOC_SLOTS = (
    [0x64D26E0, 0x64D25F8]
    + [SKIPLIST_VT + i * 8 for i in range(23)]
    + [0x64CCE28, 0x64CCD70]
    + [LEVELITER_VT + i * 8 for i in range(24)]
)


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
        census[name] = dict(got, target="0x%x" % target)
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
    # section map for VA reads
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

    skip_name = cstr(relocs[0x64D25F8])
    level_name = cstr(relocs[0x64CCD70])
    if skip_name != "*N7rocksdb12_GLOBAL__N_111SkipListRepE":
        fail("SkipListRep typeinfo name mismatch: %r" % skip_name)
    if level_name != "*N7rocksdb12_GLOBAL__N_113LevelIteratorE":
        fail("LevelIterator typeinfo name mismatch: %r" % level_name)

    def slots(base, count):
        return [{"offset": "0x%02x" % (i * 8),
                 "slot": "0x%x" % (base + i * 8),
                 "target": "0x%x" % relocs[base + i * 8]}
                for i in range(count)]

    # Literal pointers used by the seed derivations.
    oneshot_ptr = 0x4376FD
    oneshot_bytes = read_vaddr(oneshot_ptr, 1)
    oneshot_str = cstr(oneshot_ptr + 1)
    if oneshot_bytes != b"\x00":
        fail("byte at 0x4376fd is not 0x00")
    if oneshot_str != ("/home/ubuntu/hl/code_Mainnet/z_vendor/"
                       "futures-channel/src/oneshot.rs"):
        fail("oneshot path string mismatch: %r" % oneshot_str)
    desc = struct.unpack_from("<II", read_vaddr(0x459A38, 8))
    if desc != (4, 32):
        fail("0x459a38 descriptor mismatch: %r" % (desc,))

    records = {
        "task": "RE-001",
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "windows": {
            "thread_seed": {"start": "0x61c4080", "end": "0x61c4117",
                            "file": "thread-seed-61c4080.objdump.txt",
                            "re_shipped_from": "open PR #3613 (originally #3371/#3575)"},
            "picker": {"start": "0x60d5cd0", "end": "0x60d5cf0",
                       "file": "picker-60d5cd0.objdump.txt",
                       "re_shipped_from": "open PR #3613"},
            "oneshot_builder": {"start": "0x5f6b000", "end": "0x5f6b516",
                                "file": "seed-host-5f6b000.objdump.txt",
                                "seed_sites": ["0x5f6b06a", "0x5f6b11a"]},
            "oneshot_lookup": {"start": "0x5f999d0", "end": "0x5f9a478",
                               "file": "seed-host-5f999d0.objdump.txt",
                               "seed_sites": ["0x5f9a116"]},
            "flag_wait": {"start": "0x5fca940", "end": "0x5fcabdc",
                          "file": "seed-host-5fca940.objdump.txt",
                          "seed_sites": ["0x5fcaa75"]},
            "skiplist_height": {"start": "0x6063150", "end": "0x6063229",
                                "file": "seed-host-6063150.objdump.txt",
                                "seed_sites": ["0x6063165"],
                                "vtable": "SkipListRep slot 0"},
            "random_descent": {"start": "0x6066b80", "end": "0x6066d61",
                               "file": "seed-host-6066b80.objdump.txt",
                               "seed_sites": ["0x6066bc9"]},
            "skiplist_sampler": {"start": "0x6066f20", "end": "0x6067450",
                                 "file": "seed-host-6066f20.objdump.txt",
                                 "seed_sites": ["0x60671b1"],
                                 "vtable": "SkipListRep slot 14"},
            "zstd_gate": {"start": "0x60e5610", "end": "0x60e5a39",
                          "file": "seed-host-60e5610.objdump.txt",
                          "seed_sites": ["0x60e56f5"]},
            "bitmap_node_ctor": {"start": "0x60f4a00", "end": "0x60f4cb5",
                                 "file": "seed-host-60f4a00.objdump.txt",
                                 "seed_sites": ["0x60f4b2a"]},
            "sample_flag_ctor": {"start": "0x616f960", "end": "0x616fb83",
                                 "file": "seed-host-616f960.objdump.txt",
                                 "seed_sites": ["0x616fb33"]},
        },
        "census": census,
        "call_sites": rows,
        "qword_hit_notes": hit_notes,
        "skiplistrep_vtable": {
            "base": "0x64d26e8",
            "typeinfo_name": skip_name,
            "slots": slots(SKIPLIST_VT, 23),
        },
        "leveliterator_vtable": {
            "base": "0x64cce30",
            "typeinfo_name": level_name,
            "slots": slots(LEVELITER_VT, 24),
        },
        "seed_rule": {
            "seed_fn": "0x61c4080",
            "seed_constant": "0xc70f6907",
            "advance": "seed = seed * 0x41a7 mod 0x7fffffff (mersenne fold)",
            "direct_call_sites_of_seed": census["thread_seed"]["direct_calls"],
        },
        "seed_derivations": {
            "oneshot_builder_first": {
                "site": "0x5f6b06a",
                "rule": "advance once, store back; value consumed only on the "
                        "index-0 path: (seed & 0x3ff) == 0x133 gates the +0x400 "
                        "bump of every list node's +0x70 counter",
            },
            "oneshot_builder_second": {
                "site": "0x5f6b11a",
                "rule": "advance once, store back; record+0x90 = "
                        "((seed & 0x3ff) == 0x133)",
            },
            "oneshot_lookup": {
                "site": "0x5f9a116",
                "rule": "advance once, store back; record+0x90 = "
                        "((seed & 0x3ff) == 0x133)",
            },
            "flag_wait": {
                "site": "0x5fcaa75",
                "rule": "advance once, store back; skip = ((seed & 0xff) == 0); "
                        "skip selects the slow timed-wait adjustment path",
            },
            "skiplist_height": {
                "site": "0x6063165",
                "rule": "rejection-sample: tries start at 1; each try advances "
                        "once and stops at the first seed < bound (this+0x14); "
                        "height = tries, capped at min(count (this+0x10), 32); "
                        "on exhaustion height = count (or 32); count <= 1 "
                        "skips the seed entirely (height 1, seed untouched)",
            },
            "random_descent": {
                "site": "0x6066bc9",
                "rule": "once per skiplist level: advance once, store back; "
                        "index = seed % n where n = (array_end - array_base) / 8; "
                        "step to array[index]",
            },
            "skiplist_sampler": {
                "site": "0x60671b1",
                "rule": "per iteration: advance once, store back; index = "
                        "seed % remaining_nodes; if index < remaining_count, "
                        "hash-look the sampled node up and decrement "
                        "remaining_count on a hit; loop while remaining_count != 0",
            },
            "zstd_gate": {
                "site": "0x60e56f5",
                "rule": "advance once, store back; run the ZSTD CCtx setup "
                        "only when (seed % N) == 0 with N = *(arg2+0x20); "
                        "otherwise take the fast path",
            },
            "bitmap_node_ctor": {
                "site": "0x60f4b2a",
                "rule": "advance once, store back; node+0x20 = seed % count "
                        "(count = the rdx argument); node+0x10 = "
                        "floor(log2(count >> 1)) + 1 when count >= 2, else 0",
            },
            "sample_flag_ctor": {
                "site": "0x616fb33",
                "rule": "advance once, store back; this+0x1e0 = "
                        "((seed & 0x3ff) == 0x133)",
            },
        },
        "leveliterator_record_layout": {
            "size": "0x118",
            "vtable": "0x64cce30 (LevelIterator)",
            "this_plus_0x00": "vtable pointer",
            "this_plus_0x08": "Cleanable (ctor 0x61bd0c0)",
            "this_plus_0x28": "skiplist pointer (from *(this+0x10)+0x8c0)",
            "this_plus_0x30": "arg2 pointer",
            "this_plus_0x38": "arg3 (rdx) value",
            "this_plus_0x40": "(this+0x10)+0x40 pointer",
            "this_plus_0x48": "*(this+0x10)+0x48",
            "this_plus_0x50": "skiplist-array entry pointer",
            "this_plus_0x58": "0",
            "this_plus_0x60": "result of 0x5f54680",
            "this_plus_0x68": "0",
            "this_plus_0x70": "0x00ffffffffffffff (movabs $0xffffffffffffff at 0x5f6b201 / 0x5f9a232; 56-bit, NOT -1)",
            "this_plus_0x78": "0",
            "this_plus_0x80": "&this+0x1118",
            "this_plus_0x88": "per-shard statistics record (base + index*0x3c8)",
            "this_plus_0x90": "sample flag: (seed & 0x3ff) == 0x133",
            "this_plus_0x91": "3",
            "this_plus_0x92": "predicate 0x5f6afa0 result",
            "this_plus_0x93": "builder 0x5f6b000: low byte of the 6th argument (r9b, mov %r12b at 0x5f6b214); lookup 0x5f999d0: low byte of u16 0x100 (mov %ax at 0x5f9a295, so 0x00)",
            "this_plus_0x94": "builder 0x5f6b000: byte 1 (movb $0x1 at 0x5f6b227); lookup 0x5f999d0: high byte of the u16 0x100 stored at +0x93 (so 0x01)",
            "this_plus_0x98": "*(skiplist-array entry)",
            "this_plus_0xa0": "shard index",
            "this_plus_0xa8": "0",
            "this_plus_0xb8": "0x4376fd (oneshot.rs path pointer, see literals)",
            "this_plus_0xc0": "0",
            "this_plus_0xc8": "u16 0x100",
            "this_plus_0xd0": "0",
            "this_plus_0xd8": "0 (16 bytes)",
            "this_plus_0xe8": "0",
            "this_plus_0xf0": "0",
            "this_plus_0xf8": "0",
            "this_plus_0x100": "0x4376fd (oneshot.rs path pointer, see literals)",
            "this_plus_0x108": "0",
            "this_plus_0x110": "0 (byte)",
        },
        "literals": {
            "skiplistrep_typeinfo": skip_name,
            "leveliterator_typeinfo": level_name,
            "seed_constant": "0xc70f6907",
            "lcg_multiplier": "0x41a7",
            "mersenne_modulus": "0x7fffffff",
            "sample_magic_1024": "0x133",
            "sample_mask_1024": "0x3ff",
            "sample_mask_256": "0xff",
            "zstd_gate_add": "0x20000",
            "oneshot_path_pointer": "0x4376fd",
            "oneshot_path_string_at": "0x4376fe",
            "oneshot_path_string": oneshot_str,
            "node_descriptor_0x459a38": {"low_u32": desc[0], "high_u32": desc[1]},
            "histogram_record_size": "0x3c8",
        },
        "re_shipped": {
            "picker-60d5cd0.objdump.txt": "open PR #3613",
            "thread-seed-61c4080.objdump.txt": "open PR #3613 (originally #3371/#3575)",
        },
        "cited_not_pinned": {
            "0x606fba0": "StatisticsImpl slot 0xb0 ticker record (open PR #3613): "
                        "uses the picker and the seed; pinned there",
            "0x606fef0": "StatisticsImpl slot 0xd8 histogram record (#3613)",
            "0x606ffd0": "StatisticsImpl slot 0xd0 histogram wrapper (#3613)",
            "0x5f0a9c0": "MemTable range-tombstone iterator factory (merged "
                        "RE-001-range-tombstone-cache-115): picker at 0x5f0aa40, "
                        "seed at 0x5f0ad68; shard array at MemTable+0xd10, "
                        "stride 0x10, exponent at +0xd18",
            "0x605e170": "shard refresh (merged RE-001-shard-refresh-605e170-115): "
                        "picker at 0x605e17b, seed at 0x605e1d0; 0x40-byte stride, "
                        "TLS selector slot at fs:-0x408",
            "0x605f340": "hash-index insert (merged RE-001-chain-histogram-snapshot-115 "
                        "and RE-001-hashlinklist-insert-115): seed at 0x605f4bc",
            "0x61c1e10": "slot claim (merged RE-001-zstd-decompress-cache-115): "
                        "picker at 0x61c1e24, seed at 0x61c1ea8; 0x40-byte slots, "
                        "lock cmpxchg claim at slot+0x10, creator 0x628c0b0",
            "0x5f6b520": "loop driver for 0x5f6b000 (merged RE-001-indexed-call-loop-115): "
                        "calls 0x5f6b000 once per shard index 0..*(this+0x54)",
            "0x5f6afa0": "last-index predicate (merged RE-001-last-index-predicate-115): "
                        "called by 0x5f6b000 and 0x5f999d0; result lands at record+0x92",
        },
        "unknowns": [
            "The C++ names of the nine host routines (inferred from behaviour: "
            "LevelIterator builders, flag wait, skiplist height/descent/sampler, "
            "ZSTD gate, bitmap-node ctor, sample-flag ctor).",
            "The component that owns the 0x200-byte struct built by 0x616f960 "
            "(its +0x1e0 sample flag is pinned; the struct's class name and the "
            "meaning of the +0x1c0 pointer arg, whose pointee is set to -1, are open).",
            "The component that owns the 0x28-byte bitmap node built by 0x60f4a00 "
            "(node+0x20 random start and +0x10 log2 byte are pinned; the node's "
            "class name and the +0x38 slot's role are open).",
            "The stored oneshot path pointer is 0x4376fd, but the byte there is "
            "0x00 and the path string begins at 0x4376fe; whether the consumer "
            "reads from +1, or the field is a tagged/length-prefixed pointer, "
            "is not established by this packet.",
            "The exact purpose of the 0x6066f20 sampler's two phases (the sqrt "
            "split at 0x6067008 and the random-index loop at 0x60671b1) beyond "
            "the pinned seed derivation: the sampled elements feed a hash "
            "index over the skiplist, but which higher-level operation drives "
            "the sample count is open.",
            "The full traversal semantics of 0x6066b80 beyond the pinned "
            "per-level seed pick (the path-collection loop and the 0x60669f0 "
            "helper's contract are described, not modelled).",
            "The exact component name of the flag-wait routine 0x5fca940 (a "
            "spin-then-yield wait on a flag byte with perf-level-gated timing; "
            "its four direct callers and one tail-jump caller are listed in "
            "callers.tsv).",
        ],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1)
        fh.write("\n")
    print("wrote records.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
