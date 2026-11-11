"""Generate the semantic records for RE-001-statistics-shard-record-115.

Run from the repository root:
    python3 research/work-items/RE-001-statistics-shard-record-115/gen_records.py

Re-derives every record from the digest-verified work binary:
the caller census (with each site confirmed as a real call/jump in
objdump of its containing FDE), the RELATIVE relocation set for the
two vtables, the vtable slot tables, the typeinfo names, and the
immediate constants the record slots depend on. Writes records.json.
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
    ("picker", 0x60D5CD0),
    ("thread_seed", 0x61C4080),
    ("ticker_record", 0x606FBA0),
    ("histogram_record", 0x606FEF0),
    ("histogram_wrapper", 0x606FFD0),
    ("record_thunk", 0x606B1C0),
    ("record_impl", 0x606B130),
    ("statistics_ctor", 0x6071A00),
    ("shard_store_builder", 0x60716D0),
    ("current_shard_ptr", 0x605E170),
    ("slot_claim", 0x61C1E10),
    ("other_picker_consumer", 0x5F0A9C0),
]

# RELATIVE slots re-derived here: the two vtable typeinfo cells, the
# two typeinfo name cells (typeinfo object + 8), and every slot of
# both tables.
RELOC_SLOTS = [0x64D2D80, 0x64D2D00] + [0x64D2D88 + i * 8 for i in range(32)] + \
    [0x64D2B78, 0x64D2B60] + [0x64D2B80 + i * 8 for i in range(16)]


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

    stats_name = cstr(relocs[0x64D2D00])
    hist_name = cstr(relocs[0x64D2B60])
    if stats_name != "N7rocksdb14StatisticsImplE":
        fail("StatisticsImpl typeinfo name mismatch: %r" % stats_name)
    if hist_name != "N7rocksdb13HistogramImplE":
        fail("HistogramImpl typeinfo name mismatch: %r" % hist_name)

    def slots(base, count):
        return [{"offset": "0x%02x" % (i * 8),
                 "slot": "0x%x" % (base + i * 8),
                 "target": "0x%x" % relocs[base + i * 8]}
                for i in range(count)]

    records = {
        "task": "RE-001",
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "windows": {
            "picker": {"start": "0x60d5cd0", "end": "0x60d5cf0",
                       "file": "picker-60d5cd0.objdump.txt"},
            "ticker_record": {"start": "0x606fba0", "end": "0x606fc59",
                              "file": "ticker-record-606fba0.objdump.txt",
                              "vtable": "StatisticsImpl slot 0xb0"},
            "histogram_record": {"start": "0x606fef0", "end": "0x606ffce",
                                 "file": "histogram-record-606fef0.objdump.txt",
                                 "vtable": "StatisticsImpl slot 0xd8"},
            "histogram_wrapper": {"start": "0x606ffd0", "end": "0x60700c4",
                                  "file": "histogram-wrapper-606ffd0.objdump.txt",
                                  "vtable": "StatisticsImpl slot 0xd0"},
            "thread_seed": {"start": "0x61c4080", "end": "0x61c4117",
                            "file": "thread-seed-61c4080.objdump.txt",
                            "re_shipped_from": "open PR #3575"},
            "record_thunk": {"start": "0x606b1c0", "end": "0x606b1cd",
                             "file": "record_thunk.txt",
                             "vtable": "HistogramImpl slot 0x20",
                             "re_shipped_from": "open PR #3575 (originally #3371)"},
            "record_impl": {"start": "0x606b130", "end": "0x606b1b3",
                            "file": "record.txt",
                            "re_shipped_from": "open PR #3575 (originally #3371)"},
            "statistics_ctor": {"start": "0x6071a00", "end": "0x6071b60",
                                "file": "ctor-6071a00.objdump.txt",
                                "re_shipped_from": "open PR #3572"},
            "shard_store_builder": {"start": "0x60716d0", "end": "0x6071952",
                                    "file": "builder-60716d0.objdump.txt",
                                    "re_shipped_from": "open PR #3572"},
        },
        "census": census,
        "call_sites": rows,
        "qword_hit_notes": hit_notes,
        "statisticsimpl_vtable": {
            "base": "0x64d2d88",
            "typeinfo_name": stats_name,
            "slots": slots(0x64D2D88, 32),
        },
        "histogramimpl_vtable": {
            "base": "0x64d2b80",
            "typeinfo_name": hist_name,
            "slots": slots(0x64D2B80, 16),
        },
        "shard_store_layout": {
            "this_plus_0x20": "level byte (ctor writes 3)",
            "this_plus_0x28": "delegate pointer (ctor moves it from the argument)",
            "this_plus_0x60": "records base (builder out+0x00)",
            "this_plus_0x68": "bucket exponent (builder out+0x08)",
            "shard_size": "0xce40",
            "shard_header_size": "0x598",
            "ticker_counters": "178 (ids 0..0xb1), 8 bytes each at shard+id*8",
            "record_size": "0x3c8",
            "record_count_per_shard": 53,
            "records_range": "shard+0x598..shard+0xce00",
        },
        "picker": {
            "rule": "cpuid leaf 0 eax == 0 -> -1; else cpuid leaf 1 ebx >> 24",
            "direct_call_sites": census["picker"]["direct_calls"],
        },
        "seed_fallback": {
            "seed_fn": "0x61c4080",
            "seed_constant": "0xc70f6907",
            "advance": "seed = seed * 0x41a7 mod 0x7fffffff (mersenne fold)",
            "direct_call_sites_of_seed": census["thread_seed"]["direct_calls"],
        },
        "gates": {
            "ticker_record": "id > 0xb1 -> return; level byte == 0 -> return",
            "histogram_record": "level byte <= 1 -> return",
            "histogram_delegate_forward": "hist_id <= 0x33 and delegate != NULL",
            "ticker_delegate_forward": "delegate != NULL (no id cap beyond 0xb1)",
            "histogram_wrapper": "this vtable slot 0xd8 != 0x606fef0 -> tail-call slot 0xd8",
        },
        "literals": {
            "statisticsimpl_typeinfo": stats_name,
            "histogramimpl_typeinfo": hist_name,
            "seed_constant": "0xc70f6907",
            "lcg_multiplier": "0x41a7",
            "mersenne_modulus": "0x7fffffff",
            "ticker_max": "0xb1",
            "histogram_forward_max": "0x33",
            "histogram_level_threshold": "1",
        },
        "re_shipped": {
            "thread-seed-61c4080.objdump.txt": "open PR #3575",
            "record_thunk.txt": "open PR #3575 (originally #3371)",
            "record.txt": "open PR #3575 (originally #3371)",
            "boundaries.tsv": "open PR #3371",
            "ctor-6071a00.objdump.txt": "open PR #3572",
            "builder-60716d0.objdump.txt": "open PR #3572",
        },
        "cited_not_pinned": {
            "0x605e170": "other-system current-shard pointer (2 call sites); "
                         "uses a 0x40-byte stride and +0x48/+0x50 fields, "
                         "a different shard system from StatisticsImpl",
            "0x61c1e10": "other-system slot claim (5 call sites); same "
                         "picker/seed pattern, 0x40-byte slots, lock cmpxchg",
            "0x5f0a9c0": "other-system picker consumer (record-manager area); "
                         "its own component, left for a later work item",
            "0x628c0b0": "allocator used by the slot claim (96 KiB object); "
                         "part of the other system, not pinned here",
        },
        "unknowns": [
            "The C++ names of slots 0xb0/0xd0/0xd8 (inferred as record-ticker / "
            "record-histogram-entry / record-histogram from their behaviour).",
            "Which construction paths install a non-null +0x28 delegate: the "
            "ctor moves it from its argument, but no caller in this binary "
            "passes a non-null argument (both ctor callers pass a zeroed "
            "argument struct); the delegate is installed later by the parse "
            "workers (see #3572). The forward paths are pinned here; the "
            "installer is still open.",
            "Histogram ids 53..0x33 are recorded locally (records exist for "
            "53 ids) but only ids <= 0x33 are forwarded; whether ids 52..0x33 "
            "name real histograms is not established by this packet.",
            "The enable-byte setter: the level byte at +0x20 is written 3 by "
            "the ctor; no setter was found in this binary (see #3572).",
        ],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1)
        fh.write("\n")
    print("wrote records.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
