"""Generate records.json, callers.tsv, relocations.txt and vtables.tsv.

Run from the repository root:
    python3 research/work-items/RE-001-statistics-impl-ctor-115/gen_records.py

Derives everything from the digest-verified work binary:
- runs census.py and parses its canonical output;
- maps every call/tail-jump site to its containing FDE (from a fresh
  objdump --dwarf=frames dump) and verifies the site is a real
  call/jmp to the target in objdump output of that FDE;
- resolves the HistogramImpl / StatisticsImpl vtable and typeinfo
  slots from .rela.dyn R_X86_64_RELATIVE entries;
- reads the literal strings the packet relies on.
Writes the four generated files next to this script.
"""

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
    ("ctor", 0x6071A00),
    ("ctor_cleanup", 0x6071952),
    ("builder", 0x60716D0),
    ("shared_init", 0x606B020),
    ("bucket_count_init", 0x606B080),
    ("locked_init", 0x606B0C0),
    ("allocator", 0x60D5D50),
    ("free", 0x60D5DB0),
    ("destroyer", 0x606FD30),
    ("noop_dtor", 0x5D89570),
    ("mutex_init", 0x60D50C0),
    ("mutex_destroy", 0x60D5170),
]

# RELATIVE slots whose addends this packet relies on.
RELOC_SLOTS = [
    0x64D2B78,  # HistogramImpl vtable: typeinfo -> 0x64d2b58
    0x64D2B80, 0x64D2B88, 0x64D2B90, 0x64D2B98, 0x64D2BA0, 0x64D2BA8,
    0x64D2BB0, 0x64D2BB8, 0x64D2BC0, 0x64D2BC8, 0x64D2BD0, 0x64D2BD8,
    0x64D2BE0, 0x64D2BE8, 0x64D2BF0, 0x64D2BF8,  # HistogramImpl slots
    0x64D2B60,  # HistogramImpl typeinfo +0x8: name -> 0x9753f0
    0x64ED2B8,  # GOT slot compared by the destroyer -> 0x5d89570
    0x64D2D80,  # StatisticsImpl vtable: typeinfo -> 0x64d2cf8
    0x64D2D00,  # StatisticsImpl typeinfo +0x8: name -> string
]

WINDOWS = {
    "ctor": ("0x6071a00", "0x6071b60", "ctor-6071a00.objdump.txt", "0075bce8"),
    "ctor_cleanup": ("0x6071952", "0x60719f2", "ctor-cleanup-6071952.objdump.txt", "0075bd30"),
    "builder": ("0x60716d0", "0x6071952", "builder-60716d0.objdump.txt", "0075bc98"),
    "shared_init": ("0x606b020", "0x606b07c", "shared_init.txt", "00368eb8"),
    "bucket_count_init": ("0x606b080", "0x606b0a2", "bucket_count_init.txt", "00368ecc"),
    "locked_init": ("0x606b0c0", "0x606b10a", "locked_init.txt", "0075b284"),
    "allocator": ("0x60d5d50", "0x60d5db0", "allocator-60d5d50.objdump.txt", "0036cac8"),
    "free": ("0x60d5db0", "0x60d5db9", "free-60d5db0.objdump.txt", "0036caf4"),
    "destroyer": ("0x606fd30", "0x606fd94", "destroyer-606fd30.objdump.txt", "003697d0"),
    "noop_dtor": ("0x5d89570", "0x5d89575", "noop-dtor-5d89570.objdump.txt", "0034b334"),
    "mutex_init": ("0x60d50c0", "0x60d5157", "mutex-init-60d50c0.objdump.txt", "00760714"),
    "mutex_destroy": ("0x60d5170", "0x60d5200", "mutex-destroy-60d5170.objdump.txt", "00760760"),
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
    import hashlib
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    blocks = run_census()
    fdes = fde_map()
    # census section for records.json (canonical, keyed by target hex)
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
    # relocations: scan .rela.dyn for the slots of interest
    RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8
    relocs = {}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if ro in RELOC_SLOTS and (info & 0xFFFFFFFF) == 8:
            relocs[ro] = add
    for slot in RELOC_SLOTS:
        if slot not in relocs:
            fail("missing RELATIVE entry for slot 0x%x" % slot)
    # classify qword hits: a hit is a RELATIVE addend field iff
    # hit-16 is an entry start with that addend.
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
    # typeinfo names
    def cstr(va):
        end = data.find(b"\x00", va)
        return data[va:end].decode()
    hist_name = cstr(relocs[0x64D2B60])
    stats_name = cstr(relocs[0x64D2D00])
    # literal: "StatisticsOption" at 0x4539e0
    opt16 = data[0x4539E0:0x4539F0]
    if opt16 != b"StatisticsOption":
        fail("literal at 0x4539e0 mismatch: %r" % opt16)
    type_byte = data[0x97877C]
    # HistogramImpl vtable slots
    hist_slots = []
    for off in range(0x00, 0x80, 0x08):
        slot = 0x64D2B80 + off
        hist_slots.append({"offset": "0x%02x" % off, "slot": "0x%x" % slot,
                           "target": "0x%x" % relocs[slot]})
    records = {
        "task": "RE-001",
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "provenance_path": "provenance/artifacts.json",
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
            "mutex_helpers_note": ("mutex_init 0x60d50c0 and mutex_destroy "
                                   "0x60d5170 are generic libstdc++-style "
                                   "wrappers with many callers; only the "
                                   "ctor/cleanup call sites belong to this "
                                   "work item, the rest are listed for "
                                   "completeness"),
        },
        "ctor_behavior": {
            "vtable_installed": "0x64d2d88",
            "typeinfo": "0x64d2cf8",
            "typeinfo_name": stats_name,
            "level_byte": {"offset": "+0x20", "value": 3},
            "zeroed_fields": ["+0x08", "+0x10", "+0x18", "+0x30"],
            "moved_pointers": {
                "arg+0x00": "this+0x28",
                "arg+0x08": "this+0x30",
                "arg_struct_zeroed_after_move": True,
            },
            "mutex": {"offset": "+0x38", "init": "0x60d50c0",
                      "type_byte_addr": "0x97877c", "type_byte": type_byte,
                      "type_arg_ignored": True},
            "shard_store": {"offset": "+0x60", "builder": "0x60716d0"},
            "record_appended": {"name": "StatisticsOptions", "length": 17,
                                "literal_addr": "0x4539e0",
                                "literal": "StatisticsOption",
                                "extra_byte": "0x73 ('s') at +0x10",
                                "callee": "0x6099ce0",
                                "callee_note": ("options_record_append, "
                                                "centerpiece of open PR "
                                                "#3257; called, not "
                                                "re-shipped")},
            "callers": ["0x6071bda", "0x6077b74"],
        },
        "ctor_cleanup_behavior": {
            "window": "0x6071952..0x60719f2",
            "entry": ("tail jump from the ctor landing pad 0x6071b37 only; "
                      "no endbr64; shares the ctor frame (canary slot "
                      "0x38(%rsp), rbx=this, r13=this+0x38, rbp=string, "
                      "r12=exception)"),
            "steps": [
                "dispose the partial StatisticsOptions string (rbp)",
                "rbp = exception (r12)",
                "if this+0x60 != 0: destroyer 0x606fd30(this+0x60)",
                "mutex_destroy 0x60d5170(this+0x38)",
                "if this+0x30 != 0: counted_release 0x5d350c0(this+0x30)",
                "install base vtable 0x64d3430 (Configurable) at *(this)",
                "destroy the vector at +0x08/+0x10/+0x18: 48-byte elements "
                "beginning with a std::string, freed via _ZdlPvm unless SSO",
                "free the vector buffer (_ZdlPvm, size = end - begin)",
                "_Unwind_Resume(exception)",
            ],
        },
        "builder_behavior": {
            "out_layout": {"records_base": "+0x00", "exponent": "+0x08"},
            "entry_zeroing": "*out = 0 at 0x60716e2",
            "bucket_count": {
                "small_path": {"condition": "ncpu <= 8", "exponent": 3,
                               "count": 8, "alloc_size": "0x67240"},
                "main_path": ("smallest exponent e >= 4 with (1 << e) >= "
                              "ncpu; count = 1 << e; "
                              "alloc_size = count * 0xce40 + 0x40"),
                "guard": {"constant": "0x9ee009ee009e",
                          "throw": "count > 0x9ee009ee009e -> "
                                   "__cxa_throw_bad_array_new_length"},
                "stored": {"count_at": "alloc+0x38",
                           "records_base": "alloc+0x40"},
            },
            "shard_layout": {
                "stride": "0xce40",
                "header_zeroed": "0x598 bytes at shard start (rep stos, "
                                 "0xb3 qwords)",
                "records_per_shard": 53,
                "record_stride": "0x3c8",
                "record_region": "shard+0x598 .. shard+0xce00",
                "tail_untouched": "shard+0xce00 .. shard+0xce40 (0x40 bytes)",
            },
            "per_record_init": [
                "*(rec) = 0x64d2b80 (HistogramImpl vtable)",
                "call 0x606b080(rec+8): writes rec+0x398 (bucket count), "
                "then tail-jumps to shared init 0x606b020(rec+8)",
                "zero rec+0x3c0 (qword) and rec+0x3a0..0x3b0 (32 bytes, movups)",
                "call 0x606b0c0(rec): lock mutex at rec+0x3a0, call shared "
                "init 0x606b020(rec+8) again, unlock",
                "note: shared init runs twice per record (once unlocked via "
                "0x606b080, once locked via 0x606b0c0); both runs write the "
                "same values",
            ],
            "old_store_release": {
                "reachable": False,
                "reason": ("the entry zeroes *out (0x60716e2) before the "
                           "release test at 0x60717fa reads *out, so the "
                           "test always sees 0 and jumps to the return; "
                           "the release loop (0x60717eb..0x607186d) and the "
                           "unwind destroy call at 0x60718f8 are dead code "
                           "in this binary"),
                "loop_shape_if_reached": ("walk old shards back to front, "
                                          "call each record's vtable slot 0 "
                                          "unless it equals 0x5d89570, then "
                                          "free(old-0x40)"),
            },
            "unwind_paths": {
                "record_init_exception": ("destroy already-built records "
                                          "backwards via slot 0 (the no-op "
                                          "0x5d89570), then free the new "
                                          "allocation"),
                "shard_exception": ("same per-shard walk for completed "
                                    "shards, then free"),
            },
        },
        "record_init_behavior": {
            "re_shipped_from": ("open PR #3371 "
                                "RE-001-histogram-stats-family-115; "
                                "excerpts regenerated here byte-identical "
                                "from the same binary"),
            "shared_init_0x606b020": {
                "arg": "rec+8",
                "writes": {
                    "(rec+8)+0x00": "*(0x6505d38) (min pointer, runtime global)",
                    "(rec+8)+0x08": 0, "(rec+8)+0x10": 0,
                    "(rec+8)+0x18": 0, "(rec+8)+0x20": 0,
                },
                "bucket_zeroing": ("if rec+0x398 != 0: zero the first qword "
                                   "of each of count buckets at "
                                   "rec+0x30 + i*0x28 (i = 0..count-1); "
                                   "bucket stride 0x28 (40 bytes)"),
                "bucket_array_bound": ("array must end by the mutex at "
                                       "rec+0x3a0, so count <= 22"),
            },
            "bucket_count_init_0x606b080": {
                "writes": ("rec+0x398 = (*(0x6505d28) - *(0x6505d20)) >> 3 "
                           "(runtime global range / 8)"),
                "tail": "jmp 0x606b020",
            },
            "locked_init_0x606b0c0": {
                "steps": ["lock pthread mutex at rec+0x3a0",
                          "call shared init 0x606b020(rec+8)",
                          "unlock; on lock failure throw system error"],
            },
        },
        "record_layout": {
            "size": "0x3c8",
            "vtable": "+0x00 = 0x64d2b80",
            "min_ptr": "+0x08 = *(0x6505d38)",
            "zeroed_qwords": ["+0x10", "+0x18", "+0x20", "+0x28"],
            "bucket_array": "+0x30, stride 0x28, count at +0x398",
            "bucket_count_field": "+0x398",
            "mutex": "+0x3a0 (pthread_mutex_t, zeroed then locked)",
            "zeroed_tail": ["+0x3b0 (16 bytes, movups)", "+0x3c0 (qword)"],
        },
        "record_vtable": {
            "base": "0x64d2b70",
            "offset_to_top": 0,
            "typeinfo": "0x64d2b58",
            "typeinfo_name": hist_name,
            "vtable_ptr_installed": "0x64d2b80",
            "slots": hist_slots,
            "slot_roles_known": {
                "0x00": "0x5d89570 no-op dtor (ret only)",
                "0x10": "0x606b0c0 locked init",
            },
            "slot_roles_open": ("slots 0x08, 0x18, 0x20, 0x28, 0x30, 0x38, "
                                "0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, "
                                "0x78 are other HistogramImpl methods; "
                                "0x606b1c0 (slot 0x20) is the outer record "
                                "thunk whose callers are 0x606004c, "
                                "0x6198ae7, 0x6198e2a"),
        },
        "statisticsimpl_vtable": {
            "base": "0x64d2d78",
            "offset_to_top": 0,
            "typeinfo": "0x64d2cf8",
            "typeinfo_name": stats_name,
            "vtable_ptr_installed": "0x64d2d88",
            "slots_note": ("the 32 slots are pinned by open PRs #3396 "
                           "(write side), #3392 (locked read accessors), "
                           "#3378 (slot-0xf0), #3362 (produce 0x6070810); "
                           "this packet pins only the ctor that installs it"),
        },
        "allocator_behavior": {
            "allocator_0x60d5d50": {
                "method": "posix_memalign(&out, 0x40, size)",
                "alignment": 64,
                "on_success": "return out",
                "on_failure": "return NULL, store the error code in *errno",
                "stack_protector": True,
            },
            "free_0x60d5db0": "tail-jmp to free@plt",
        },
        "destroyer_behavior": {
            "arg": "records base (alloc+0x40)",
            "count_source": "*(base-8) = alloc+0x38 (bucket_count)",
            "order": ("shards last to first; within a shard records from "
                      "shard+0xca38 down to shard+0x598 step 0x3c8 (53)"),
            "skip_rule": ("call record slot 0 unless it equals "
                          "*(GOT 0x64ed2b8), which resolves to 0x5d89570 "
                          "via RELATIVE; HistogramImpl records always skip, "
                          "so the walk calls nothing for them"),
            "end": "free(base-0x40)",
            "live_callers": ["0x60719b9 (ctor cleanup partition)"],
            "dead_callers": ["0x6071904 (builder unwind pad; *out is 0)"],
        },
        "mutex_behavior": {
            "init_0x60d50c0": {
                "method": "pthread_mutex_init(mutex, NULL)",
                "second_arg_ignored": True,
                "ok_codes": [0, 16, 110],
                "on_other_error": "print via __fprintf_chk and abort",
            },
            "destroy_0x60d5170": {
                "method": "pthread_mutex_destroy(mutex)",
                "ok_codes": [0, 16, 110],
                "on_other_error": "print via __fprintf_chk and abort",
            },
        },
        "unknowns": [
            "the runtime values at 0x6505d20/0x6505d28/0x6505d38 (bucket range and min pointer) — .bss, zero in the file; the bucket count they imply must be <= 22 to fit before the record mutex",
            "the contents of the 0x598-byte shard header (zeroed by the builder, never read by this packet's routines) and of the 0x40-byte shard tail",
            "the roles of StatisticsImpl +0x28/+0x30 (two pointers moved from the ctor argument; +0x30 is released via counted_release in the cleanup, +0x28 is not)",
            "the semantics of HistogramImpl vtable slots other than 0x00 and 0x10",
            "who calls the ctor at 0x6077b74 and at 0x6071bda, and what argument struct they pass",
            "the 48-byte vector elements at StatisticsImpl +0x08 beyond their leading std::string",
            "why the builder zeroes *out before the release test (source-level intent of the dead release loop)",
        ],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1)
        fh.write("\n")
    print("wrote records.json")
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("site\ttarget\tkind\tcontaining_fde\n")
        for r in rows:
            fh.write("%s\t%s\t%s\t%s\n" % (r["site"], r["target"], r["kind"], r["fde"]))
    print("wrote callers.tsv (%d rows)" % len(rows))
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        for slot in sorted(relocs):
            fh.write("0x%x\tR_X86_64_RELATIVE\t0x%x\n" % (slot, relocs[slot]))
    print("wrote relocations.txt (%d rows)" % len(relocs))
    with open(os.path.join(HERE, "vtables.tsv"), "w") as fh:
        fh.write("vtable\toffset\tslot\ttarget\tnote\n")
        for s in hist_slots:
            fh.write("0x64d2b80\t%s\t%s\t%s\tHistogramImpl\n"
                     % (s["offset"], s["slot"], s["target"]))
        fh.write("0x64d2d88\theader\t0x64d2d78\t0x0\toffset-to-top\n")
        fh.write("0x64d2d88\theader\t0x64d2d80\t0x%x\ttypeinfo %s\n"
                 % (relocs[0x64D2D80], stats_name))
        fh.write("0x64d2b80\theader\t0x64d2b70\t0x0\toffset-to-top\n")
        fh.write("0x64d2b80\theader\t0x64d2b78\t0x%x\ttypeinfo %s\n"
                 % (relocs[0x64D2B78], hist_name))
    print("wrote vtables.tsv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
