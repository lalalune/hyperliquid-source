"""Generate records.json for RE-001-range-tombstone-cache-115.

Run from the repository root:
    python3 research/work-items/RE-001-range-tombstone-cache-115/gen_records.py

Derives the windows (FDE ranges from objdump --dwarf=frames), the
caller census (from census.py's binary scan) and the per-window sample
bytes (from the raw binary) directly from the digest-verified binary.
The semantic constants (layout, rules, roles, the shard/iterator
contracts) are the packet author's readings of the verbatim excerpts,
recorded here so the checker can re-derive them; the model in tools/
implements the same rules and its tests exercise them end to end.
"""

import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = {
    "host": ("0x5f0a9c0", "0x5f0b04c"),
    "shard": ("0x605e170", "0x605e20d"),
    "picker": ("0x60d5cd0", "0x60d5cf0"),
    "seed": ("0x61c4080", "0x61c4117"),
    "ctor_a": ("0x5f31380", "0x5f3146f"),
    "ctor_b": ("0x5f315a0", "0x5f316ce"),
    "cache_ctor": ("0x5f37410", "0x5f37e31"),
    "cleanable_ctor": ("0x61bd0c0", "0x61bd0d4"),
    "cleanable_dtor": ("0x61bd0e0", "0x61bd131"),
    "release": ("0x5d350c0", "0x5d35145"),
    "list_release": ("0x5f059b0", "0x5f05b79"),
}

# Caller roles, read from objdump around each census site. The FDE is
# the containing function; no symbol names exist in the stripped binary
# except where the vendor census names the function (noted as such).
# Sites without an explicit role get "consumer in FDE <start>
# (exact use open)".
CALLER_ROLES = {
    0x5F0E061: "the merged RE-014 batch-lookup function 0x5f0d740 "
               "(window-5f0d740.objdump.txt, merged): at 0x5f0e061 it "
               "calls the host with (owner, arg2, seq>>8, flag), then "
               "applies 0x5f32900 to the returned iterator and destroys "
               "it via vtable slot 0x8",
    0x5F0B068: "the merged RE-014 probe-gated-lookup thunk 0x5f0b050: "
               "tail-jumps to the host (by contract)",
    0x5F11931: "merged RE-001 shard-allocate 0x5f117a0: calls the "
               "shard refresh",
    0x5F11CF7: "merged RE-001 allocate 0x5f11c40: calls the shard refresh",
    0x5F0AA40: "host: CPUID picker for the shard index",
    0x605E17B: "shard helper: CPUID picker for the shard index",
    0x606FBC4: "StatisticsImpl ticker slot 0xb0 0x606fba0 (open PR "
               "#3613): CPUID picker",
    0x606FF0C: "StatisticsImpl histogram slot 0xd8 0x606fef0 (open PR "
               "#3613): CPUID picker",
    0x6070003: "StatisticsImpl histogram wrapper slot 0xd0 0x606ffd0 "
               "(open PR #3613): CPUID picker",
    0x61C1E24: "ZSTD decompress slot claim 0x61c1e10 (open PR #3635): "
               "CPUID picker",
    0x5F0AD68: "host: per-thread seed when the picker returns -1",
    0x605E1D0: "shard helper: per-thread seed when the picker returns -1",
    0x605F4BC: "HashLinkListRep index-insert 0x605f340 (open PR #3575): "
               "per-thread seed",
    0x606FC20: "ticker slot 0xb0 (open PR #3613): seed advance",
    0x606FF90: "histogram slot 0xd8 (open PR #3613): seed advance",
    0x6070088: "histogram wrapper 0xd0 (open PR #3613): seed advance",
    0x61C1EA8: "ZSTD decompress slot claim 0x61c1e10 (open PR #3635): seed",
    0x5F0AA15: "host: builds the 0xc8 iterator from a fresh list "
               "(flag path)",
    0x5F33A3B: "second ctor-A consumer in FDE 0x5f33950 (exact use open)",
    0x5F0AB05: "host: builds the 0xc8 iterator from the cached shared_ptr",
    0x5F0AC12: "host: builds the 0xe8 cache from the fresh 0x80 list",
    0x5F0A536: "sibling cache builder in FDE 0x5f0a3d0 (exact use open)",
    0x5F29367: "cache consumer in FDE 0x5f29140 (exact use open)",
    0x6109F07: "cache consumer in FDE 0x6109c40 (exact use open)",
    0x5F05A41: "self-recursion on the +0x18 child",
    0x5F0ACC4: "host teardown: releases the old cache's +0x60 node list",
    0x5F0A610: "sibling cache builder in FDE 0x5f0a3d0 (exact use open)",
    0x5F3799F: "cache ctor: finalizes the cache (main path)",
    0x5F37AD1: "cache ctor: finalizes the cache (null-list path)",
    0x5F0E09C: "the batch-lookup caller (FDE 0x5f0d740): applies it to "
               "the host's returned iterator",
    0x5F0AE03: "host teardown: moves the old cache's +0xc0 array entries",
    0x5F0AE27: "host teardown: copies into the old cache's +0xc0 array "
               "(upper half)",
    0x5F0AF39: "host teardown: copies the old cache's +0xc0 array "
               "(lower half)",
}

# In-packet call sites of the three generic helpers (libstdc++/
# RocksDB-wide; full caller lists are 103 / 223+32 / 1273+25 sites
# and add no RE value, so only the sites this behaviour uses are
# pinned here). Each is verified as a real call in its FDE.
PACKET_INTERNAL_SITES = {
    "0x61bd0c0": [
        (0x5F0AB3C, "host: the fresh 0x80 list's Cleanable at +0x8"),
        (0x5F313A8, "ctor A: the iterator's comparator Cleanable at +0x8"),
        (0x5F315C8, "ctor B: the iterator's comparator Cleanable at +0x8"),
        (0x5F374CD, "cache ctor: the cache's Cleanable at +0x98"),
        (0x5F37827, "cache ctor: a stack iterator's Cleanable"),
    ],
    "0x61bd0e0": [
        (0x5F0AC60, "host teardown: the old cache's +0x98 Cleanable"),
    ],
    "0x5d350c0": [
        (0x5F0AB18, "host: release the claim-time shared_ptr reference"),
    ],
}

GENERIC_HELPER_COUNTS = {
    "0x61bd0c0": "103 direct calls",
    "0x61bd0e0": "223 direct calls + 32 tail jumps",
    "0x5d350c0": "1273 direct calls + 25 tail jumps",
}


def fde_table():
    out = subprocess.run(
        ["objdump", "--dwarf=frames", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    fdes = []
    for m in re.finditer(
            r"^([0-9a-f]{8}) \S+ \S+ FDE cie=([0-9a-f]+) "
            r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", out, re.M):
        fdes.append((int(m.group(3), 16), int(m.group(4), 16),
                     m.group(1), m.group(2)))
    return fdes


def containing(fdes, va):
    for s, e, off, cie in fdes:
        if s <= va < e:
            return (hex(s), hex(e))
    return (None, None)


def main():
    data = open(BIN, "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        print("binary digest mismatch")
        return 1
    sys.path.insert(0, HERE)
    import census as census_mod
    calls, tails, hits, slots = census_mod.scan(BIN)
    fdes = fde_table()

    windows = {}
    for name, (start, end) in WINDOWS.items():
        s, e = int(start, 16), int(end, 16)
        match = [f for f in fdes if f[0] == s and f[1] == e]
        if not match:
            print("no FDE for", name)
            return 1
        off, cie = match[0][2], match[0][3]
        first_bytes = data[s - 0x1000: s - 0x1000 + 4].hex()
        windows[name] = {
            "start": start, "end": end, "size_bytes": e - s,
            "fde_offset": "0x" + off, "cie_offset": "0x" + cie,
            "first_instruction_bytes": first_bytes,
        }

    census = {}
    for t in census_mod.TARGETS:
        census[hex(t)] = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }

    callers = {}
    for t in census_mod.TARGETS:
        rows = []
        for site in calls[t]:
            fs, fe = containing(fdes, site)
            role = CALLER_ROLES.get(site)
            if role is None:
                role = "consumer in FDE %s (exact use open)" % fs
            rows.append({
                "site": hex(site), "kind": "direct_call",
                "containing_fde": [fs, fe],
                "role": role,
            })
        for site in tails[t]:
            fs, fe = containing(fdes, site)
            role = CALLER_ROLES.get(site)
            if role is None:
                role = "consumer in FDE %s (exact use open)" % fs
            rows.append({
                "site": hex(site), "kind": "tail_jump",
                "containing_fde": [fs, fe],
                "role": role,
            })
        callers[hex(t)] = rows

    internal_sites = {}
    for t_hex, sites in PACKET_INTERNAL_SITES.items():
        rows = []
        for site, role in sites:
            fs, fe = containing(fdes, site)
            rows.append({
                "site": hex(site), "kind": "direct_call",
                "containing_fde": [fs, fe],
                "role": role,
            })
        internal_sites[t_hex] = rows

    records = {
        "artifact": "work/hl-node-115.bin",
        "artifact_sha256": DIGEST,
        "provenance_path": "artifacts/node/115/hl-node",
        "task": "RE-001",
        "vendor_attribution": {
            "host": {
                "catalogue_id": "node115-vendor-5f0a9c0",
                "label": "librocksdb-sys 0.11.0+8.1.1: "
                         "_ZN7rocksdb8MemTable33NewRangeTombstoneIteratorInternalERKNS_11ReadOptionsEmb",
                "raw_equal_bytes": "1536/1676",
                "non_relocation_bytes_equal": "1505/1676",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "ctor_a": {
                "catalogue_id": "node115-vendor-5f31380",
                "label": "librocksdb-sys 0.11.0+8.1.1: "
                         "_ZN7rocksdb32FragmentedRangeTombstoneIteratorC1EPNS_28FragmentedRangeTombstoneListERKNS_21InternalKeyComparatorEmPKNS_5SliceEm",
                "raw_equal_bytes": "232/239",
                "non_relocation_bytes_equal": "230/239",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "ctor_b": {
                "catalogue_id": "node115-vendor-5f315a0",
                "label": "librocksdb-sys 0.11.0+8.1.1: "
                         "_ZN7rocksdb32FragmentedRangeTombstoneIteratorC1ERKSt10shared_ptrINS_33FragmentedRangeTombstoneListCacheEERKNS_21InternalKeyComparatorEmPKNS_5SliceEm",
                "raw_equal_bytes": "292/302",
                "non_relocation_bytes_equal": "289/302",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "picker": {
                "catalogue_id": "node115-vendor-60d5cd0",
                "label": "librocksdb-sys 0.11.0+8.1.1: "
                         "_ZN7rocksdb4port14PhysicalCoreIDEv",
                "raw_equal_bytes": "32/32",
                "non_relocation_bytes_equal": "32/32",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "cleanable_dtor": {
                "catalogue_id": "node115-vendor-61bd0e0",
                "label": "librocksdb-sys 0.11.0+8.1.1: one of 2 identical "
                         "copies of 2 build functions, e.g. "
                         "_ZN7rocksdb9Cleanable9DoCleanupEv",
                "raw_equal_bytes": "78/81",
                "non_relocation_bytes_equal": "77/81",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "release": {
                "catalogue_id": "node115-vendor-5d350c0",
                "label": "librocksdb-sys 0.11.0+8.1.1: "
                         "_ZNSt16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv",
                "raw_equal_bytes": "126/133",
                "non_relocation_bytes_equal": "125/133",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "shard": {
                "catalogue_id": None,
                "label": "0x40-stride shard-pointer helper (no catalogue "
                         "row pins this address; identified by shape: the "
                         "picker/seed mask, the 0x40 stride, the TLS record)",
                "non_relocation_bytes_equal": None,
                "evidence": "this packet's excerpts",
            },
            "cache_ctor": {
                "catalogue_id": None,
                "label": "FragmentedRangeTombstoneListCache constructor "
                         "(no catalogue row pins this address; identified "
                         "by shape: the 0xe8 zero-init, the list iteration "
                         "via vtable slots, the +0xd8 count / +0xe0 total)",
                "non_relocation_bytes_equal": None,
                "evidence": "this packet's excerpts",
            },
            "seed": {
                "catalogue_id": None,
                "label": "per-thread hash seed (no catalogue row pins "
                         "this address; re-derived fresh here, same routine "
                         "as open PR #3613)",
                "non_relocation_bytes_equal": None,
                "evidence": "this packet's excerpts",
            },
            "cleanable_ctor": {
                "catalogue_id": None,
                "label": "Cleanable default constructor (no catalogue row "
                         "pins this address; identified by shape: zeroes "
                         "+0x0 and +0x18, the pair its DoCleanup reads)",
                "non_relocation_bytes_equal": None,
                "evidence": "this packet's excerpts",
            },
            "list_release": {
                "catalogue_id": None,
                "label": "recursive 0x28-byte node-tree release (no "
                         "catalogue row pins this address; identified by "
                         "shape: the +0x18 self-recursion, the 0x28-byte "
                         "node frees)",
                "non_relocation_bytes_equal": None,
                "evidence": "this packet's excerpts",
            },
        },
        "host": {
            "name": "rocksdb::MemTable::NewRangeTombstoneIteratorInternal",
            "arguments": ["rdi = owner (MemTable)",
                          "rsi = arg2 (a struct; the flag path reads a "
                          "Slice at arg2+0x58)",
                          "rdx = arg3 (passed as the seq-like argument to "
                          "both ctors)",
                          "cl = flag byte (bool)"],
            "returns": "a 0xc8-byte FragmentedRangeTombstoneIterator "
                       "(operator new, never null in the observed paths)",
            "catalogue_name_note": "the catalogue name lists "
                                   "(const ReadOptions&, bool); the live "
                                   "rdx argument is an observed difference "
                                   "from that name (open)",
            "flag_path": "cl != 0: operator new(0xc8), ctor A 0x5f31380 "
                         "with (list = owner+0xce0, comparator = owner+8, "
                         "arg4 = rdx, slice = arg2+0x58, arg6 = 0); the "
                         "slot is never touched; return the iterator",
            "shard_pick": "source = picker 0x60d5cd0; when it returns -1, "
                          "the per-thread seed 0x61c4080 is advanced once "
                          "(*0x41a7 mod 0x7fffffff, Mersenne fold) and the "
                          "advanced value is used; idx = source & "
                          "((1 << shift) - 1) with shift = owner+0xd18 "
                          "(dword); slot = owner+0xd10 + idx*0x10",
            "claim": "_Sp_locker over the slot, then a 16-byte copy of "
                     "the slot's shared_ptr {ptr, ctrl}; when ctrl != 0 "
                     "its use count at +0x8 is bumped (lock addl iff the "
                     "global byte at 0x64ed290 is 0, else plain addl)",
            "ready_path": "slot-object flag byte +0x30 != 0: build the "
                          "iterator via ctor B 0x5f315a0 from the stack "
                          "copy, release the claim-time reference via "
                          "_M_release 0x5d350c0, return",
            "mutex_path": "flag clear: pthread_mutex_lock(slot object); "
                          "when slot-object +0x28 (cache) != 0, unlock and "
                          "take the ready path; when it is 0, build",
            "build": ["operator new(0x80) for the list; Cleanable ctor "
                      "0x61bd0c0 at list+0x8; fill list fields (see "
                      "list_fields below)",
                      "operator new(0xe8) for the cache; cache ctor "
                      "0x5f37410(cache, &list, owner+8, 0, scratch)",
                      "old = slot-object +0x28; install the new cache "
                      "there; when old != 0 tear it down (see teardown)",
                      "destroy the temporary list via its vtable slot 1",
                      "set the ready flag byte +0x30 = 1, unlock the "
                      "mutex, build the iterator via ctor B from the "
                      "stack copy, release the claim-time reference, "
                      "return"],
            "list_fields": {"+0x00": "vtable 0x64cc638+0x10",
                            "+0x08": "Cleanable (ctor 0x61bd0c0: head +0x8 "
                                     "= 0, link +0x20 = 0)",
                            "+0x28": "0",
                            "+0x30": "owner+0xc58 (a pointer)",
                            "+0x38": "vtable-valued 0x64cc600+0x10",
                            "+0x40": "vtable-valued 0x64c8fe8+0x10",
                            "+0x48": "owner+0x10",
                            "+0x50": "(owner+0xa58)->vtable slot 0x90()",
                            "+0x58": "0 (u16)",
                            "+0x5a": "owner+0x31 ^ 1 (byte)",
                            "+0x60": "owner+0x6c",
                            "+0x68": "0", "+0x6c": "0 (u16)",
                            "+0x70": "0",
                            "+0x78": "owner+0x60"},
            "teardown": ["when the old cache's +0xb8 flag is set: the "
                         "+0xc0 array fixup (memmove 0x5f053d0, memcpy "
                         "0x5f05120, insertion-sort dedup, per-entry "
                         "dtors via *0x8, the +0x98 cleanup chain run, "
                         "+0x98/+0xb0 zeroed)",
                         "operator delete[] of the +0xc0 array "
                         "(size = +0xd0 - +0xc0) when its begin != 0",
                         "DoCleanup(old+0x98) via 0x61bd0e0",
                         "walk the +0x80 list (0x30-byte nodes): free "
                         "each node's +0x10 buffer (size +0x20 + 1) "
                         "unless it equals &node+0x20, then delete the "
                         "node (0x30 bytes)",
                         "walk the +0x60 list (0x28-byte nodes): release "
                         "each node+0x18 via 0x5f059b0, then delete the "
                         "node (0x28 bytes)",
                         "free the +0x30 buffer (size +0x40 - +0x30), "
                         "the +0x18 buffer (size +0x28 - +0x18) and the "
                         "+0x0 buffer (size +0x10 - +0x0), each when "
                         "non-null",
                         "operator delete(old, 0xe8)"],
            "teardown_note": "the old-cache teardown is defensive in "
                             "this flow: the mutex is held from the null "
                             "check at +0x28 through the install, so old "
                             "is null in the single-threaded flow; the "
                             "branch exists for a cache swap by another "
                             "path (open)",
            "slot_object": "the shared_ptr's object: a pthread_mutex_t "
                           "at +0x0 (0x28 bytes), the cache pointer at "
                           "+0x28, the ready flag byte at +0x30",
            "error_paths": "stack-canary failure -> __stack_chk_fail; "
                          "pthread_mutex_lock failure -> "
                          "__throw_system_error (not modelled)",
            "landing_pads": "the five endbr64 stubs at 0x5f0b004.."
                            "0x5f0b048 each save %rax to %rbx and jump to "
                            "0x5f0a90a/0x5f0a93e/0x5f0a960/0x5f0a989/"
                            "0x5f0a9ad in FDE 0x5f0a90a..0x5f0a9bf (the "
                            "preceding function, a shared rethrow block); "
                            "not decoded",
            "caller": "the merged RE-014 batch-lookup function 0x5f0d740 "
                      "calls the host at 0x5f0e061 with (owner, arg2, "
                      "seq>>8, flag), applies 0x5f32900 to the returned "
                      "iterator and destroys it via vtable slot 0x8; the "
                      "merged RE-014 probe thunk 0x5f0b050 tail-jumps to "
                      "the host at 0x5f0b068",
        },
        "shard": {
            "name": "0x40-stride shard-pointer helper",
            "arguments": ["rdi = owner"],
            "fields": "shift = owner+0x50 (dword), table = owner+0x48",
            "steps": ["source = picker 0x60d5cd0; when -1, the per-thread "
                      "seed 0x61c4080 is advanced once (same fold) and "
                      "the advanced value is used",
                      "idx = source & ((1 << shift) - 1); "
                      "slot = table + idx*0x40",
                      "record = idx | (1 << shift) (bts); "
                      "TLS[fs:0 - 0x408] = record; return the slot"],
            "callers": "the merged allocate windows 0x5f117a0 (site "
                       "0x5f11931) and 0x5f11c40 (site 0x5f11cf7); the "
                       "merged allocate packets model it by contract "
                       "only (tools/shard_allocate_115.py refresh_shard) "
                       "- this packet pins its internals",
            "relation": "the same picker/seed mask as the host, but a "
                        "different table (owner+0x48/+0x50) and a 0x40 "
                        "stride instead of the host's 0x10 shared_ptr "
                        "slots",
        },
        "picker": {
            "name": "rocksdb::port::PhysicalCoreID (catalogue)",
            "arguments": [],
            "rule": "cpuid leaf 0 gives the max leaf in eax; when it is "
                    "0 return -1; otherwise cpuid leaf 1 and return "
                    "EBX >> 24 (the maximum number of addressable "
                    "logical-processor IDs)",
            "callers": "6 direct call sites: the host, the shard helper, "
                       "the StatisticsImpl ticker/histogram slots (open "
                       "PR #3613) and the ZSTD decompress slot claim "
                       "(open PR #3635)",
        },
        "seed": {
            "name": "per-thread hash seed",
            "arguments": [],
            "rule": "first use: _Hash_bytes(&pthread_self, 8, "
                    "0xc70f6907) & 0x7fffffff, or 1 when that is 0, "
                    "cached per thread (pointer at thread-0x10); later "
                    "uses return the cached value; callers advance the "
                    "cached value in place by *0x41a7 mod 0x7fffffff "
                    "(Mersenne fold: (x & 0x7fffffff) + (x >> 31), minus "
                    "0x7fffffff once when negative as signed 32-bit; a "
                    "true 0 stays 0x7fffffff)",
            "callers": "17 direct call sites (see callers.tsv)",
        },
        "ctor_a": {
            "name": "rocksdb::FragmentedRangeTombstoneIterator::"
                    "FragmentedRangeTombstoneIterator(list, comparator, "
                    "seq, slice, arg6) (catalogue)",
            "arguments": ["rdi = this (0xc8)", "rsi = list",
                          "rdx = comparator", "rcx = seq (arg4)",
                          "r8 = slice (arg5)", "r9 = arg6"],
            "fields": {"+0x00": "vtable 0x64ccae0+0x10",
                       "+0x08": "comparator subobject (ctor 0x61bd0c0)",
                       "+0x28": "comparator+0x8", "+0x30": "comparator+0x8",
                       "+0x38": "comparator", "+0x40": "comparator+0x8",
                       "+0x48..+0x68": "0 (the shared_ptr at +0x58 is null)",
                       "+0x68": "list", "+0x70": "seq", "+0x78": "arg6",
                       "+0x80": "slice",
                       "+0x88": "list+0x8", "+0x90": "list+0x18",
                       "+0x98": "list+0x8", "+0xa0": "list+0x18",
                       "+0xa8": "&this+0xb8", "+0xb0": "0",
                       "+0xb8": "0 (byte)"},
        },
        "ctor_b": {
            "name": "rocksdb::FragmentedRangeTombstoneIterator::"
                    "FragmentedRangeTombstoneIterator(shared_ptr<Cache>, "
                    "comparator, seq, slice, arg6) (catalogue)",
            "arguments": ["rdi = this (0xc8)", "rsi = shared_ptr<Cache>",
                          "rdx = comparator", "rcx = seq (arg4)",
                          "r8 = slice (arg5)", "r9 = arg6"],
            "fields": {"+0x00": "vtable 0x64ccae0+0x10",
                       "+0x08": "comparator subobject (ctor 0x61bd0c0)",
                       "+0x28": "comparator+0x8", "+0x30": "comparator+0x8",
                       "+0x38": "comparator", "+0x40": "comparator+0x8",
                       "+0x48..+0x58": "0",
                       "+0x58": "the 16-byte shared_ptr copy (ptr, ctrl); "
                                "when ctrl != 0 its use count at +0x8 is "
                                "bumped (lock addl iff the global byte at "
                                "0x64ed290 is 0, else plain addl)",
                       "+0x68": "shared_ptr object +0x28 (the cache)",
                       "+0x70": "seq", "+0x78": "arg6",
                       "+0x80": "slice (an empty slice, non-null with "
                                "+0x8 == 0, is treated as null)",
                       "+0x88": "cache+0x8", "+0x90": "cache+0x20",
                       "+0x98": "cache+0x8", "+0xa0": "cache+0x20",
                       "+0xa8": "&this+0xb8", "+0xb0": "0",
                       "+0xb8": "0 (byte)"},
            "note": "ctor A reads the raw list's +0x8/+0x18 as the bounds "
                    "pair; ctor B reads the cache's +0x8/+0x20. The two "
                    "layouts differ because the cache is a different "
                    "struct from the raw list; the iterator distinguishes "
                    "them by the null/non-null shared_ptr at +0x58",
        },
        "cache_ctor": {
            "name": "FragmentedRangeTombstoneListCache constructor (by shape)",
            "arguments": ["rdi = cache (0xe8, operator new)",
                          "rsi = &list (pointer to the 0x80 list*)",
                          "rdx = owner+8", "ecx = arg4 (0 in the host)",
                          "r8 = a 0x20-byte stack scratch at 0x30(%rsp) "
                          "(zeroed by the host; the finalize fills it as "
                          "a heap range, freed by the host after the "
                          "install; exact type open)"],
            "zero_init": {"+0x00..+0x10": "0", "+0x10..+0x40": "0",
                          "+0x40": "0 (qword)", "+0x48": "0 (dword)",
                          "+0x58": "0 (dword)", "+0x60": "0",
                          "+0x68/+0x70": "&cache+0x58",
                          "+0x78": "0",
                          "+0x80..+0x90": "(cache+0x80, cache+0x80)",
                          "+0x90": "0",
                          "+0x98": "Cleanable (ctor 0x61bd0c0)",
                          "+0xb8": "0 (byte)", "+0xc0..+0xd0": "0",
                          "+0xd8..+0xe8": "0"},
            "iteration": "when *list == 0, the null-list path finalizes "
                         "at once (0x5f37aa8); otherwise a stack iterator "
                         "(vtable 0x64cca10+0x10, Cleanable at its +0x8) "
                         "walks the list via vtable slots 0x10 (Valid), "
                         "0x18 (Next), 0x50 (key), 0x60 (size), 0x38 and "
                         "0x90, counting entries at cache+0xd8 and summing "
                         "sizes at cache+0xe0; a perf-level gate (TLS "
                         "perf_level via _ZTHN7rocksdb10perf_levelE, "
                         "counter at 0x64ed2b0) guards the counting path; "
                         "the loop at 0x5f37900 builds the sorted index "
                         "vector (begin +0xc0, end +0xc8, capacity +0xd0 "
                         "per the teardown's vector triple)",
            "finalize": "0x5f36c70(cache, 0x18(%rsp), owner+8, arg4 byte, "
                        "scratch) at 0x5f3799f (main path) and 0x5f37ad1 "
                        "(null-list path)",
            "callers": "4 direct call sites: the host plus the sibling "
                       "cache builder in FDE 0x5f0a3d0 and two other cache "
                       "consumers (FDEs 0x5f29140, 0x6109c40)",
        },
        "cleanable_ctor": {
            "name": "Cleanable default constructor (by shape)",
            "arguments": ["rdi = Cleanable subobject"],
            "steps": ["zero +0x0 (the cleanup head)", "zero +0x18 "
                      "(the chain link)"],
        },
        "cleanable_dtor": {
            "name": "rocksdb::Cleanable::DoCleanup (catalogue, one of 2 "
                    "identical copies)",
            "arguments": ["rdi = Cleanable subobject"],
            "steps": ["when the head is null, return at once",
                      "call the head's fn(head+0x8, head+0x10)",
                      "walk the +0x18 chain: call each node's "
                      "fn(node+0x8, node+0x10) and delete the 0x20-byte "
                      "node"],
        },
        "release": {
            "name": "std::_Sp_counted_base::_M_release (catalogue)",
            "arguments": ["rdi = counted base"],
            "steps": ["the +0x8 qword holds (use, weak) as two dwords; "
                      "when it equals 0x100000001 (use 1, weak 1) dispose "
                      "at once (vtable slot 0x10, then destroy via slot "
                      "0x18)",
                      "otherwise decrement the use count (lock xadd iff "
                      "the global byte at 0x64ed290 is 0, else plain dec) "
                      "and dispose iff the old count was 1",
                      "the dispose path jumps to the shared stub FDE "
                      "0x5d35070..0x5d350bc (not decoded)"],
            "atomicity": "the global byte at 0x64ed290 selects locked vs "
                         "plain RMW in the host, ctor B and _M_release "
                         "alike (0 -> locked, nonzero -> plain); its "
                         "symbolic identity is open",
        },
        "list_release": {
            "name": "recursive 0x28-byte node-tree release (by shape)",
            "arguments": ["rdi = node (null returns at once)"],
            "steps": ["release the +0x18 child subtree first "
                      "(self-recursion at 0x5f05a41)",
                      "free the node itself (0x28 bytes)",
                      "release the +0x10 sibling",
                      "every node in the +0x18/+0x10 tree is freed exactly "
                      "once; the unrolled descent interleaves the levels "
                      "(exact interleave open)"],
            "callers": "6 direct call sites, including the host teardown "
                       "(0x5f0acc4) and the sibling cache builder "
                       "(0x5f0a610)",
        },
        "callers": callers,
        "census": census,
        "packet_internal_sites": internal_sites,
        "generic_helper_counts": GENERIC_HELPER_COUNTS,
        "windows": windows,
        "unknowns": [
            "the host's live rdx argument vs the catalogue name's "
            "(const ReadOptions&, bool) (see host.catalogue_name_note)",
            "the 0x80 list's +0x30/+0x38/+0x40 vtable-valued slots' "
            "subobject identities",
            "the owner (MemTable) fields the list build copies (+0x10, "
            "+0x31, +0x60, +0x6c, +0xa58, +0xc58, +0xce0) beyond the "
            "shard table at +0xd10/+0xd18",
            "which store in the cache ctor's iteration/finalize populates "
            "cache+0x8/+0x20 (the bound pair ctor B copies)",
            "the cache ctor's sorted-index entry layout and the 0x5f36c70 "
            "finalize contract (0x5f36c70 itself is not a window)",
            "the 0x5f32900 contract (applied by the caller to the "
            "returned iterator; 4 call sites, not a window)",
            "the TLS record at fs:0-0x408 written by the shard helper "
            "(idx | (1 << shift)): its consumer is open",
            "the global byte at 0x64ed290 (the atomicity selector): its "
            "symbolic identity is open",
            "the cache ctor's 5th argument (r8): a 0x20-byte stack scratch "
            "the finalize fills as a heap range; its exact type is open",
            "the host's landing-pad stubs (FDE 0x5f0a90a) and _M_release's "
            "dispose stub (FDE 0x5d35070) are shared rethrow/dispose "
            "blocks, not decoded; the LSDA call-site tables are not "
            "decoded",
            "the old-cache teardown branch is defensive in the host flow "
            "(see host.teardown_note)",
            "the sibling cache builder in FDE 0x5f0a3d0 (which also calls "
            "the cache ctor, the list release and the memmove/memcpy "
            "helpers) is not identified",
            "the 0x5f053d0 (memmove) and 0x5f05120 (memcpy) helpers' exact "
            "contracts (census targets only, not windows)",
        ],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    # callers.tsv: one row per census site.
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("target\tsite\tkind\tcontaining_fde_start\tcontaining_fde_end\trole\n")
        for t in census_mod.TARGETS:
            for row in callers[hex(t)]:
                fs, fe = row["containing_fde"]
                fh.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (
                    hex(t), row["site"], row["kind"], fs, fe, row["role"]))
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write("No R_X86_64_RELATIVE entry in .rela.dyn has an addend "
                 "equal to any packet window start.\n")
        fh.write("The iterator vtable 0x64ccae0+0x10, the list vtables "
                 "0x64cc638+0x10 / 0x64cc600+0x10 / 0x64c8fe8+0x10 and the "
                 "cache-ctor stack-iterator vtable 0x64cca10+0x10 are "
                 "RIP-relative leas in the excerpts (no relocation).\n")
        fh.write("The atomicity selector 0x64ed290 is read by a "
                 "RIP-relative mov in the host, ctor B and release "
                 "excerpts (no relocation).\n")
        fh.write("The shard helper's TLS record at fs:0-0x408 and the "
                 "seed's per-thread slot at thread-0x10 are "
                 "thread-pointer-relative (no relocation).\n")
    # MANIFEST.sha256: every packet file except itself and __pycache__.
    manifest = {}
    for name in sorted(os.listdir(HERE)):
        if name == "MANIFEST.sha256" or name == "__pycache__":
            continue
        path = os.path.join(HERE, name)
        if os.path.isfile(path):
            manifest[name] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    with open(os.path.join(HERE, "MANIFEST.sha256"), "w") as fh:
        for name in sorted(manifest):
            fh.write("%s  %s\n" % (manifest[name], name))
    print("wrote records.json, callers.tsv, relocations.txt, MANIFEST.sha256")
    return 0


if __name__ == "__main__":
    sys.exit(main())
