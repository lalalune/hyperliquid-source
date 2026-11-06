"""Generate records.json for RE-001-zstd-decompress-cache-115.

Run from the repository root:
    python3 research/work-items/RE-001-zstd-decompress-cache-115/gen_records.py

Derives the windows (FDE ranges from objdump --dwarf=frames), the
caller census (from census.py's binary scan) and the per-window sample
bytes (from the raw binary) directly from the digest-verified binary.
The semantic constants (layout, rules, roles) are the packet author's
readings of the verbatim excerpts, recorded here so the checker can
re-derive them; the model in tools/ implements the same rules and its
tests exercise them end to end.
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
    "claim": ("0x61c1e10", "0x61c1f0f"),
    "claim_landing": ("0x61c1dec", "0x61c1e0a"),
    "create_dctx": ("0x628c0b0", "0x628c1d6"),
    "table_ctor": ("0x61c1f30", "0x61c20b6"),
    "static_init": ("0x61c20d0", "0x61c2109"),
    "getter": ("0x61c2120", "0x61c21a6"),
    "teardown": ("0x61c1d60", "0x61c1dec"),
    "factory": ("0x61c1ce0", "0x61c1d5a"),
    "picker": ("0x60d5cd0", "0x60d5cf0"),
    "seed": ("0x61c4080", "0x61c4117"),
}

# Caller roles, read from objdump around each census site. The FDE is
# the containing function; no symbol names exist in the stripped binary.
CALLER_ROLES = {
    0x5DB1951: "static-holder init: calls the getter, claims, stores the pair to stack slots",
    0x60EA81A: "holder refill/swap: calls the getter, claims, stores the pair into the struct at r15+0x8/+0x10",
    0x60FE79E: "holder ctor: zeroes the holder, claims only for kind 7 or 0x40, stores the pair at holder+0x8/+0x10",
    0x6158C11: "large decompress-path function: calls the getter, claims, stores the pair to stack slots",
    0x615A98F: "large decompress-path function: calls the getter, claims, stores the pair; also frees a held DCtx via 0x628c1e0 at 0x615a929",
    0x5F01E9D: "holder init: installs the factory product at +0x78 beside a 0x8000-byte array at +0x80",
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
            rows.append({
                "site": hex(site), "kind": "direct_call",
                "containing_fde": [fs, fe],
                "role": CALLER_ROLES.get(site, ""),
            })
        for site in tails[t]:
            fs, fe = containing(fdes, site)
            rows.append({
                "site": hex(site), "kind": "tail_jump",
                "containing_fde": [fs, fe],
                "role": CALLER_ROLES.get(site, ""),
            })
        callers[hex(t)] = rows

    records = {
        "artifact": "work/hl-node-115.bin",
        "artifact_sha256": DIGEST,
        "provenance_path": "artifacts/node/115/hl-node",
        "task": "RE-001",
        "vendor_attribution": {
            "claim": {
                "catalogue_id": "node115-vendor-61c1e10",
                "label": "librocksdb-sys 0.11.0+8.1.1: "
                         "_ZN7rocksdb23CompressionContextCache27"
                         "GetCachedZSTDUncompressDataEv",
                "non_relocation_bytes_equal": "235/235",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
            "create_dctx": {
                "catalogue_id": "node115-vendor-628c0b0",
                "label": "zstd-sys 2.0.15+zstd.1.5.7/2.1.2+zstd.1.5.7: "
                         "one of 2 identical bodies, e.g. ZSTD_createDCtx",
                "non_relocation_bytes_equal": "290/290",
                "evidence": "research/work-items/RE-002-node115-vendor-census/census.json",
            },
        },
        "table": {
            "struct_bytes": 16,
            "fields": {"entries": "T+0x0", "shift": "T+0x8 (dword)"},
            "array_layout": "[count:8 bytes][entries: count * 64 bytes], "
                            "count stored at entries-8",
            "size_rule": "ncpu <= 8: shift 3, count 8, alloc 0x208; else "
                         "smallest e >= 4 with (1 << e) >= ncpu, "
                         "alloc = count * 64 + 8; count >> 57 nonzero "
                         "makes the new[] size -1 (throws)",
            "entry_layout": {"obj": "+0x0, null until claimed",
                             "marker": "+0x8, -1 while the slot owns its object",
                             "claim": "+0x10, the entry address itself while "
                                      "unclaimed, 0 once claimed"},
            "static_slot": "0x6508900 (table pointer), guard byte 0x65088f8",
        },
        "claim": {
            "name": "rocksdb::CompressionContextCache::GetCachedZSTDUncompressData",
            "arguments": ["rdi = out pair (16 bytes: +0x0 object, +0x8 index)",
                          "rsi = pointer to the static table slot (T**)"],
            "out_init": "(None, -1)",
            "index": "cpu = picker 0x60d5cd0(); cpu >= 0: index = cpu & "
                     "((1 << shift) - 1); else seed = advance(seed) once "
                     "(*0x41a7 mod 0x7fffffff) and index = seed & mask",
            "entry": "base + index * 64",
            "claim_step": "lock cmpxchg(entry+0x10, expect=entry, new=0); "
                          "success wins the shared slot, failure takes the "
                          "private-fallback path",
            "shared_path": "entry.obj null: entry.obj = createDCtx(), "
                           "marker stays -1; out = (entry.obj, index)",
            "shared_path_existing": "entry.obj already set: out = "
                                    "(entry.obj, index), no create call",
            "contention_path": "out.obj still null (fresh out): "
                               "out = (createDCtx(), -1); the fresh object "
                               "never enters the slot",
            "landing_pad": "0x61c1dec: on unwind, if out.obj != 0 and "
                           "out.index == -1, freeDCtx(out.obj), then resume",
        },
        "create_dctx": {
            "name": "ZSTD_createDCtx (catalogue: one of 2 identical bodies)",
            "arguments": [],
            "alloc": "malloc(0x176f8); null returns null",
            "init": {"0x75c0": 0, "0x75d8": 0, "0x74d8": 0, "0x75fc": 0,
                     "0x7620": 0, "0x7628": 0, "0x7648": 0, "0x761c": 0,
                     "0x7668": 0, "0x7670": 0, "0x767c": 0, "0x176e8": 0,
                     "0x75e0": 1, "0x75b0": 0, "0x75e8": 0, "0x7608": 0,
                     "0x7638": "0x8000001", "0x7680": 0, "0x7598": 0,
                     "0x7610": 0, "0x7614": 0},
            "feature_probe": "+0x75e4 = 0 when cpuid max leaf <= 6; else 1 "
                             "iff leaf-7 EBX has both bits 3 and 8 set "
                             "(BMI1 + BMI2), else 0",
        },
        "free_dctx": {
            "name": "ZSTD_freeDCtx (by contract)",
            "note": "null returns immediately; releases the context's "
                    "internal buffers (fields +0x75d8/+0x75b8/+0x75c0 are "
                    "read first). Called by the teardown, the table-ctor "
                    "old-release path, the claim landing pad, and 19 holder "
                    "release sites.",
        },
        "teardown": {
            "entry": "registered via __cxa_atexit in the getter; takes T**",
            "steps": ["if T null: return",
                      "if entries null: delete(T, 0x10) only",
                      "walk entries last-to-first; free each object whose "
                      "marker == -1 via 0x628c1e0",
                      "delete[](entries - 8, count * 64 + 8)",
                      "delete(T, 0x10)"],
        },
        "factory": {
            "name": "kind-7 holder factory",
            "arguments": ["dil = kind byte", "esi -> +0xc", "rdx -> +0x10"],
            "gate": "kind != 7 returns null",
            "product": {"size": "0x38", "vtable": "0x64d7438 + 0x10 at +0x0",
                        "kind_byte": "7 at +0x8", "field_c": "+0xc",
                        "field_10": "+0x10", "dctx": "+0x18, fresh createDCtx()",
                        "field_20": "0", "field_28": "0 (16 bytes)"},
            "landing_pad": "0x61c1d4e: on unwind, delete(0x38) and resume",
            "caller": "0x5f01e9d installs the product at holder+0x78 beside "
                      "a 0x8000-byte array at +0x80",
        },
        "getter": {
            "returns": "address of the static slot (T**), 0x6508900",
            "steps": ["guard byte 0x65088f8 set: return &static",
                      "else __cxa_guard_acquire; static_init 0x61c20d0(&static)",
                      "__cxa_atexit(teardown 0x61c1d60, &static, __dso_handle)",
                      "__cxa_guard_release; return &static"],
        },
        "static_init": {
            "steps": ["operator new(0x10) for the table struct",
                      "table_ctor 0x61c1f30(T)",
                      "store T into the static slot"],
            "landing_pad": "on unwind, __cxa_guard_abort and resume",
        },
        "pickers": {
            "picker_0x60d5cd0": "cpuid leaf 0; -1 when no leaf 1 exists, "
                               "else leaf-1 EBX >> 24",
            "seed_0x61c4080": "per-thread cell at fs:0-0x20, pointer cached "
                             "at fs:0-0x10; _Hash_bytes(&pthread_self, 8, "
                             "0xc70f6907) & 0x7fffffff, or 1 when 0; returns "
                             "a pointer to the seed cell",
            "seed_step": "seed = seed * 0x41a7 folded mod 0x7fffffff "
                         "(same step as open PR #3613); a true 0 reads back "
                         "as 0x7fffffff",
        },
        "callers": callers,
        "census": census,
        "windows": windows,
        "unknowns": [
            "the RocksDB-level identities of the five claim-caller functions "
            "(FDEs only; the binary is stripped)",
            "whether a private-fallback DCtx is always freed by its holder "
            "or can leak on a holder error path (one explicit free site, "
            "0x615a929, was examined)",
            "the 0x70-byte kind-7 sibling factory 0x61c1c10 (calls 0x6218920 "
            "and 0x6212010) is not modelled here",
            "the twin identical body of 0x628c0b0 named by the catalogue "
            "(createCCtx candidate): its address is not pinned here",
            "the 16-byte shared_ptr-slot table in 0x5f0a9c0 is a different "
            "per-CPU table and a separate work item",
            "the LSDA call-site tables for the landing pads (not decoded)",
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
        fh.write("The factory vtable 0x64d7438 is referenced by a "
                 "RIP-relative lea in the factory excerpt (no relocation).\n")
        fh.write("The static slot 0x6508900 and guard 0x65088f8 live in "
                 ".bss (no file qword, no relocation).\n")
    print("wrote records.json, callers.tsv, relocations.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
