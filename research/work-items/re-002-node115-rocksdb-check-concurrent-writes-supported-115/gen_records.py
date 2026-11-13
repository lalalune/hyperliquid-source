#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

The body hash is recomputed from work/hl-node-115.bin over the FDE
range. The single FDE is vendor-census-bound (member
25dac13516458d4d-column_family.o, librocksdb-sys 0.11.0+8.1.1);
its source hash reproduces exactly by zeroing the census
relocations (6, kinds 2/4, no relaxation). The FDE has no .cold
FDE and no LSDA (aug_len 0).
"""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# (start, end, name, slug, census-bound?)
FUNCS = [
    ("0x5d8ba60", "0x5d8bb48",
     "rocksdb::CheckConcurrentWritesSupported",
     "check-concurrent-writes-supported-5d8ba60", True),
]


def va2off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BIN)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def _caller_sites():
    sites = []
    with open(PACKET / "callers.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            row = dict(zip(header, line.rstrip("\n").split("\t")))
            sites.append({
                "instruction": row["instruction"],
                "kind": row["kind"], "site": row["site"],
                "site_fde_end": row["site_fde_end"],
                "site_fde_start": row["site_fde_start"],
                "target": row["target"],
                "target_name": row["target_name"]})
    return sites


def main():
    data = open(BIN, "rb").read()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    census = json.load(open(
        ROOT / "research" / "work-items" / "RE-002-node115-vendor-census"
        / "census.json"))["records"]
    by_start = {r["start"]: r for r in census}
    rows = []
    functions = {}
    for start_s, end_s, name, slug, census_bound in FUNCS:
        start, end = int(start_s, 16), int(end_s, 16)
        body = data[va2off(start):va2off(end)]
        body_hash = hashlib.sha256(body).hexdigest()
        assert census_bound
        rec = by_start[start]
        assert body_hash == rec["target_body_sha256"], name
        zeroed = bytearray(body)
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
        source_hash = hashlib.sha256(bytes(zeroed)).hexdigest()
        assert source_hash == rec["source_body_sha256"], name
        relocs = ";".join(
            "%d:kind%d" % (r["offset"], r["kind"])
            for r in rec["relocations"])
        symbol = rec["symbol"]
        raw_equal = str(rec["raw_equal"])
        row = {
            "name": name, "start": start_s, "end": end_s,
            "size": str(end - start), "body_sha256": body_hash,
            "source_sha256": source_hash,
            "raw_equal": raw_equal,
            "relocations": relocs,
            "census_id": "node115-vendor-%s" % start_s[2:],
            "symbol": symbol,
            "excerpt": slug + ".objdump.txt", "hex": slug + ".hex",
        }
        functions[start_s] = {
            "body_sha256": body_hash,
            "source_sha256": source_hash,
            "relocations": relocs,
            "census_id": row["census_id"],
            "mangled": symbol,
            "callers": [],
            "lea_refs": [],
        }
        rows.append(row)
    with open(PACKET / "functions.tsv", "w") as fh:
        cols = ["name", "start", "end", "size", "body_sha256",
                "source_sha256", "raw_equal", "relocations", "census_id",
                "symbol", "excerpt", "hex"]
        fh.write("\t".join(cols) + "\n")
        for r in rows:
            fh.write("\t".join(r[c] for c in cols) + "\n")
    print("wrote functions.tsv (%d functions, all hashes verified)"
          % len(rows))

    # Caller census sites, read back from callers.tsv (no hand copy).
    sites = _caller_sites()
    main_calls = [s for s in sites if s["target"] == "0x5d8ba60"]
    functions["0x5d8ba60"]["callers"] = [s["site"] for s in main_calls]
    functions["0x5d8ba60"]["model"] = (
        "232-byte helper "
        "CheckConcurrentWritesSupported(const ColumnFamilyOptions&) "
        "(result by value, sret out in rdi = rbx; cf_options in "
        "rsi; stack canary used). Checks in binary order, first "
        "failure wins: inplace_update_support (+0x18, bool) != 0 "
        "-> 'In-place memtable updates (inplace_update_support) "
        "is not compatible with concurrent writes "
        "(allow_concurrent_memtable_write)' (InvalidArgument, 125 "
        "B, 0x95a210); memtable_factory (+0x128, "
        "shared_ptr<MemTableRepFactory>) -> "
        "IsInsertConcurrentlySupported() at vtable slot 0xa8 "
        "returns false -> 'Memtable doesn't concurrent writes "
        "(allow_concurrent_memtable_write)' (InvalidArgument, 68 "
        "B, 0x95e160). Else OK (out = {0, 0, nullptr}). Both "
        "error paths share the single Status ctor call at "
        "0x5d8bb0e (0x61cf670); the Slices are built on the stack "
        "(msg at (%rsp)/0x8(%rsp), msg2 = {0x4376fd, 0} at "
        "0x10(%rsp)/0x18(%rsp)). The FDE has no .cold FDE and no "
        "LSDA (aug_len 0): no landing pad, no catch, no cleanup; "
        "a throw propagates straight through and the canary is "
        "checked only on normal returns.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-column-family-data-validate-"
            "options-115 (open, PR #6449): reconstructs "
            "ColumnFamilyData::ValidateOptions 0x5d8e3b0, which "
            "calls this helper once when "
            "allow_concurrent_memtable_write is set (site "
            "0x5d8e7ee), as its second check. The #6449 packet's "
            "reference oracle for this function is superseded by "
            "this full reconstruction.",
            "RE-002-node115-vendor-census: the single FDE is "
            "census-bound (member 25dac13516458d4d-column_family.o, "
            "librocksdb-sys 0.11.0+8.1.1). Body a74c3048... / "
            "source c9479551... (6 relocations, kinds 2/4, no "
            "relaxation; all six are PC32/PLT32 disp32s: 124/136 "
            "the two msg2 leas, 175 the Status ctor call, 196/208 "
            "the two message leas, 228 the __stack_chk_fail "
            "call).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "db/column_family.cc:161-171 defines this helper "
            "exactly as the binary behaves (the "
            "inplace_update_support gate, then the "
            "memtable_factory->IsInsertConcurrentlySupported() "
            "gate, else OK); include/rocksdb/memtablerep.h:321 "
            "defines the base IsInsertConcurrentlySupported "
            "(returns false) and :354 the SkipListFactory "
            "override (returns true); include/rocksdb/options.h "
            "declares ColumnFamilyOptions. The binary matches "
            "v8.1.1 step for step, including both verbatim "
            "messages.",
            "ColumnFamilyOptions field offsets verified this cycle "
            "by compiling offsetof() against the real v8.1.1 "
            "headers (g++): inplace_update_support +0x18, "
            "memtable_factory +0x128; the #6449 anchors reproduce "
            "too (compaction_style +0xe8, ttl +0x160, "
            "table_factory +0x2b8, sizeof ColumnFamilyOptions "
            "0x300). The vtable slot of "
            "MemTableRepFactory::IsInsertConcurrentlySupported is "
            "verified two ways: hand-counting the vtable "
            "(Configurable 14 slots, Customizable 5 more, "
            "CreateMemTableRep x2, then "
            "IsInsertConcurrentlySupported at slot 21) and "
            "compiling the pointer-to-member encoding with g++ "
            "(vtable byte offset 168 = 0xa8, matching the "
            "binary's call *0xa8(%rax)).",
            "Binary-vs-source observations (recorded, not hidden): "
            "the FDE has no LSDA and no .cold FDE, so there is no "
            "landing pad and no cleanup for a throw from the "
            "Status ctor or the virtual call -- the exception "
            "propagates straight through, and the canary is "
            "checked only on normal returns. The binary loads the "
            "memtable_factory word and dereferences its vtable "
            "with no null check; a null factory is not a "
            "reachable state for a valid ColumnFamilyOptions "
            "(the default is SkipListFactory), so the model takes "
            "the factory's IsInsertConcurrentlySupported answer "
            "as an input and records the assumption. The gate on "
            "allow_concurrent_memtable_write (+0x1d2) lives in the "
            "caller (ColumnFamilyData::ValidateOptions), not in "
            "this helper: the helper itself never reads +0x1d2.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "target, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "CheckConcurrentWritesSupported 0x5d8ba60: exactly 1 "
                "direct call, 0 tail jumps, 0 LEA refs -- "
                "ColumnFamilyData::ValidateOptions 0x5d8e3b0 (site "
                "0x5d8e7ee, census-bound, column_family.o, open PR "
                "#6449). The helper runs once per ValidateOptions "
                "call when allow_concurrent_memtable_write is set, "
                "as its second check.",
                "No LSDA: the FDE record in .eh_frame (section "
                "offset 0x34ba04, length 0x20, initial_location "
                "0x5d8ba60, range 0xe8, aug_len 0) carries no LSDA "
                "pointer, so there is no call-site table and no "
                "landing pad.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 checks (each check failing alone, pairs "
                     "where check 1 must win, boundaries: all four "
                     "combinations of inplace_update_support x "
                     "memtable_factory_concurrent, mixed options) "
                     "+ 600 status (OK image, each error image with "
                     "code/subcode/severity/pad/state_ content, the "
                     "ctor's ': ' join with a non-empty msg2, both "
                     "verbatim messages) + 600 throw (BadAlloc in "
                     "the Status ctor at each of the 2 error sites "
                     "with the half-built status attached and no "
                     "cleanup, CalleeThrow at the virtual call, "
                     "canary failures on OK and error returns, "
                     "BadAlloc beating a bad canary -- with no LSDA "
                     "there is no pad canary check, so it still "
                     "propagates as BadAlloc -- alloc_ok=False with "
                     "no fail_at) + 600 bindings (caller-site "
                     "independence across the single caller, "
                     "FDE hashes as expected values)",
            "tests": "tests/test_check_concurrent_writes_supported115.py",
            "tool": "tools/check_concurrent_writes_supported115.py",
            "what_is_checked": [
                "checks: the first failing check wins (check 1 "
                "masks check 2); the inplace_update_support gate "
                "is tested before the virtual call (with inplace "
                "on, the factory answer never matters); the "
                "virtual call is reached only when check 1 passes",
                "status: the Status byte layout the ctor proves "
                "(code u8 +0x0, subcode u8 +0x1, severity u8 +0x2, "
                "padding +0x3..+0x7 zero with +0x6..+0x7 unwritten, "
                "state_ +0x8); the state_ buffer is msg + NUL with "
                "alloc len+1; the ctor's ': ' join when msg2 is "
                "non-empty (ctor behavior, never fired by this FDE); "
                "both messages byte-exact (125 B and 68 B)",
                "throw: each throwing call is recorded with pad "
                "None and empty cleanup (no LSDA); a BadAlloc "
                "leaves out half-built (code/subcode/severity "
                "written, state_ null); canary failures raise "
                "StackCheckFailed on the return path only -- a "
                "throw never reaches the epilogue and there is no "
                "pad canary check, so BadAlloc + a bad canary "
                "still propagates as BadAlloc",
                "bindings: the result depends only on the options, "
                "never on the caller site; the FDE body hash, the "
                "source hash (6 relocations zeroed) and the "
                "engine-call counts match the binary",
            ],
        },
        "engine_callees": {
            "0x61cf670": "rocksdb::Status::Status(Code, SubCode, "
                         "const Slice&, const Slice&, Severity) "
                         "(census-bound, status.o): the five-argument "
                         "Status ctor, called once (0x5d8bb0e, shared "
                         "by both error paths). Its observable "
                         "behavior IS pinned from its disassembly: "
                         "code u8 +0x0, subcode u8 +0x1, severity u8 "
                         "+0x2, zeroes +0x3..+0x5, state_ = new "
                         "char[size+1] holding msg + (': ' + msg2 if "
                         "len2) + NUL. Its trailing delete[] of the "
                         "old state_ is DEAD (state_ is zeroed at "
                         "0x61cf6b0 before the read at 0x61cf6e4).",
            "0x5d8ba90": "The virtual call site: memtable_factory "
                         "(+0x128) vtable slot 0xa8 = "
                         "MemTableRepFactory::"
                         "IsInsertConcurrentlySupported. The base "
                         "returns false (memtablerep.h:321); "
                         "SkipListFactory returns true (:354). The "
                         "call is indirect (call *0xa8(%rax)); the "
                         "factory object itself is never modelled, "
                         "only its answer.",
            "0x63f0d70": "PLT __stack_chk_fail: the canary failure "
                         "at the epilogue (0x5d8bb43). Reached only "
                         "on a normal return; a throw never reaches "
                         "the epilogue.",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this VM. "
            "The target binary is never executed. The tool models the "
            "helper in Python from its whole-FDE disassembly; the "
            "Status ctor's observable behavior is pinned from its own "
            "disassembly. Status state_ buffers are deterministic heap "
            "ids, not real pointers; the subcode padding bytes "
            "(+0x6..+0x7) the binary never writes are modelled as "
            "zero. The live check (--live) reads the binary: the FDE "
            "body hash, the source hash, the FDE record (length "
            "0x20, range 0xe8, aug_len 0, no LSDA), the engine-call "
            "counts, the field cmp instructions, the two message "
            "bytes and the one-site caller census. make "
            "verify/test/catalogue-check in a tooled environment is "
            "still owed upstream.",
        "functions": functions,
        "layouts": {
            "status": {
                "+0x00": "code (u8; the Code enum; 0 = kOk). Written "
                         "by the ctor (mov %sil) and by the OK path "
                         "(movl $0x0 covers +0x0..+0x3).",
                "+0x01": "subcode (u8). Written by the ctor "
                         "(mov %dl); 0 in every result this FDE "
                         "produces.",
                "+0x02": "severity (u8). Written by the ctor "
                         "(mov %r9b); 0 in every result this FDE "
                         "produces.",
                "+0x03": "padding (5 bytes, +0x3..+0x7). The ctor "
                         "writes +0x3..+0x5 zero; the OK path writes "
                         "+0x3..+0x5 zero; +0x6..+0x7 are NEVER "
                         "written by any path in this FDE -- modelled "
                         "as zero, recorded as unwritten.",
                "+0x08": "state_ (char*, 8 bytes). nullptr = no "
                         "message; otherwise a heap buffer of "
                         "len(msg)+1 bytes holding msg + NUL (msg2 "
                         "is always empty here), freed by the "
                         "caller's move/delete[], never in this FDE.",
                "size": "0x10 (16 bytes)",
            },
            "cf_options_fields_read": {
                "+0x18": "inplace_update_support (bool).",
                "+0x128": "memtable_factory (shared_ptr<"
                         "MemTableRepFactory>, 16 bytes: ptr word "
                         "at +0x128, ctrl word at +0x130; only the "
                         "ptr word is read, to load the vtable).",
                "not_read": "allow_concurrent_memtable_write (+0x1d2) "
                            "is never read by this FDE -- the gate "
                            "lives in the caller.",
            },
            "lsda": {
                "none": "This FDE has NO LSDA: the .eh_frame record "
                        "(section offset 0x34ba04, length 0x20, "
                        "initial_location 0x5d8ba60, range 0xe8, "
                        "aug_len 0) carries no LSDA pointer. There "
                        "is no call-site table, no landing pad, no "
                        "catch and no cleanup. A throw from the "
                        "Status ctor (0x5d8bb0e) or the virtual call "
                        "(0x5d8ba90) propagates straight through; "
                        "the canary is checked only on normal "
                        "returns (epilogue 0x5d8baae).",
            },
            "landing_pads": {
                "none": "No landing pads exist: the FDE has no LSDA.",
            },
            "error_blocks": {
                "0x5d8bb18": "inplace error: Slices built (msg "
                            "0x95a210 len 125, msg2 empty) -> shared "
                            "Status ctor 0x5d8bb0e into out -> "
                            "epilogue.",
                "0x5d8bad0": "memtable error: Slices built (msg "
                            "0x95e160 len 68, msg2 empty) -> shared "
                            "Status ctor 0x5d8bb0e into out -> "
                            "epilogue.",
                "0x5d8ba9c": "OK path: movl $0x0,(%rbx); movw "
                            "$0x0,0x4(%rbx); movq $0x0,0x8(%rbx), "
                            "then the epilogue (canary check).",
            },
        },
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
