#!/usr/bin/env python3
"""Generate records.json for the node #115 WritableFileWriter::
GetFileChecksumFuncName packet from the tool, the caller census
and the case ledger. Semantic records only; no per-instruction
mnemonic lists in JSON.

Run from the repository root:
    python3 research/work-items/re-002-node115-rocksdb-writable-file-writer-get-file-checksum-func-name-115/gen_records.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
import get_file_checksum_func_name115 as tool  # noqa: E402

HERE = Path(__file__).resolve().parent


def _callers():
    sites = []
    with open(HERE / "callers.tsv") as fh:
        header = fh.readline()
        assert header.startswith("target\t"), header
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            sites.append({
                "target": parts[0],
                "target_name": parts[1],
                "kind": parts[2],
                "site": parts[3],
                "site_fde_start": parts[4],
                "site_fde_end": parts[5],
                "instruction": parts[6],
            })
    return sites


def _case_count():
    with open(HERE / "cases.tsv") as fh:
        return sum(1 for _ in fh) - 1


def main():
    sites = _callers()
    assert len(sites) == 6, len(sites)
    notes = [
        "GetFileChecksumFuncName 0x604c780: exactly 3 direct calls, "
        "3 tail jumps, 0 LEA refs -- rocksdb::BuildTable 0x5e1b9c0 "
        "(site 0x5e1f508; main FDE has no vendor census record, its "
        ".cold FDE is census-bound as BuildTable, member builder.o), "
        "CompactionOutputs::WriterSyncClose 0x5e183f0 (site "
        "0x5e189be, census-bound, compaction_outputs.o), "
        "BlobLogWriter::AppendFooter 0x5e26e90 (site 0x5e27213, "
        "census-bound, blob_log_writer.o), and the three table "
        "builders' own GetFileChecksumFuncName wrappers, which "
        "tail-jump here: BlockBasedTableBuilder 0x60e2180 (site "
        "0x60e2194, census-bound), CuckooTableBuilder 0x615cb10 "
        "(site 0x615cb1d, census-bound), PlainTableBuilder "
        "0x618b330 (site 0x618b340, census-bound). Each direct "
        "caller strlen()s the returned pointer and assigns it into "
        "a std::string (BuildTable: meta->file_checksum_func_name, "
        "db/builder.cc:336). Each wrapper loads its writer, "
        "null-checks it, and either tail-jumps here or returns its "
        "own TU-local copy of the \"Unknown\" literal (BlockBased "
        "0x97a0b0, Cuckoo 0x97ba18, Plain 0x97be00).",
        "No LSDA: the FDE record in .eh_frame (section offset "
        "0x367154, length 0x10, initial_location 0x604c780, range "
        "0x28, aug_len 0) carries no LSDA pointer, so there is no "
        "call-site table and no landing pad. The function has no "
        "stack frame and no canary, and makes no direct call at "
        "all: its only transfer is the indirect tail jump to the "
        "generator's Name. A throw from Name propagates with no "
        "cleanup of this function -- the tail jump leaves no frame "
        "of ours on the stack, so Name returns (or throws) "
        "directly to this function's caller.",
    ]
    records = {
        "artifact": "node #115",
        "artifact_sha256": tool.ARTIFACT_SHA256,
        "bound_context": [
            "RE-002-node115-rocksdb-writable-file-writer-get-file-"
            "checksum-115 (PR #6568, open at submission time): "
            "reconstructs WritableFileWriter::GetFileChecksum "
            "0x604c710, the sibling that returns the checksum "
            "itself (the generator's GetChecksum result, or the "
            "empty string). This packet reconstructs the sibling "
            "that returns the checksum FUNCTION NAME (the "
            "generator's Name result, or \"Unknown\"). The two "
            "packets share the checksum_generator_ at this+0xc8 "
            "and the vtable-order reasoning (complete-object "
            "dtor, deleting dtor, Update, Finalize, GetChecksum, "
            "Name); GetChecksum is slot 4, Name is slot 5. Unlike "
            "its sibling, this function returns const char* "
            "(this in rdi, pointer in rax) -- no sret out, no "
            "stack frame, no canary.",
            "RE-002-node115-file-checksum-name-115 (merged on "
            "upstream main): reconstructs the generator-side "
            "FileChecksumGenCrc32c::Name at 0x61cd020 -- a "
            "DIFFERENT function (the concrete generator's Name "
            "implementation, vtable slot 5 of "
            "FileChecksumGenCrc32c). This packet covers only the "
            "WritableFileWriter dispatcher at 0x604c780, which "
            "tail-jumps to whichever generator's Name is set; the "
            "concrete name string is the generator's own "
            "behavior, not this function's.",
            "RE-002-node115-vendor-census: the single FDE is "
            "census-bound (member "
            "a895f7517936a0f7-writable_file_writer.o, librocksdb-sys "
            "0.11.0+8.1.1). Body 33f3e26f... / source eeb70928... "
            "(1 kind-2 relocation at offset 35, the \"Unknown\" "
            "lea disp32; zeroing it reproduces the source hash "
            "exactly).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "file/writable_file_writer.cc:424-430 defines this "
            "helper exactly as the binary behaves (if "
            "checksum_generator_ != nullptr, return "
            "checksum_generator_->Name(); else return "
            "kUnknownFileChecksumFuncName); "
            "file/writable_file_writer.h:284 declares it as "
            "const char* GetFileChecksumFuncName() const; "
            "db/builder.cc:335-336 stores the checksum in "
            "meta->file_checksum (via GetFileChecksum) and the "
            "name in meta->file_checksum_func_name (via this "
            "function) -- the same BuildTable call sites the "
            "census finds in the binary. "
            "include/rocksdb/file_checksum.h:25 defines "
            "kUnknownFileChecksumFuncName as \"Unknown\" and :67 "
            "declares Name() as virtual const char* Name() "
            "const = 0; :52-67 declares FileChecksumGenerator's "
            "virtuals in order (complete-object dtor, deleting "
            "dtor, Update, Finalize, GetChecksum, Name) -- the "
            "two Itanium ABI destructor slots come first -- so "
            "vtable slot 5 (*0x28 past the vptr) is Name() "
            "const. The binary matches v8.1.1 step for step.",
            "Binary-vs-source observations (recorded, not hidden): "
            "the function returns const char*, not std::string -- "
            "the null branch is a bare lea + ret of the literal "
            "pointer, and the present branch is a tail jump that "
            "preserves no sret out; the three direct callers "
            "confirm it by strlen()ing the result before "
            "assigning it into a std::string. The tail jump "
            "means Name() returns directly to this function's "
            "caller. The three table-builder wrappers each carry "
            "their own TU-local copy of the \"Unknown\" literal "
            "(0x97a0b0 / 0x97ba18 / 0x97be00) rather than sharing "
            "this function's 0x974e00 -- the literal is "
            "constexpr char[] in a header, so each TU has its "
            "own copy. The 10-byte nop at 0x604c796 is alignment "
            "padding inside the FDE. The FDE has no LSDA and no "
            ".cold FDE.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on "
                      "the target, validated by decoding forward "
                      "from the enclosing FDE start with Capstone "
                      "(census.py). A site counts only on a real "
                      "instruction boundary with the expected "
                      "mnemonic.",
            "notes": notes,
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": _case_count(),
            "ledger": "cases.tsv",
            "split": "100 checks (50 name variants -- 10 lens x 5 "
                     "patterns -- x 2 generator states: null and "
                     "FileChecksumGenCrc32c) + 100 edge (10 name "
                     "values x 2 generator states x 5 conditions: "
                     "normal, generator throws, generator returns "
                     "empty, throw with empty name, generator "
                     "returns \"Unknown\" -- pinning that a throw "
                     "propagates with no frame of ours, that "
                     "gen_throws is vacuous with no generator, "
                     "and that a generator returning \"Unknown\" "
                     "is value-identical to the null branch but a "
                     "different path) + 100 bindings (25 "
                     "(generator, name) pairs x 4 recorded "
                     "invariants: body_sha256, source_sha256, "
                     "fde_record, caller_census -- each row records "
                     "the invariant's expected value and replay "
                     "compares it)",
            "tests": "tests/test_get_file_checksum_func_name115.py",
            "tool": "tools/get_file_checksum_func_name115.py",
            "what_is_checked": [
                "checks: a null generator always returns the "
                "\"Unknown\" pointer, for every name variant; a "
                "present generator returns its Name value "
                "verbatim, including the empty string and the "
                "literal \"Unknown\" itself",
                "edge: a generator throw propagates (the tail jump "
                "leaves no frame, so it reaches this function's "
                "caller directly); with no generator, gen_throws "
                "has no effect and the null branch still returns "
                "\"Unknown\"",
                "bindings: the result depends only on the writer "
                "state and the generator's returned name, never "
                "on the caller site; each bindings row records "
                "its invariant's expected value (body hash, "
                "source hash, FDE record, 3-call + 3-jump caller "
                "census) and replay compares it",
            ],
        },
        "engine_callees": {
            "FileChecksumGenerator::Name": "Virtual dispatch, not "
                "a direct call: the tail jump at 0x604c793 goes "
                "to vtable slot 5 of the object at this+0xc8 "
                "(checksum_generator_). The slot is Name() const "
                "by the FileChecksumGenerator vtable order in "
                "include/rocksdb/file_checksum.h:52-67 "
                "(complete-object dtor, deleting dtor, Update, "
                "Finalize, GetChecksum, Name) -- the two Itanium "
                "ABI destructor slots come first, so the sixth "
                "entry is Name, returning const char* (:67). The "
                "concrete Name implementation is the generator's "
                "(the CRC32C generator's Name is reconstructed "
                "in the merged RE-002-node115-file-checksum-"
                "name-115 packet); this packet claims no name "
                "string of its own, only the dispatch, the null "
                "branch and the returned pointer.",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on "
            "this VM. The target binary is never executed. The "
            "tool models the helper in Python from its whole-FDE "
            "disassembly; name strings are deterministic values, "
            "not real generator names. The live check (--live) "
            "reads the binary: the FDE body hash, the source hash "
            "(1 kind-2 relocation), the FDE record (length 0x10, "
            "range 0x28, aug_len 0, no LSDA), the 9 verbatim "
            "instructions, the \"Unknown\" literal at 0x974e00, "
            "the 3-call + 3-jump caller census and the model "
            "end-to-end legs. make verify/test/catalogue-check in "
            "a tooled environment is still owed upstream.",
        "functions": {
            "0x604c780": {
                "body_sha256": tool.BODY_SHA256,
                "callers": [s["site"] for s in sites],
                "census_id": "node115-vendor-604c780",
                "lea_refs": [],
                "mangled": tool.SYMBOL,
                "model": "40-byte GetFileChecksumFuncName() const "
                         "(this in rdi, const char* result in rax; "
                         "no stack frame, no canary, no LSDA, no "
                         ".cold FDE). Loads this+0xc8 "
                         "(checksum_generator_, std::unique_ptr<"
                         "FileChecksumGenerator>); if null, loads "
                         "the \"Unknown\" literal address "
                         "(0x974e00, kUnknownFileChecksumFuncName) "
                         "into rax and returns; else tail-jumps to "
                         "vtable slot 5 of the generator "
                         "(*0x28(%rax)) with (generator) -- slot 5 "
                         "is Name() const by the "
                         "FileChecksumGenerator vtable order "
                         "(complete-object dtor, deleting dtor, "
                         "Update, Finalize, GetChecksum, Name) -- "
                         "and Name returns directly to this "
                         "function's caller. 9 instructions: "
                         "endbr64; mov rdi, [rdi+0xc8]; test rdi, "
                         "rdi; je 0x604c7a0; mov rax, [rdi]; jmp "
                         "[rax+0x28]; nop (10-byte alignment "
                         "padding); lea rax, [rip-0x56d79a7] "
                         "(\"Unknown\" at 0x974e00); ret. The FDE "
                         "has no .cold FDE and no LSDA (aug_len "
                         "0): no landing pad, no catch, no "
                         "cleanup; a throw from Name propagates "
                         "with no cleanup of this function.",
                "relocations": tool.RELOCATIONS,
                "source_sha256": tool.SOURCE_SHA256,
                "raw_equal": False,
            },
        },
    }
    with open(HERE / "records.json", "w") as fh:
        json.dump(records, fh, indent=1)
        fh.write("\n")
    print("wrote records.json:", records["cases"]["count"], "cases,",
          len(sites), "caller sites")


if __name__ == "__main__":
    main()
