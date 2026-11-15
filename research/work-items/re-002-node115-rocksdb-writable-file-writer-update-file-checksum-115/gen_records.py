#!/usr/bin/env python3
"""Generate records.json for the node #115 WritableFileWriter::
UpdateFileChecksum packet from the tool, the caller census
and the case ledger. Semantic records only; no per-instruction
mnemonic lists in JSON.

Run from the repository root:
    python3 research/work-items/re-002-node115-rocksdb-writable-file-writer-update-file-checksum-115/gen_records.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
import update_file_checksum115 as tool  # noqa: E402

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
    assert len(sites) == 1, len(sites)
    notes = [
        "UpdateFileChecksum 0x604c7b0: exactly 1 direct call, "
        "0 tail jumps, 0 LEA refs -- WritableFileWriter::Append "
        "0x6054680 (site 0x6054764, census-bound, "
        "writable_file_writer.o). The helper runs once per Append, "
        "before PrepareWrite, forwarding the appended Slice to the "
        "writer's checksum generator when one is set.",
        "No LSDA: the FDE record in .eh_frame (section offset "
        "0x367168, length 0x10, initial_location 0x604c7b0, range "
        "0x21, aug_len 0) carries no LSDA pointer, so there is no "
        "call-site table and no landing pad. The function cannot "
        "throw: it has no calls, no stack frame and no canary; the "
        "tail jump to the generator's Update is the only transfer "
        "out, and Update itself is the callee's behavior, not this "
        "function's.",
    ]
    records = {
        "artifact": "node #115",
        "artifact_sha256": tool.ARTIFACT_SHA256,
        "bound_context": [
            "RE-002-node115-rocksdb-writable-file-writer-append-115 "
            "(PR #6215, open at submission time): reconstructs "
            "WritableFileWriter::Append 0x6054680, which calls this "
            "helper once (site 0x6054764) before PrepareWrite. The "
            "#6215 packet records checksum_generator_ at this+0xc8 "
            "and names this helper as the checksum-forwarding step; "
            "this packet supersedes that reference oracle with the "
            "full reconstruction.",
            "RE-002-node115-vendor-census: the single FDE is "
            "census-bound (member "
            "a895f7517936a0f7-writable_file_writer.o, librocksdb-sys "
            "0.11.0+8.1.1). Body 1f2a30cf... / source 1f2a30cf... "
            "(raw_equal, 0 relocations).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "file/writable_file_writer.cc:731-735 defines this "
            "helper exactly as the binary behaves (if "
            "checksum_generator_ != nullptr, "
            "checksum_generator_->Update(data.data(), data.size())); "
            "file/writable_file_writer.h:163 declares "
            "checksum_generator_ as "
            "std::unique_ptr<FileChecksumGenerator>; "
            "file/writable_file_writer.cc:59 calls it once, in "
            "Append -- the same single call site the census finds "
            "in the binary. include/rocksdb/file_checksum.h:52-67 "
            "declares FileChecksumGenerator's virtuals in order "
            "(complete-object dtor, deleting dtor, Update, "
            "Finalize, GetChecksum, Name) -- the two Itanium ABI "
            "destructor slots come first -- so vtable slot 2 "
            "(*0x10 past the vptr) is Update(const char*, size_t). "
            "The binary matches v8.1.1 step for step.",
            "Binary-vs-source observations (recorded, not hidden): "
            "the binary tail-jumps to the generator's Update "
            "instead of calling it (jmp *0x10(%rax) at 0x604c7ca), "
            "so this FDE has no return path after the dispatch -- "
            "the tail jump transfers control with Append's return "
            "address still on the stack, so Update returns to "
            "Append, at the instruction after the call site (not "
            "to Append's caller). The 3-byte nop at 0x604c7cd is alignment "
            "padding inside the FDE. The concrete checksum "
            "algorithm is the generator's own behavior (already "
            "reconstructed for the CRC32C/XXH generators in "
            "earlier RE-002 packets), not this function's; this "
            "model pins the dispatch and the forwarded arguments "
            "only. The FDE has no LSDA and no .cold FDE.",
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
            "split": "100 checks (50 data variants -- 10 lens x 5 "
                     "ptr ids -- x 2 generator states: null and "
                     "FileChecksumGenCrc32c) + 100 edge (size_t "
                     "extremes 0, 1, 2, 0x7fffffff, 0x80000000, "
                     "0xffffffff, 0x100000000, 0x7fffffffffffffff, "
                     "0x8000000000000000, 0xffffffffffffffff on "
                     "either side, pinning that a null generator "
                     "never calls even for a huge len and a present "
                     "generator is called even for len 0) + 100 "
                     "bindings (25 (generator, data) pairs x 4 "
                     "recorded invariants: body_sha256, "
                     "source_sha256, fde_record, caller_census -- "
                     "each row records the invariant's expected "
                     "value and replay compares it)",
            "tests": "tests/test_update_file_checksum115.py",
            "tool": "tools/update_file_checksum115.py",
            "what_is_checked": [
                "checks: a null generator never calls, for every "
                "data variant; a present generator always calls "
                "exactly once, with (data.data(), data.size()) "
                "forwarded verbatim",
                "edge: size_t extremes pass through as 64-bit "
                "values (len 0x100000000 stays 0x100000000, not "
                "truncated to 32 bits); len 0 still calls Update "
                "when a generator is set",
                "bindings: the result depends only on the writer "
                "state and the Slice, never on the caller site; "
                "each bindings row records its invariant's "
                "expected value (body hash, source hash, FDE "
                "record, 1-site caller census) and replay "
                "compares it",
            ],
        },
        "engine_callees": {
            "FileChecksumGenerator::Update": "Virtual dispatch, not "
                "a direct call: the tail jump at 0x604c7ca goes to "
                "vtable slot 2 of the object at this+0xc8 "
                "(checksum_generator_). The slot is Update(const "
                "char*, size_t) by the FileChecksumGenerator "
                "vtable order in include/rocksdb/file_checksum.h:"
                "52-67 (complete-object dtor, deleting dtor, "
                "Update, Finalize, GetChecksum, Name) -- the two "
                "Itanium ABI destructor slots come first, so the "
                "third entry is Update. The concrete Update "
                "implementation is the "
                "generator's (CRC32C/XXH generators reconstructed "
                "in earlier RE-002 packets); this packet claims no "
                "checksum algorithm, only the dispatch and the "
                "forwarded (data, len).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on "
            "this VM. The target binary is never executed. The "
            "tool models the helper in Python from its whole-FDE "
            "disassembly; data pointers are deterministic ids, not "
            "real addresses, and the generator is modelled as an "
            "abstract FileChecksumGenerator (null or named). The "
            "live check (--live) reads the binary: the FDE body "
            "hash, the source hash, the FDE record (length 0x10, "
            "range 0x21, aug_len 0, no LSDA), the 10 verbatim "
            "instructions, the 1-site caller census and the model "
            "end-to-end legs. make verify/test/catalogue-check in "
            "a tooled environment is still owed upstream.",
        "functions": {
            "0x604c7b0": {
                "body_sha256": tool.BODY_SHA256,
                "callers": [s["site"] for s in sites],
                "census_id": "node115-vendor-604c7b0",
                "lea_refs": [],
                "mangled": tool.SYMBOL,
                "model": "33-byte leaf UpdateFileChecksum(const "
                         "Slice&) (this in rdi, data Slice* in rsi: "
                         "data.data() at (%rsi), data.size() at "
                         "0x8(%rsi); no stack frame, no canary, no "
                         "calls). Loads this+0xc8 (checksum_"
                         "generator_, std::unique_ptr<FileChecksum"
                         "Generator>); if null, returns; else "
                         "tail-jumps to vtable slot 2 of the "
                         "generator (*0x10(%rax)) with (data.data(), "
                         "data.size()) -- slot 2 is Update(const "
                         "char*, size_t) by the FileChecksum"
                         "Generator vtable order (complete-object "
                         "dtor, deleting dtor, Update, Finalize, "
                         "GetChecksum, Name). The tail jump leaves "
                         "Append's return address on the stack, so "
                         "Update returns to Append, at the "
                         "instruction after the call site. 10 "
                         "instructions: endbr64; mov rdi, [rdi+"
                         "0xc8]; test rdi, rdi; je 0x604c7d0; mov "
                         "rax, [rdi]; mov rdx, [rsi+8]; mov rsi, "
                         "[rsi]; jmp [rax+0x10]; nop (3-byte "
                         "alignment padding); ret. The FDE has no "
                         ".cold FDE and no LSDA (aug_len 0): no "
                         "landing pad, no catch, no cleanup; the "
                         "function cannot throw.",
                "relocations": "",
                "source_sha256": tool.SOURCE_SHA256,
                "raw_equal": True,
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
