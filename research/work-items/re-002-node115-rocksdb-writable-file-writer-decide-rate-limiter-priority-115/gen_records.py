#!/usr/bin/env python3
"""Generate records.json for the node #115 WritableFileWriter::
DecideRateLimiterPriority packet from the tool, the caller census
and the case ledger. Semantic records only; no per-instruction
mnemonic lists in JSON.

Run from the repository root:
    python3 research/work-items/re-002-node115-rocksdb-writable-file-writer-decide-rate-limiter-priority-115/gen_records.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
import decide_rate_limiter_priority115 as tool  # noqa: E402

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
        "DecideRateLimiterPriority 0x604c800: exactly 6 direct calls, "
        "0 tail jumps, 0 LEA refs -- one site in each of "
        "WritableFileWriter::WriteBuffered 0x604e140 (site 0x604e1d6), "
        "WriteBufferedWithChecksum 0x604f080 (site 0x604f10c), "
        "WriteDirect 0x604fe80 (site 0x604fff1), "
        "WriteDirectWithChecksum 0x6050c80 (site 0x6050df9), Flush "
        "0x6051a20 (site 0x6051b69) and Append 0x6054680 (site "
        "0x6054829), all census-bound, writable_file_writer.o. The "
        "helper runs once per write path, before PrepareWrite, to "
        "pick the rate-limiter priority of that write.",
        "No LSDA: the FDE record in .eh_frame (section offset "
        "0x367198, length 0x10, initial_location 0x604c800, range "
        "0x27, aug_len 0) carries no LSDA pointer, so there is no "
        "call-site table and no landing pad. The function cannot "
        "throw: it has no calls, no stack frame and no canary.",
    ]
    records = {
        "artifact": "node #115",
        "artifact_sha256": tool.ARTIFACT_SHA256,
        "bound_context": [
            "RE-002-node115-rocksdb-writable-file-writer-append-115 "
            "(PR #6215, open at submission time): reconstructs "
            "WritableFileWriter::Append 0x6054680, which calls this "
            "helper once (site 0x6054829) before PrepareWrite. The "
            "#6215 packet's reference oracle for this function is "
            "superseded by this full reconstruction.",
            "RE-002-node115-vendor-census: the single FDE is "
            "census-bound (member "
            "a895f7517936a0f7-writable_file_writer.o, librocksdb-sys "
            "0.11.0+8.1.1). Body 1e2d437d... / source 1e2d437d... "
            "(raw_equal, 0 relocations).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "file/writable_file_writer.cc:974-987 defines this "
            "helper exactly as the binary behaves (both TOTAL -> "
            "TOTAL; file TOTAL -> op; op TOTAL -> file; neither -> "
            "op); include/rocksdb/env.h:431-437 defines the "
            "IOPriority enum (IO_LOW 0, IO_MID 1, IO_HIGH 2, "
            "IO_USER 3, IO_TOTAL 4); file/writable_file_writer.cc "
            "calls it at lines 64 (Append), 364 (WriteBuffered), "
            "557 (WriteDirect), 652 (WriteDirectWithChecksum), 789 "
            "(WriteBufferedWithChecksum) and 899 (Flush) -- the "
            "same six call sites the census finds in the binary. "
            "The binary matches v8.1.1 step for step.",
            "Binary-vs-source observations (recorded, not hidden): "
            "the source writes the decision as a four-arm if/else "
            "chain; the binary compiles it into a different branch "
            "shape (it tests op == 4 once into dl at 0x604c807, "
            "then branches on file == 4) with identical semantics "
            "for every 32-bit input. The FDE has no LSDA and no "
            ".cold FDE, so there is no landing pad and no cleanup; "
            "the function cannot throw.",
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
            "split": "100 checks (every valid (file, op) pair in "
                     "IO_LOW..IO_TOTAL x 4 caller contexts: Append, "
                     "WriteBuffered, WriteDirect, Flush) + 100 edge "
                     "(out-of-range 32-bit values 5, 6, 255, "
                     "0x7fffffff, 0x80000000, 0xffffffff on either "
                     "side, pinning that the binary compares full "
                     "32-bit values against 4 only) + 100 bindings "
                     "(the 25 valid pairs x 4 recorded invariants: "
                     "body_sha256, source_sha256, fde_record, "
                     "caller_census)",
            "tests": "tests/test_decide_rate_limiter_priority115.py",
            "tool": "tools/decide_rate_limiter_priority115.py",
            "what_is_checked": [
                "checks: all 25 valid pairs return op unless op is "
                "IO_TOTAL, in which case file; both TOTAL returns "
                "TOTAL; the result is identical in all four caller "
                "contexts (caller-independence)",
                "edge: out-of-range values pass through unchanged "
                "(op != 4 -> op; op == 4 -> file) for values above "
                "the enum range and for the 32-bit extremes, "
                "including 0xffffffff and 0x80000000",
                "bindings: the result depends only on the two "
                "priorities, never on the caller site; the FDE body "
                "hash, the source hash (raw_equal, 0 relocations) "
                "and the 6-site caller census match the binary",
            ],
        },
        "engine_callees": {},
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on "
            "this VM. The target binary is never executed. The "
            "tool models the helper in Python from its whole-FDE "
            "disassembly; the function has no callees, so there is "
            "no engine-call surface to pin. The live check "
            "(--live) reads the binary: the FDE body hash, the "
            "source hash, the FDE record (length 0x10, range 0x27, "
            "aug_len 0, no LSDA), the 16 verbatim instructions, "
            "the 6-site caller census and the model end-to-end "
            "legs. make verify/test/catalogue-check in a tooled "
            "environment is still owed upstream.",
        "functions": {
            "0x604c800": {
                "body_sha256": tool.BODY_SHA256,
                "callers": [s["site"] for s in sites],
                "census_id": "node115-vendor-604c800",
                "lea_refs": [],
                "mangled": tool.SYMBOL,
                "model": "39-byte leaf DecideRateLimiterPriority("
                         "Env::IOPriority, Env::IOPriority) "
                         "(result in eax; first arg in edi = "
                         "writable_file_io_priority, second arg in "
                         "esi = op_rate_limiter_priority; no stack "
                         "frame, no canary, no calls). Returns op "
                         "unless op == IO_TOTAL (4), in which case "
                         "file; both TOTAL -> TOTAL. 16 "
                         "instructions: endbr64; cmp $0x4,%esi; "
                         "sete %dl; cmp $0x4,%edi; jne 0x604c820; "
                         "mov $0x4,%eax; test %dl,%dl; jne "
                         "0x604c81f; cmp $0x4,%edi; jne 0x604c820; "
                         "mov %esi,%eax; ret; test %dl,%dl; je "
                         "0x604c81d; mov %edi,%eax; ret. All four "
                         "conditional jumps stay inside the FDE. "
                         "The FDE has no .cold FDE and no LSDA "
                         "(aug_len 0): no landing pad, no catch, "
                         "no cleanup; the function cannot throw.",
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
