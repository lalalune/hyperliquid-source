#!/usr/bin/env python3
"""Generate records.json for the node #115 WritableFileWriter::
SyncWithoutFlush packet from the tool, the caller census and the
case ledger. Semantic records only; no per-instruction mnemonic
lists in JSON.

Run from the repository root:
    python3 research/work-items/re-002-node115-rocksdb-writable-file-writer-sync-without-flush-115/gen_records.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
import sync_without_flush115 as tool  # noqa: E402

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
        "SyncWithoutFlush 0x604d500: exactly 1 direct call, 0 tail "
        "jumps, 0 LEA refs -- rocksdb::DBImpl::SyncWAL 0x5d7f3b0 "
        "(site 0x5d7f657, FDE 0x5d7f3b0..0x5d7fb40, census-bound, "
        "db_impl.o). The single caller is the WAL-sync path: "
        "upstream db_impl.cc calls SyncWithoutFlush from "
        "DBImpl::SyncWAL, the same caller the census finds in the "
        "binary. No other call site exists in the node.",
        "Main FDE record in .eh_frame (section offset 0x759550, "
        "length 0x34, initial_location 0x604d500, range 0x1bd, "
        "aug_len 4, LSDA at 0x41e76e in .gcc_except_table: 4 "
        "call-site entries, all cleanup, action 0 -- [0] start "
        "0x4e len 3 no pad (the IsSyncThreadSafe virtual call), "
        "[1] start 0x72 len 5 pad 0x1b1 (the NotSupported new[] "
        "-> stub 0x604d6b1 -> .cold 0x604d4ce), [2] start 0x102 "
        "len 5 no pad (the SyncInternal call), [3] start 0x159 "
        "len 5 pad 0x1a5 (the IOError new[] -> stub 0x604d6a5 -> "
        ".cold 0x604d4a8). Cold FDE record (section offset "
        "0x759588, length 0x1c, initial_location 0x604d4a8, range "
        "0x56, aug_len 4, LSDA at 0x41e786: 1 entry, start 0x21 "
        "len 0x2b, no pad). A throw from IsSyncThreadSafe or from "
        "SyncInternal therefore propagates with no cleanup of "
        "this function (out untouched, seen_error_ unchanged); a "
        "failed new[] lands in the .cold cleanup, which deletes "
        "the out state_ (null at that point), checks the canary, "
        "and calls _Unwind_Resume -- a bad canary there calls "
        "__stack_chk_fail instead of resuming.",
        "The function has a 0x20 stack frame and a canary (stored "
        "at rsp+0x18, checked before every return; failure calls "
        "__stack_chk_fail at 0x604d6a0). The two landing-pad "
        "stubs at the end of the main FDE (0x604d6a5 and "
        "0x604d6b1: endbr64; mov rbp, rax; jmp .cold) are the only "
        "out-of-FDE jumps; all conditional jumps stay inside the "
        "main FDE.",
    ]
    records = {
        "artifact": "node #115",
        "artifact_sha256": tool.ARTIFACT_SHA256,
        "bound_context": [
            "RE-002-node115-rocksdb-writable-file-writer-sync-115 "
            "(open PR, sibling): reconstructs "
            "WritableFileWriter::Sync 0x6052800, which flushes "
            "first and then calls SyncInternal when pending_sync_ "
            "is set. This packet reconstructs the sibling that "
            "syncs WITHOUT flushing -- the call a concurrent "
            "writer may make while appends continue. Both share "
            "SyncInternal (0x604c900) as their engine call and "
            "the seen_error_ flag at this+0x89; Sync additionally "
            "reads pending_sync_ and calls Flush, which this "
            "function never does.",
            "RE-002-node115-rocksdb-writable-file-writer-append-115 "
            "(merged): reconstructs WritableFileWriter::Append, "
            "the only caller of UpdateFileChecksum and the "
            "writer's main entry point; it shares the "
            "checksum_generator_ at this+0xc8 and the "
            "writable_file_ (FSWritableFilePtr) layout used here "
            "(io_tracer_ at this+0x20, fs_tracer_ at this+0x30).",
            "RE-002-node115-vendor-census: both FDEs are "
            "census-bound (member "
            "a895f7517936a0f7-writable_file_writer.o, librocksdb-sys "
            "0.11.0+8.1.1). Main body 6904e218... / source "
            "37748165... (15 relocations, kinds 2/4; zeroing them "
            "reproduces the source hash exactly). Cold body "
            "88100ca5... / source f8aefe2c... (6 kind-4 "
            "relocations; zeroing them reproduces the source hash "
            "exactly).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "file/writable_file_writer.cc:455-474 defines "
            "SyncWithoutFlush exactly as the binary behaves "
            "(seen_error() -> AssertFalseAndGetStatusForPrevError; "
            "!writable_file_->IsSyncThreadSafe() -> NotSupported "
            "with the 94-char message; SyncInternal(use_fsync); "
            "on failure set_seen_error(); return s). "
            "file/writable_file_writer.h:296-301 defines "
            "AssertFalseAndGetStatusForPrevError as "
            "IOStatus::IOError(\"Writer has previous error.\") "
            "(the NDEBUG assert on sync_without_flush_called_ "
            "is compiled out); :286-294 defines seen_error() / "
            "set_seen_error() on the atomic<bool> at this+0x89. "
            "env/file_system_tracer.h:345-383 defines "
            "FSWritableFilePtr (shared_ptr<IOTracer> io_tracer_ "
            "at +0x20, unique_ptr<FSWritableFileTracingWrapper> "
            "fs_tracer_ at +0x30) and its get(): the tracing "
            "wrapper itself when io_tracer_ is set and tracing "
            "is enabled, else fs_tracer_->target(). "
            "include/rocksdb/file_system.h:1048 declares "
            "IsSyncThreadSafe() (default false) and :1683 the "
            "tracing wrapper's override forwarding to its "
            "target; :1638-1644 defines FSWritableFileWrapper "
            "with target_ at +0x28 (after the FSWritableFile "
            "base: vtable + two u64 + two int + bool + pad = "
            "0x28). trace_replay/io_tracer.h:170 defines "
            "is_tracing_enabled() as returning the "
            "tracing_enabled bool (read at +0x68 of the "
            "IOTracer object in the binary). "
            "include/rocksdb/io_status.h:171 defines the "
            "IOStatus copy ctor, which resets severity to "
            "kNoError -- the binary's copy of the SyncInternal "
            "result zeroes out byte +0x2 for exactly that "
            "reason. The FSWritableFile vtable order "
            "(file_system.h:940-1075) puts IsSyncThreadSafe at "
            "slot 11 (*0x58 past the vptr): dtor x2, Append x2, "
            "PositionedAppend x2, Truncate, Close, Flush, Sync, "
            "Fsync, then IsSyncThreadSafe. The binary matches "
            "v8.1.1 step for step.",
            "Binary-vs-source observations (recorded, not hidden): "
            "the vendored WritableFileWriter layout differs from "
            "a stock v8.1.1 compile (checksum_generator_ at "
            "+0xc8, not +0xb0; seen_error_ at +0x89) -- the model "
            "follows the binary offsets, and the layout is "
            "pinned by the two binary anchors (seen_error_ "
            "read at entry and set on SyncInternal failure; "
            "checksum_generator_ at +0xc8 from the sibling "
            "packets). The 94-char NotSupported message is "
            "copied in six 16-byte movdqa chunks whose last "
            "chunk starts at buffer +0x4e, overlapping the "
            "previous chunk by 2 bytes; the 26-char message's "
            "second chunk starts at +0xa. The copy of the "
            "SyncInternal result leaves out bytes +0x6..+0x7 "
            "unwritten (padding) and zeroes byte +0x2 "
            "(severity reset by the copy ctor). The .cold FDE "
            "holds two identical cleanup blocks (delete the out "
            "state_, check the canary, _Unwind_Resume) reached "
            "from the two different landing-pad stubs. The "
            "single caller is DBImpl::SyncWAL; SyncWithoutFlush "
            "is never called from Flush, Append or the table "
            "builders in this binary.",
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
            "split": "100 checks (50 combos -- tracer state x "
                     "thread-safety x use_fsync x SyncInternal "
                     "result -- x 2 seen_error states) + 100 edge "
                     "(10 base combos x 10 conditions: normal, "
                     "IsSyncThreadSafe throws, SyncInternal throws, "
                     "new[] fails in the NotSupported path, new[] "
                     "fails in the IOError path, bad canary on "
                     "return, throw with bad canary, new[] failure "
                     "with bad canary, empty sync message) + 100 "
                     "bindings (25 (writer, use_fsync) pairs x 4 "
                     "recorded invariants: body_sha256, "
                     "source_sha256, fde_record, caller_census -- "
                     "each row records the invariant's expected "
                     "value and replay compares it)",
            "tests": "tests/test_sync_without_flush115.py",
            "tool": "tools/sync_without_flush115.py",
            "what_is_checked": [
                "checks: a seen_error writer always returns the "
                "26-char IOError regardless of the file state; a "
                "non-thread-safe file always returns the 94-char "
                "NotSupported before SyncInternal is reached; a "
                "thread-safe file returns the SyncInternal result "
                "with severity reset to kNoError, and a non-OK "
                "result sets seen_error_",
                "edge: a throw from IsSyncThreadSafe or from "
                "SyncInternal propagates with no landing pad (out "
                "untouched, seen_error unchanged); a failed new[] "
                "in either error path lands in the .cold cleanup; "
                "a bad canary becomes StackCheckFailed at the "
                "return check",
                "bindings: the result depends only on the writer "
                "state, the tracer state and the SyncInternal "
                "oracle result, never on the caller site; each "
                "bindings row records its invariant's expected "
                "value (both FDE body/source hashes, both FDE "
                "records with LSDA pointers, 1-call caller "
                "census) and replay compares it",
            ],
        },
        "engine_callees": {
            "WritableFileWriter::SyncInternal": "Direct call at "
                "0x604d602 (FDE 0x604c900..0x604d4a7, .cold "
                "0x604c828..0x604c8f5, census-bound .cold, member "
                "writable_file_writer.o). The oracle of this "
                "packet: its result is an input to the model, not "
                "computed here. It takes (out, this, use_fsync) "
                "and returns the IOStatus this function copies "
                "(severity reset by the copy ctor) and, on "
                "non-OK, records via set_seen_error(). Upstream "
                "file/writable_file_writer.cc:476-515.",
            "FSWritableFile::IsSyncThreadSafe": "Virtual call, not "
                "a direct call: the indirect call at 0x604d54e "
                "goes to vtable slot 11 (*0x58 past the vptr) of "
                "the effective file resolved by "
                "FSWritableFilePtr::get(). The slot is "
                "IsSyncThreadSafe() const by the FSWritableFile "
                "vtable order in include/rocksdb/file_system.h: "
                "940-1075 (dtor x2, Append x2, PositionedAppend "
                "x2, Truncate, Close, Flush, Sync, Fsync, then "
                "IsSyncThreadSafe; default returns false, "
                ":1048). The tracing wrapper's override "
                "(:1683) forwards to its target, so the deciding "
                "value is the target file's either way.",
            "operator new[] / operator delete[]": "PLT calls: new "
                "at 0x63f0e30 (twice: the 95-byte NotSupported "
                "buffer and the 27-byte prev-error buffer) and "
                "delete[] at 0x63f0dc0 (the out state_ release in "
                "both fresh-error builders and in both .cold "
                "cleanup blocks). A failed new[] throws BadAlloc "
                "into the .cold cleanup (LSDA entries [1] and "
                "[3]).",
            "__stack_chk_fail / _Unwind_Resume": "PLT calls: "
                "__stack_chk_fail at 0x63f0d70 (bad canary at the "
                "return check, 0x604d6a0, and in both .cold "
                "blocks, 0x604d4f4/0x604d4f9); _Unwind_Resume at "
                "0x63f0a50 (both .cold blocks, 0x604d4c9/"
                "0x604d4ef).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on "
            "this VM. The target binary is never executed. The "
            "tool models the helper in Python from its whole-FDE "
            "disassembly; SyncInternal is an oracle whose result "
            "is an input to the model. The live check (--live) "
            "reads the binary: both FDE body hashes, both source "
            "hashes (15 + 6 census relocations), both FDE records "
            "(lengths 0x34/0x1c, ranges 0x1bd/0x56, aug_len 4, "
            "LSDA pointers 0x41e76e/0x41e786), both LSDA call-site "
            "tables (4 + 1 entries), the 105 + 20 verbatim "
            "instructions, both message byte reconstructions, the "
            "1-call caller census and the model end-to-end legs. "
            "make verify/test/catalogue-check in a tooled "
            "environment is still owed upstream.",
        "functions": {
            "0x604d500": {
                "body_sha256": tool.BODY_SHA256,
                "callers": [s["site"] for s in sites],
                "census_id": "node115-vendor-604d500",
                "cold_body_sha256": tool.COLD_BODY_SHA256,
                "cold_fde": "0x604d4a8..0x604d4fe (86 B, body "
                            "88100ca5..., source f8aefe2c..., 6 "
                            "kind-4 relocations at offsets 10, 34, "
                            "48, 72, 77, 82; FDE record section "
                            "offset 0x759588, length 0x1c, range "
                            "0x56, aug_len 4, LSDA at 0x41e786, 1 "
                            "call-site entry, no pad)",
                "cold_source_sha256": tool.COLD_SOURCE_SHA256,
                "lea_refs": [],
                "mangled": tool.SYMBOL,
                "model": "445-byte SyncWithoutFlush(bool use_fsync) "
                         "(sret out in rdi, this in rsi, use_fsync "
                         "in edx; 0x20 stack frame, canary at "
                         "rsp+0x18). If seen_error_ (this+0x89) is "
                         "set, return IOStatus::IOError(\"Writer "
                         "has previous error.\", code 5). Else "
                         "resolve the file via FSWritableFilePtr::"
                         "get() (io_tracer_ at this+0x20, "
                         "fs_tracer_ at this+0x30; tracing wrapper "
                         "itself when io_tracer_ is set and its "
                         "+0x68 tracing_enabled byte is set, else "
                         "fs_tracer_->target() at wrapper+0x28) "
                         "and call IsSyncThreadSafe (vtable slot "
                         "11, *0x58(%rax)); if false, return "
                         "IOStatus::NotSupported with the 94-char "
                         "message (code 3). Else call SyncInternal "
                         "(use_fsync) at 0x604c900 into a stack "
                         "IOStatus; if its code is non-zero, "
                         "set_seen_error(); return the copy of "
                         "that status with severity reset to "
                         "kNoError by the IOStatus copy ctor. 105 "
                         "instructions main, 20 cold; main LSDA 4 "
                         "entries (pads 0x1b1/0x1a5 to the two "
                         ".cold cleanup blocks); cold LSDA 1 "
                         "entry, no pad.",
                "relocations": tool.RELOCATIONS_DESC,
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
