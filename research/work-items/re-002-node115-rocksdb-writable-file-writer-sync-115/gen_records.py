#!/usr/bin/env python3
"""Generate records.json for the node #115 WritableFileWriter::Sync
packet from the tool, the caller census and the case ledger.
Semantic records only; no per-instruction mnemonic lists in JSON.

Run from the repository root:
    python3 research/work-items/re-002-node115-rocksdb-writable-file-writer-sync-115/gen_records.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
import sync115 as tool  # noqa: E402

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
    assert len(sites) == 11, len(sites)
    notes = [
        "Sync 0x6052800: exactly 11 direct calls, 0 tail jumps, 0 "
        "LEA refs -- rocksdb::DBImpl::SyncClosedLogs 0x5ddd080 "
        "(site 0x5ddd278, FDE 0x5ddd080..0x5ddd673, census-bound, "
        "db_impl_compaction_flush.o), rocksdb::CompactionOutputs::"
        "WriterSyncClose 0x5e183f0 (site 0x5e1881a, FDE "
        "0x5e183f0..0x5e18b3b, census-bound, compaction_outputs.o), "
        "rocksdb::BuildTable 0x5e1b9c0 (site 0x5e1eed6, FDE "
        "0x5e1b9c0..0x5e20481; the main FDE has no census record, "
        "its .cold is census-bound as BuildTable, builder.o), "
        "rocksdb::BlobLogWriter::Sync 0x5e26110 (site 0x5e261ac, "
        "FDE 0x5e26110..0x5e262c4, census-bound, blob_log_writer.o), "
        "rocksdb::DBImpl::Open 0x5e62c50 (sites 0x5e63cce and "
        "0x5e650c7, FDE 0x5e62c50..0x5e65462, census-bound, "
        "db_impl_open.o), rocksdb::DBImpl::WriteToWAL 0x5e89c90 "
        "(site 0x5e8a1d2, FDE 0x5e89c90..0x5e8a4a9, census-bound, "
        "db_impl_write.o), rocksdb::CreateFile 0x603a5a0 (site "
        "0x603a9aa, FDE 0x603a5a0..0x603ad3e, census-bound, "
        "file_util.o), rocksdb::CopyFile 0x603ae70 (site 0x603bcda, "
        "FDE 0x603ae70..0x603bfd6, census-bound, file_util.o), "
        "rocksdb::SyncManifest 0x603fa00 (site 0x603fb3d, FDE "
        "0x603fa00..0x603ff25, census-bound, filename.o), "
        "rocksdb::PersistRocksDBOptions 0x60d2820 (site 0x60d43ff, "
        "FDE 0x60d2820..0x60d49d3, census-bound, options_parser.o). "
        "No other call site exists in the node.",
        "Main FDE record in .eh_frame (section offset 0x7598bc, "
        "length 0x34, initial_location 0x6052800, range 0x1ee, "
        "aug_len 4, LSDA at 0x41ea39 in .gcc_except_table: 3 "
        "call-site entries, all cleanup, action 0 -- [0] start "
        "0x43 len 5 pad 0x1d6 (the prev-error new[] -> stub "
        "0x60529d6 -> .cold 0x60527a6), [1] start 0xa6 len 5 no "
        "pad (the Flush call), [2] start 0xd3 len 0x21 pad 0x1e2 "
        "(the use_direct_io call at 0xd3 and the SyncInternal "
        "call at 0xef, sharing the stub 0x60529e2 -> .cold "
        "0x60527cc). Cold FDE record (section offset 0x7598f4, "
        "length 0x1c, initial_location 0x60527a6, range 0x57, "
        "aug_len 4, LSDA at 0x41ea4d: 1 entry, start 0x21 len "
        "0x2c, no pad). A throw from Flush therefore propagates "
        "with no cleanup of this function (out untouched, "
        "seen_error_ unchanged); a throw from use_direct_io or "
        "from SyncInternal lands in the .cold cleanup at "
        "0x60527cc, which deletes the local status's state_ "
        "(null after the OK Flush), checks the canary, and calls "
        "_Unwind_Resume; a failed new[] lands in the .cold "
        "cleanup at 0x60527a6, which deletes the out state_ "
        "(null at that point), checks the canary, and calls "
        "_Unwind_Resume -- a bad canary in either block calls "
        "__stack_chk_fail instead of resuming.",
        "The function has a 0x30 stack frame and a canary (stored "
        "at rsp+0x28, checked before every return; failure calls "
        "__stack_chk_fail at 0x60529d1). The two landing-pad "
        "stubs at the end of the main FDE (0x60529d6 and "
        "0x60529e2: endbr64; mov rbp/rbx, rax; jmp .cold) are the "
        "only out-of-FDE jumps; all conditional jumps stay inside "
        "the main FDE. The move-assign block at 0x60528f4.."
        "0x6052948 moves the SyncInternal result (rsp+0x10) into "
        "the local status (rsp) field by field -- code/subcode, "
        "bytes +3..+5, state_ pointer -- without writing the "
        "destination's severity byte, so it stays 0 from the OK "
        "Flush result; the second delete[] in that block is dead "
        "(the source state_ was already moved out and nulled). "
        "The shared failure copy at 0x60529a0..0x60529cc serves "
        "both the Flush failure and the SyncInternal failure: "
        "set_seen_error(), then copy the local status to out "
        "with byte +0x2 zeroed (severity reset by the copy ctor).",
    ]
    records = {
        "artifact": "node #115",
        "artifact_sha256": tool.ARTIFACT_SHA256,
        "bound_context": [
            "WritableFileWriter::SyncWithoutFlush 0x604d500 (open "
            "PR #6570, not merged): the sibling that syncs without "
            "flushing -- the call a concurrent writer may make "
            "while appends continue (file/writable_file_writer.cc: "
            "455-474). It shares SyncInternal (0x604c900) as its "
            "engine call, the seen_error_ flag at this+0x89, the "
            "26-char prev-error message and its two .rodata chunks "
            "(0x451480/0x452bf0), and the FSWritableFilePtr::get() "
            "file resolution; it differs in that it checks "
            "IsSyncThreadSafe (vtable slot 11) and never calls "
            "Flush, never reads pending_sync_, and never calls "
            "use_direct_io (slot 12).",
            "RE-002-node115-rocksdb-writable-file-writer-append-115 "
            "(merged): reconstructs WritableFileWriter::Append, "
            "the writer's main entry point; it shares the "
            "checksum_generator_ at this+0xc8 and the "
            "writable_file_ (FSWritableFilePtr) layout used here "
            "(io_tracer_ at this+0x20, fs_tracer_ at this+0x30).",
            "WritableFileWriter::Flush 0x6051a20 (open PR #6057): "
            "the public Flush(Env::IOPriority) this function calls "
            "with the default IO_TOTAL (writable_file_writer.h:244 "
            "declares the default). Its result is an oracle input "
            "to this model, not computed here.",
            "RE-002-node115-vendor-census: both FDEs are "
            "census-bound (member "
            "a895f7517936a0f7-writable_file_writer.o, librocksdb-sys "
            "0.11.0+8.1.1). Main body 6de1b149... / source "
            "5f209027... (11 relocations, kinds 2/4; zeroing them "
            "reproduces the source hash exactly). Cold body "
            "0f2e32ed... / source 7b132dd1... (6 kind-4 "
            "relocations; zeroing them reproduces the source hash "
            "exactly).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "file/writable_file_writer.cc:432-453 defines Sync "
            "exactly as the binary behaves (seen_error() -> "
            "AssertFalseAndGetStatusForPrevError; s = Flush(); on "
            "failure set_seen_error() and return s; if "
            "(!use_direct_io() && pending_sync_) { s = "
            "SyncInternal(use_fsync); if (!s.ok()) { "
            "set_seen_error(); return s; } }; pending_sync_ = "
            "false; return IOStatus::OK()). "
            "file/writable_file_writer.h:244 declares Flush with "
            "the default Env::IO_TOTAL; :273 defines "
            "use_direct_io() as writable_file_->use_direct_io(); "
            ":286-294 defines seen_error() / set_seen_error() on "
            "the atomic<bool> at this+0x89; :296-301 defines "
            "AssertFalseAndGetStatusForPrevError as "
            "IOStatus::IOError(\"Writer has previous error.\"). "
            "env/file_system_tracer.h:345-383 defines "
            "FSWritableFilePtr (shared_ptr<IOTracer> io_tracer_ "
            "at +0x20, unique_ptr<FSWritableFileTracingWrapper> "
            "fs_tracer_ at +0x30) and its get(): the tracing "
            "wrapper itself when io_tracer_ is set and tracing "
            "is enabled, else fs_tracer_->target(). "
            "include/rocksdb/file_system.h:1052 declares "
            "use_direct_io() (default false) and :1685 the "
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
            "kNoError -- the binary's copies of the Flush and "
            "SyncInternal results zero out byte +0x2 for exactly "
            "that reason, and the move-assign never writes the "
            "destination severity byte at all. The "
            "FSWritableFile vtable order (file_system.h:940-1075) "
            "puts use_direct_io at slot 12 (*0x60 past the "
            "vptr): dtor x2, Append x2, PositionedAppend x2, "
            "Truncate, Close, Flush, Sync, Fsync, "
            "IsSyncThreadSafe (slot 11), then use_direct_io. The "
            "binary matches v8.1.1 step for step.",
            "Binary-vs-source observations (recorded, not hidden): "
            "the vendored WritableFileWriter layout differs from "
            "a stock v8.1.1 compile (checksum_generator_ at "
            "+0xc8, not +0xb0; seen_error_ at +0x89) -- the model "
            "follows the binary offsets, and the layout is "
            "pinned by the two binary anchors (seen_error_ "
            "read at entry and set on Flush/SyncInternal "
            "failure; checksum_generator_ at +0xc8 from the "
            "sibling packets). The 26-char message's second "
            "chunk starts at +0xa (the same chunks as "
            "SyncWithoutFlush). The failure copies leave out "
            "bytes +0x6..+0x7 unwritten (padding) and zero byte "
            "+0x2 (severity reset by the copy ctor). The .cold "
            "FDE holds two cleanup blocks with different targets "
            "(delete the out state_ vs delete the local status's "
            "state_) reached from the two different landing-pad "
            "stubs. DBImpl::Open calls Sync twice (sites "
            "0x5e63cce and 0x5e650c7); the other nine callers "
            "call it once each.",
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
                     "direct-I/O x pending_sync x Flush result x "
                     "SyncInternal result x use_fsync -- x 2 "
                     "seen_error states) + 100 edge (10 base "
                     "combos x 10 conditions: normal, Flush throws, "
                     "use_direct_io throws, SyncInternal throws, "
                     "new[] fails in the IOError path, bad canary "
                     "on return, Flush throw with bad canary, "
                     "SyncInternal throw with bad canary, new[] "
                     "failure with bad canary, empty sync message) "
                     "+ 100 bindings (25 (writer, use_fsync) pairs "
                     "x 4 recorded invariants: body_sha256, "
                     "source_sha256, fde_record, caller_census -- "
                     "each row records the invariant's expected "
                     "value and replay compares it)",
            "tests": "tests/test_sync115.py",
            "tool": "tools/sync115.py",
            "what_is_checked": [
                "checks: a seen_error writer always returns the "
                "26-char IOError regardless of the file state; a "
                "failed Flush sets seen_error_ and returns the "
                "copy with severity reset; a direct-I/O file or a "
                "clear pending_sync_ returns OK without calling "
                "SyncInternal; a pending sync returns the "
                "SyncInternal result with severity reset, and a "
                "non-OK result sets seen_error_ and leaves "
                "pending_sync_ set",
                "edge: a throw from Flush propagates with no "
                "landing pad (out untouched, seen_error "
                "unchanged); a throw from use_direct_io or from "
                "SyncInternal lands in the .cold cleanup at "
                "0x60527cc; a failed new[] in the IOError path "
                "lands in the .cold cleanup at 0x60527a6; a bad "
                "canary becomes StackCheckFailed at the return "
                "check, or in the .cold cleanup instead of "
                "resuming",
                "bindings: the result depends only on the writer "
                "state, the tracer state and the Flush/SyncInternal "
                "oracle results, never on the caller site; each "
                "bindings row records its invariant's expected "
                "value (both FDE body/source hashes, both FDE "
                "records with LSDA pointers, 11-call caller "
                "census) and replay compares it",
            ],
        },
        "engine_callees": {
            "WritableFileWriter::Flush": "Direct call at "
                "0x60528a6 (FDE 0x6051a20..0x605257c, open PR "
                "#6057). The first oracle of this packet: its "
                "result is an input to the model, not computed "
                "here. It takes (out, this, IO_TOTAL) -- the "
                "default argument (writable_file_writer.h:244) "
                "inlined as the constant 4 -- and returns the "
                "IOStatus this function copies (severity reset by "
                "the copy ctor) and, on non-OK, records via "
                "set_seen_error(). Upstream "
                "file/writable_file_writer.cc:325.",
            "WritableFileWriter::SyncInternal": "Direct call at "
                "0x60528ef (FDE 0x604c900..0x604d4a7, .cold "
                "0x604c828..0x604c8f5, census-bound .cold, member "
                "writable_file_writer.o). The second oracle of "
                "this packet: its result is an input to the model, "
                "not computed here. It takes (out, this, "
                "use_fsync) and returns the IOStatus the model "
                "move-assigns into the local status (severity "
                "stays 0) and, on non-OK, records via "
                "set_seen_error(). Upstream "
                "file/writable_file_writer.cc:476-515.",
            "FSWritableFile::use_direct_io": "Virtual call, not a "
                "direct call: the indirect call at 0x60528d3 goes "
                "to vtable slot 12 (*0x60 past the vptr) of the "
                "effective file resolved by "
                "FSWritableFilePtr::get(). The slot is "
                "use_direct_io() const by the FSWritableFile "
                "vtable order in include/rocksdb/file_system.h: "
                "940-1075 (dtor x2, Append x2, PositionedAppend "
                "x2, Truncate, Close, Flush, Sync, Fsync, "
                "IsSyncThreadSafe (slot 11), then use_direct_io; "
                "default returns false, :1052). The tracing "
                "wrapper's override (:1685) forwards to its "
                "target, so the deciding value is the target "
                "file's either way. WritableFileWriter's own "
                "use_direct_io() (writable_file_writer.h:273) is "
                "this call.",
            "operator new[] / operator delete[]": "PLT calls: new "
                "at 0x63f0e30 (once: the 27-byte prev-error "
                "buffer) and delete[] at 0x63f0dc0 (3x in main: "
                "the shared release at 0x6052870 serving both "
                "the prev-error out-state_ release and the "
                "OK-path local-state_ release; the two "
                "move-assign releases at 0x6052939/0x6052948, the "
                "second dead because the source state_ was "
                "already moved out and nulled; plus once in each "
                ".cold cleanup block). A failed new[] throws "
                "BadAlloc into the .cold cleanup (LSDA entry [0]).",
            "__stack_chk_fail / _Unwind_Resume": "PLT calls: "
                "__stack_chk_fail at 0x63f0d70 (bad canary at the "
                "return check, 0x60529d1, and in both .cold "
                "blocks, 0x60527f3/0x60527f8); _Unwind_Resume at "
                "0x63f0a50 (both .cold blocks, 0x60527c7/"
                "0x60527ee).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on "
            "this VM. The target binary is never executed. The "
            "tool models the helper in Python from its whole-FDE "
            "disassembly; Flush (open PR #6057) and SyncInternal "
            "are oracles whose results are inputs to the model. "
            "The live check (--live) reads the binary: both FDE "
            "body hashes, both source hashes (11 + 6 census "
            "relocations), both FDE records (lengths 0x34/0x1c, "
            "ranges 0x1ee/0x57, aug_len 4, LSDA pointers "
            "0x41ea39/0x41ea4d), both LSDA call-site tables (3 + 1 "
            "entries), the 116 + 20 verbatim instructions, the "
            "26-char message byte reconstruction, the 11-call "
            "caller census and the model end-to-end legs. "
            "make verify/test/catalogue-check in a tooled "
            "environment is still owed upstream.",
        "functions": {
            "0x6052800": {
                "body_sha256": tool.BODY_SHA256,
                "callers": [s["site"] for s in sites],
                "census_id": "node115-vendor-6052800",
                "cold_body_sha256": tool.COLD_BODY_SHA256,
                "cold_fde": "0x60527a6..0x60527fd (87 B, body "
                            "0f2e32ed..., source 7b132dd1..., 6 "
                            "kind-4 relocations at offsets 10, 34, "
                            "49, 73, 78, 83; FDE record section "
                            "offset 0x7598f4, length 0x1c, range "
                            "0x57, aug_len 4, LSDA at 0x41ea4d, 1 "
                            "call-site entry, no pad)",
                "cold_source_sha256": tool.COLD_SOURCE_SHA256,
                "lea_refs": [],
                "mangled": tool.SYMBOL,
                "model": "494-byte Sync(bool use_fsync) (sret out "
                         "in rdi, this in rsi, use_fsync in edx; "
                         "0x30 stack frame, canary at rsp+0x28). "
                         "If seen_error_ (this+0x89) is set, return "
                         "IOStatus::IOError(\"Writer has previous "
                         "error.\", code 5). Else call Flush("
                         "IO_TOTAL) at 0x6051a20 into the stack-"
                         "local status at rsp; if its code is "
                         "non-zero, set_seen_error() and return "
                         "the copy. Else resolve the file via "
                         "FSWritableFilePtr::get() (io_tracer_ at "
                         "this+0x20, fs_tracer_ at this+0x30; "
                         "tracing wrapper itself when io_tracer_ "
                         "is set and its +0x68 tracing_enabled "
                         "byte is set, else fs_tracer_->target() "
                         "at wrapper+0x28) and call use_direct_io "
                         "(vtable slot 12, *0x60(%rax)); if true, "
                         "clear pending_sync_ (this+0x88) and "
                         "return OK. Else if pending_sync_ is "
                         "clear, return OK the same way. Else call "
                         "SyncInternal(use_fsync) at 0x604c900 "
                         "into a second stack IOStatus at rsp+0x10, "
                         "move-assign it into the local status "
                         "(severity stays 0), then if its code is "
                         "non-zero, set_seen_error() and return "
                         "the copy; else clear pending_sync_ and "
                         "return OK. 116 instructions main, 20 "
                         "cold; main LSDA 3 entries (pads 0x1d6/"
                         "0x1e2 to the two .cold cleanup blocks); "
                         "cold LSDA 1 entry, no pad.",
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
