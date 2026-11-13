#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
range. The .cold function is census-bound: its body hash matches the
census target_body_sha256 exactly and its source hash is reproduced
by zeroing the recorded relocations (8 relocations, kinds 2/4). The
main function has NO vendor census record (like #5992): body hash
only, source_sha256 empty, raw_equal "n/a", relocations "0",
census_id "none", symbol empty.
"""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BIN = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# (start, end, name, slug, census-bound?)
FUNCS = [
    ("0x6054680", "0x605518b",
     "rocksdb::WritableFileWriter::Append",
     "writable-file-writer-append-6054680", False),
    ("0x6054600", "0x605467c",
     "rocksdb::WritableFileWriter::Append.cold",
     "writable-file-writer-append-cold-6054600", True),
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
        if census_bound:
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
            row = {
                "name": name, "start": start_s, "end": end_s,
                "size": str(end - start), "body_sha256": body_hash,
                "source_sha256": source_hash,
                "raw_equal": str(rec["raw_equal"]),
                "relocations": relocs,
                "census_id": "node115-vendor-%s" % start_s[2:],
                "symbol": rec["symbol"],
                "excerpt": slug + ".objdump.txt", "hex": slug + ".hex",
            }
            functions[start_s] = {
                "body_sha256": body_hash,
                "source_sha256": source_hash,
                "relocations": relocs,
                "census_id": row["census_id"],
                "mangled": rec["symbol"],
                "callers": ["0x605514a"],
                "lea_refs": [],
            }
        else:
            assert start not in by_start, name
            row = {
                "name": name, "start": start_s, "end": end_s,
                "size": str(end - start), "body_sha256": body_hash,
                "source_sha256": "", "raw_equal": "n/a",
                "relocations": "0", "census_id": "none", "symbol": "",
                "excerpt": slug + ".objdump.txt", "hex": slug + ".hex",
            }
            functions[start_s] = {
                "body_sha256": body_hash,
                "source_sha256": "",
                "relocations": "0",
                "census_id": "none",
                "mangled": "",
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
    main_calls = [s for s in sites if s["target"] == "0x6054680"]
    cold_jumps = [s for s in sites if s["target"] == "0x6054600"]
    functions["0x6054680"]["callers"] = [s["site"] for s in main_calls]
    functions["0x6054680"]["model"] = (
        "2827-byte IOStatus Append(const Slice& data, uint32_t "
        "crc32c_checksum, Env::IOPriority priority) (sret 16-byte "
        "out-pointer in rdi, WritableFileWriter* in rsi, &data Slice in "
        "rdx, crc32c in rcx, priority in r8d). Seen-error gate: byte "
        "this+0x89 set -> return IOStatus code 5 'Writer has previous "
        "error.' (27-byte heap state_, old state_ delete[]'d), nothing "
        "else touched. pending_sync_ (this+0x88) = 1. "
        "UpdateFileChecksum(data) at 0x604c7b0 when checksum_generator_ "
        "(this+0xc8) is set (tail-jump to vtable slot 2 = Update). "
        "IOOptions 0x58 B built on the stack at rsp+0x70 with exact "
        "defaults (timeout 0, prio 0 = kIOLow, rate_limiter_priority "
        "IO_TOTAL 4 then overwritten at +0x0c with "
        "DecideRateLimiterPriority, type 7 = kUnknown, empty "
        "property_bag with self-pointer bucket at rsp+0xb8, count 1, "
        "max_load 1.0f, force_dir_fsync 0, do_not_recurse 0), "
        "destroyed via the _Hashtable dtor at 0x5d36110 after "
        "PrepareWrite. DecideRateLimiterPriority (0x604c800, 39 B): "
        "both IO_TOTAL -> IO_TOTAL; file TOTAL -> op; op TOTAL -> "
        "file; else op. TEST_SYNC_POINT gate (global *0x64ed5d0, "
        "RELATIVE reloc to 0x606d9f0, TLS marker helper); perf-level "
        "TLS via _ZTHN7rocksdb10perf_levelE (GLOB_DAT at 0x64ed2b0); "
        "IOSTATS_TIMER_GUARD(prepare_write_nanos) armed iff perf_level "
        "> 2, start = SystemClock::Default()->NowNanos() (vtable slot "
        "20; SystemClock::Default 0x5fe2680), elapsed added to the TLS "
        "counter (iostats+0x48). The CPU-timer half is DEAD: flag "
        "(rsp+0x41), id (rsp+0x44), object (rsp+0x60) are zeroed and "
        "never set. The out-of-line guard dtor 0x604c6b6 does the same "
        "work and is called from .cold only. PrepareWrite: void, "
        "vtable slot 24 (0xc0), args (filesize_, left, io_options, "
        "nullptr); the file is selected by "
        "FSWritableFilePtr::operator-> (tracer null or its +0x68 byte "
        "clear -> the raw file at wrapper+0x28, else the wrapper at "
        "this+0x30). GetIOPriority devirtualization: the guard compares "
        "vtable slot 16 against the RELATIVE reloc at 0x64ecf30 "
        "(addend 0x5df6e90); 0x5df6e90 is 'mov 0x18(%rdi),%eax; ret' = "
        "base FSWritableFile::GetIOPriority, so when equal the binary "
        "reads file+0x18 directly, else it makes the virtual call at "
        "0x6054e90. Buffer growth loop: if capacity-cursize < left, "
        "for cap=capacity; cap<max; cap*=2: desired=min(cap*2,max); if "
        "desired-cursize >= left OR (use_direct_io() AND desired==max): "
        "AllocateNewBuffer(desired, copy_data=true); break. "
        "AllocateNewBuffer inlined at 0x6054e04: skip if copy_data and "
        "desired<cursize; new_capacity=Roundup(desired,alignment); new "
        "char[new_capacity+alignment]; memcpy old bytes; cursize "
        "unchanged. Flush-if-needed: if !use_direct_io() AND "
        "remaining<left AND cursize>0: s=Flush(priority) at 0x6051a20; "
        "if !ok: set_seen_error, return s. Main write, four arms: (a) "
        "verification gate (perform_data_verification_ +0xd1 AND "
        "buffered_data_with_checksum_ +0xd8 AND crc!=0): remaining>=left "
        "-> buf_.Append + Crc32cCombine(old, crc, left) at 0x61c2600 "
        "(single-append uses Combine, NOT Extend); direct-io + "
        "remaining<left -> loop appending min(remaining,left) + "
        "Extend(old,src,appended) via thunk 0x61c25f0 + Flush on "
        "left>0; !direct + remaining<left -> "
        "buffered_data_crc32c_checksum_=crc, then "
        "WriteBufferedWithChecksum(src,left,priority) at 0x604f080. "
        "(b) plain arm: direct-io OR capacity>=left -> loop (append + "
        "conditional Extend + Flush); else direct-write path: "
        "verification+checksum -> checksum=Value(src,left) then "
        "WriteBufferedWithChecksum; else WriteBuffered(src,left,"
        "priority) at 0x604e140. Epilogue: if s.ok(): filesize_ += "
        "data.size() (this+0x70); else set_seen_error(); sret "
        "returned; stack canary checked, __stack_chk_fail on mismatch.")
    functions["0x6054600"]["model"] = (
        "124-byte .cold landing pad, entered from the six endbr64 stubs "
        "at the main FDE tail (0x6055143..0x605518b) that jump here at "
        "0x6054600, 0x6054612, 0x605461f, 0x605463f and 0x605464e (one "
        "tail jump at 0x605514a is the census-validated site): delete[] "
        "the sret status's state_ when non-null, run the out-of-line "
        "timer-guard dtor 0x604c6b6, check the stack canary, then "
        "_Unwind_Resume or __stack_chk_fail. Unwind-only; no case "
        "exercises it.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-log-writer-emit-physical-record-115 "
            "(merged, PR #6012): reconstructs "
            "log::Writer::EmitPhysicalRecord 0x5f03b80, which calls this "
            "routine twice (header Append at 0x5f03c2a with crc arg 0, "
            "payload Append at 0x5f03cae with crc arg payload_crc) and "
            "takes its status as the emit result. That packet took this "
            "body as an input oracle only and named it in its entry as "
            "the natural follow-up. This packet supersedes that input "
            "with the full reconstruction; it is the direct follow-up "
            "the #6012 entry left open.",
            "RE-002-node115-rocksdb-log-writer-emit-physical-record-115 "
            "(merged, PR #6012) and RE-002-node115-log-reader-read-"
            "physical-record-115 (merged, PR #5982): the reader-side "
            "twin -- ReadPhysicalRecord parses exactly the headers "
            "EmitPhysicalRecord writes, and this routine is the writer "
            "that moves those bytes to the file.",
            "RE-002-node115-vendor-census: the .cold function is "
            "census-bound (body hash matches target_body_sha256 "
            "exactly; source hash reproduced by zeroing the recorded "
            "relocations: 8 relocations, offsets 14 kind2; 27, 54, 59, "
            "72, 88, 115, 120 kind4). The main function has NO vendor "
            "census record: body hash only, per the #5992 no-census "
            "convention.",
            "facebook/rocksdb v8.1.1, read live this cycle: "
            "file/writable_file_writer.cc:83-339 (Append), 621-790 "
            "(Flush), 1039-1216 (WriteBuffered), 1219-1394 "
            "(WriteBufferedWithChecksum), 1397-1405 "
            "(UpdateFileChecksum), 1420-1430 "
            "(Crc32cHandoffChecksumCalculation), 1449-1642 "
            "(WriteDirect), 1645-1857 (WriteDirectWithChecksum), "
            "1859-1885 (DecideRateLimiterPriority); "
            "file/writable_file_writer.h (whole file: member order and "
            "AssertFalseAndGetStatusForPrevError returning IOStatus::"
            "IOError(\"Writer has previous error.\")); "
            "include/rocksdb/file_system.h (IOOptions struct, "
            "FSWritableFile class and vtable slots); "
            "env/file_system_tracer.h (FSWritableFilePtr); "
            "trace_replay/io_tracer.h (is_tracing_enabled reads the "
            "plain bool tracing_enabled); util/aligned_buffer.h "
            "(AlignedBuffer layout and AllocateNewBuffer/Append/"
            "PadToAlignmentWith/RefitTail semantics).",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "targets, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "WritableFileWriter::Append 0x6054680: exactly 39 "
                "direct calls, 0 tail jumps, 0 LEA refs. Callers: "
                "BlobLogWriter::WriteHeader (1), EmitPhysicalRecord "
                "(3), AppendFooter (1); log::Writer::EmitPhysicalRecord "
                "x2 (0x5f03c2a header, 0x5f03cae payload); "
                "log::Writer::AddRecord (1); uncatalogued FDE 0x5fce280 "
                "(1); CreateFile (1); CopyFile (1); "
                "PersistRocksDBOptions (8); BlockBasedTableBuilder::"
                "WriteMaybeCompressedBlock (2), WriteFooter (1); "
                "CuckooTableBuilder::Finish (6); PlainTableBuilder::"
                "Finish (5), Add (2); PlainTableKeyEncoder::AppendKey "
                "(4).",
                "WritableFileWriter::Append.cold 0x6054600: exactly 1 "
                "tail jump at 0x605514a (the endbr64 stub at the main "
                "FDE tail). The .cold FDE has 6 endbr64 stubs at the "
                "main-FDE tail (0x6055143..0x605518b) jumping into "
                ".cold at 0x6054600, 0x6054612, 0x605461f, 0x605463f, "
                "0x605464e.",
                "No other caller exists in the binary: every file "
                "write the node makes through a WritableFileWriter "
                "goes through this routine.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 gate (seen-error, checksum generator, "
                     "verification flags, crc zero/nonzero, priorities "
                     "0..4, tracer selection, perf level 0..5, sync "
                     "point, small data 0..64 B) + 600 growth "
                     "(alignment 512/4096, capacity/cursize/max "
                     "combinations pinning the doubling loop, the max "
                     "cap and the direct-io max arm) + 600 write_paths "
                     "(buffered/direct x verification x crc x "
                     "remaining/left x Flush/WriteBuffered scripted "
                     "outcomes x rate limiter x listeners, incl. the "
                     "RangeSync arm with filesize > 1 MiB) + 600 "
                     "bindings (body/source hashes, 40 caller-census "
                     "sites, vtable slots 12/16/24, 29 writer-layout "
                     "offsets, IOOptions defaults, 25-cell priority "
                     "matrix, CRC vectors incl. check vector "
                     "'123456789' -> 0xE3069283, Combine identities, "
                     "AlignedBuffer unit rows, timer-guard thresholds, "
                     "file-selection matrix)",
            "tests": "tests/test_writable_file_writer_append115.py",
            "tool": "tools/writable_file_writer_append115.py",
            "what_is_checked": [
                "gate: seen_error returns code 5 with the 27-byte "
                "heap state_ and writes nothing; empty append sets "
                "pending_sync_ and advances nothing; filesize_ "
                "advances by data.size() on ok; checksum_generator_ "
                "records the UpdateFileChecksum call",
                "growth: no growth when it fits; capacity doubles "
                "(4096 -> 8192 for a 5000 B write); growth stops at "
                "max (no desired size satisfies the loop for a 20000 B "
                "write with max 8192, so capacity stays 4096); the "
                "direct-io max arm grows to max even when the grown "
                "buffer still cannot hold the write; the "
                "AllocateNewBuffer skip guard (copy_data and "
                "desired<cursize) is pinned directly because the "
                "growth loop can never request it",
                "write_paths: a buffered append stays in buf_ and "
                "Flush moves it to the file; the verification single "
                "append Combines (not Extends) the checksum; crc==0 "
                "takes the plain arm but the plain arm still Extends "
                "when both flags are set; the direct-io loop appends "
                "4096 B, Extends, Flushes positionally, and leaves the "
                "904 B tail buffered (Flush pads it to the 4096 B page, "
                "so the physical file is 8192 B); a Flush write "
                "failure sets seen_error_; a WriteBuffered failure "
                "clears the buffer and sets seen_error_; the RangeSync "
                "arm fires with filesize > 1 MiB and bytes_per_sync; a "
                "plain direct write bypasses the buffer entirely",
                "bindings: both body hashes match the binary; the "
                ".cold source hash is reproduced by zeroing the 8 "
                "recorded relocations; the main function has no census "
                "record; the 39 call sites and 1 jump site are pinned; "
                "vtable slots 12/16/24; the 29 writer-layout offsets; "
                "IOOptions defaults (0x58 B image, type 7, "
                "rate_limiter_priority at +0x0c); the 25-cell "
                "DecideRateLimiterPriority matrix; CRC check vector, "
                "Combine == Value(a+b), degenerate Combine len2==0 "
                "== crc1^crc2, Mask/Unmask round-trip; timer guard "
                "armed iff perf_level > 2; file selection raw vs "
                "wrapper",
            ],
        },
        "engine_callees": {
            "0x604c7b0": "WritableFileWriter::UpdateFileChecksum "
                        "(census-bound): tail-jump to checksum_generator_ "
                        "vtable slot 2 = Update when checksum_generator_ "
                        "is set.",
            "0x604c800": "WritableFileWriter::DecideRateLimiterPriority "
                        "(census-bound, 39 B): both IO_TOTAL -> "
                        "IO_TOTAL; file TOTAL -> op; op TOTAL -> file; "
                        "else op. Verified instruction by instruction.",
            "0x604c6b6": "Out-of-line IOSTATS_TIMER_GUARD dtor (no "
                        "census): the same stop work as the inlined "
                        "guard stop, called from .cold only.",
            "0x604e140": "WritableFileWriter::WriteBuffered (no census, "
                        "oracle): writes the data straight to the file, "
                        "clears buf_, resets the buffer checksum, "
                        "advances flushed_size_.",
            "0x604f080": "WritableFileWriter::WriteBufferedWithChecksum "
                        "(no census, oracle): as WriteBuffered, with the "
                        "buffered_data_crc32c_checksum_ passed as the "
                        "handoff checksum.",
            "0x6051a20": "WritableFileWriter::Flush (census-bound, 3452 "
                        "B, oracle): buffered path calls "
                        "WriteBuffered[WithChecksum]; direct path calls "
                        "WriteDirect[WithChecksum] only when "
                        "pending_sync_; then file_->Flush(); then the "
                        "bytes_per_sync RangeSync arm (filesize > 1 MiB).",
            "0x606d9f0": "TEST_SYNC_POINT helper FDE (RELATIVE reloc "
                        "from *0x64ed5d0): the sync-point gate for "
                        "'WritableFileWriter::Append:BeforePrepareWrite'.",
            "0x5df6e90": "Base FSWritableFile::GetIOPriority ('mov "
                        "0x18(%rdi),%eax; ret'): the devirtualization "
                        "guard compares vtable slot 16 against the "
                        "RELATIVE reloc at 0x64ecf30; when equal the "
                        "binary reads file+0x18 directly.",
            "0x5d36110": "std::_Hashtable dtor for the IOOptions "
                        "property_bag, called after PrepareWrite.",
            "0x5fe2680": "SystemClock::Default (census-bound): the "
                        "timer guard's NowNanos() source (vtable slot "
                        "20).",
            "0x61c25f0": "crc32c::Extend 16-byte thunk (jumps through "
                        "the BSS function-pointer slot 0x6508908 to "
                        "ExtendImpl<Slow_CRC32> 0x61c21d0; reconstructed "
                        "in merged RE-002-node115-crc32c-extend-combine-"
                        "115). Called in the direct-io verification "
                        "loop.",
            "0x61c2600": "rocksdb::crc32c::Crc32cCombine (census-bound; "
                        "reconstructed in merged RE-002-node115-crc32c-"
                        "extend-combine-115). Called on the verification "
                        "single-append arm.",
            "0x63f0d70": "PLT __stack_chk_fail (the stack-canary "
                        "failure path in the main epilogue and in .cold).",
            "0x63f0dc0": "PLT operator delete[] _ZdaPv (the seen-error "
                        "gate's delete of the old sret state_ and the "
                        ".cold pad's delete).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this "
                               "VM. The target binary is never executed. "
                               "The tool models the routine in Python; "
                               "the callees WriteBuffered, "
                               "WriteBufferedWithChecksum, Flush and "
                               "UpdateFileChecksum are taken as scripted "
                               "oracles, and the live engine check drives "
                               "the model against a real file and asserts "
                               "the model's file image equals the real "
                               "file bytes after every Append (a real "
                               "file, not the node binary). make verify/"
                               "test/catalogue-check in a tooled "
                               "environment is still owed upstream.",
        "functions": functions,
        "layouts": {
            "writer_0xe0": {
                "+0x00": "file_name_ (std::string, 32 B)",
                "+0x20": "writable_file_ (FSWritableFilePtr: io_tracer_ "
                         "+0x20/+0x28, fs_tracer_ +0x30)",
                "+0x38": "clock_ (SystemClock*, 8)",
                "+0x40": "buf_ (AlignedBuffer: alignment_ +0x40, buf_ "
                         "+0x48, capacity_ +0x50, cursize_ +0x58, "
                         "bufstart_ +0x60)",
                "+0x68": "max_buffer_size_ (size_t, 8)",
                "+0x70": "filesize_ (uint64, 8) -- written: += "
                         "data.size() on ok",
                "+0x78": "flushed_size_ (uint64, 8)",
                "+0x80": "next_write_offset_ (uint64, 8)",
                "+0x88": "pending_sync_ (bool, 1) -- written: = 1 at "
                         "entry",
                "+0x89": "seen_error_ (bool, 1) -- read: the gate",
                "+0x90": "last_sync_size_ (uint64, 8)",
                "+0x98": "bytes_per_sync_ (uint64, 8)",
                "+0xa0": "rate_limiter_ (RateLimiter*, 8)",
                "+0xa8": "stats_ (Statistics*, 8)",
                "+0xb0": "listeners_ (24 B)",
                "+0xc8": "checksum_generator_ "
                         "(FileChecksumGenerator*, 8)",
                "+0xd0": "checksum_finalized_ (bool, 1)",
                "+0xd1": "perform_data_verification_ (bool, 1)",
                "+0xd4": "buffered_data_crc32c_checksum_ (uint32, 4)",
                "+0xd8": "buffered_data_with_checksum_ (bool, 1)",
                "+0xdc": "temperature_ (Temperature, 4)",
            },
            "aligned_buffer": {
                "+0x00": "alignment_ (size_t, 8)",
                "+0x08": "buf_ (char*, 8)",
                "+0x10": "capacity_ (size_t, 8)",
                "+0x18": "cursize_ (size_t, 8)",
                "+0x20": "bufstart_ (char*, 8)",
            },
            "io_options_0x58": {
                "+0x00": "timeout (uint64, 8) -- 0",
                "+0x08": "prio (uint8, 1) -- 0 = kIOLow",
                "+0x0c": "rate_limiter_priority (int, 4) -- "
                         "DecideRateLimiterPriority result",
                "+0x10": "type (uint8, 1) -- 7 = kUnknown",
                "+0x18": "property_bag (unordered_map, 56 B) -- empty, "
                         "self-pointer bucket at rsp+0xb8, count 1, "
                         "max_load 1.0f",
                "+0x50": "force_dir_fsync (bool, 1) -- 0",
                "+0x51": "do_not_recurse (bool, 1) -- 0",
            },
            "status_16": {
                "+0x00": "code (uint8)",
                "+0x01": "subcode (uint8)",
                "+0x02": "severity (uint8)",
                "+0x03": "retryable (uint8)",
                "+0x04": "data_loss (uint8)",
                "+0x05": "scope (uint8)",
                "+0x06..+0x07": "padding",
                "+0x08..+0x0f": "state_ pointer (uint64) -- 0 = null, "
                               "else a heap message",
            },
        },
        "observations": [
            "The seen-error gate is the first thing the body does: "
            "byte this+0x89 set -> IOStatus code 5 with the 27-byte "
            "heap state_ 'Writer has previous error.' (rodata 0x451480 "
            "'Writer has previ' + 0x452bf0 ' previous error.'), the old "
            "sret state_ delete[]'d first, and nothing else touched. "
            "Upstream writable_file_writer.h:555-563 "
            "(AssertFalseAndGetStatusForPrevError) returns exactly "
            "IOStatus::IOError(\"Writer has previous error.\").",
            "The single-append verification arm uses Crc32cCombine, "
            "NOT Extend: buffered_data_crc32c_checksum_ = Combine(old, "
            "crc, left). The direct-io loop arm uses Extend per chunk. "
            "The plain arm Extends too. So the same crc argument is "
            "folded three different ways depending on the arm -- pinned "
            "by the gate/write_paths cases.",
            "The degenerate Combine len2==0 case (crc1^crc2) is live "
            "here: appending 0 bytes with verification on still "
            "changes buffered_data_crc32c_checksum_ to old^crc, because "
            "the binary calls Combine unconditionally with length=left.",
            "The growth loop can never trigger the AllocateNewBuffer "
            "skip guard from Append: desired >= cap >= capacity >= "
            "cursize, so desired < cursize is unreachable. The guard is "
            "pinned by direct AlignedBuffer unit rows instead.",
            "The CPU-timer half of the IOSTATS_TIMER_GUARD is dead: the "
            "flag (rsp+0x41), id (rsp+0x44) and object (rsp+0x60) are "
            "zeroed and never set. Only the wall-clock half runs, and "
            "only when perf_level > 2.",
            "GetIOPriority is devirtualized by a vtable-address "
            "comparison: the guard compares slot 16 against the "
            "RELATIVE reloc at 0x64ecf30 (addend 0x5df6e90, the base "
            "implementation 'mov 0x18(%rdi),%eax; ret'). When equal, "
            "the binary reads file+0x18 directly; otherwise it makes "
            "the virtual call at 0x6054e90.",
            "WriteDirect pads to the page boundary: flushing a 904 B "
            "buffered tail with direct I/O writes 4096 B positionally, "
            "so the physical file is 8192 B for 5000 logical bytes. "
            "Pinned by the direct-io test.",
            "The .cold FDE is entered from six endbr64 stubs at the "
            "main FDE tail (0x6055143..0x605518b); only the jump at "
            "0x605514a is the census-validated site. The stubs are "
            "part of the main FDE, not separate functions.",
            "The IOOptions property_bag is built empty with a "
            "self-pointer bucket: the binary stores rsp+0xb8 at "
            "rsp+0xb8 itself (bucket count 1, max_load 1.0f) and "
            "destroys it via the _Hashtable dtor at 0x5d36110 after "
            "PrepareWrite.",
        ],
        "unknowns": [
            "WriteBuffered, WriteBufferedWithChecksum, Flush and "
            "UpdateFileChecksum are taken as oracles here (their bodies "
            "are separate FDEs: Flush 0x6051a20 is census-bound, the "
            "others have no census record). Their internal steps are "
            "modelled from upstream source, not from their own binary "
            "bodies; reconstructing them is the natural follow-up.",
            "Whether the returned status's bytes 6-7 (padding, never "
            "written by the Append callee's error path) ever matter to "
            "a caller: the 39 callers move the 16-byte status in their "
            "frames right after the call; whether bytes 6-7 are read "
            "was not traced.",
            "The exact .cold entry-point selection (which exception "
            "region uses which of the six stubs at 0x6055143.."
            "0x605518b): the stubs and the pad are pinned, but the LSDA "
            "region mapping was not decoded.",
            "make verify/test/catalogue-check in a tooled environment "
            "is still owed upstream (no cargo/rustc/git-lfs/Ghidra on "
            "this VM).",
        ],
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json (%d caller sites)" % len(sites))
    return rows


if __name__ == "__main__":
    main()
