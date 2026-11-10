#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
range. WriteBuffered itself has NO vendor census record (body hash
only, per the #5992 no-census convention); WriteBuffered.cold IS
census-bound: its body hash matches the census target_body_sha256
exactly and its source hash is reproduced by zeroing the recorded
relocations (14 relocations, kinds 2/4; no kind-42 relocation, so
no GOTPCRELX mov-lea restoration applies).
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
    ("0x604e140", "0x604ef0d",
     "rocksdb::WritableFileWriter::WriteBuffered",
     "writable-file-writer-writebuffered-604e140", False),
    ("0x604e01c", "0x604e139",
     "rocksdb::WritableFileWriter::WriteBuffered.cold",
     "writable-file-writer-writebuffered-cold-604e01c", True),
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
                if rel.get("relaxation") == "gotpcrelx-mov-lea":
                    # GOTPCRELX relaxation: the linker rewrote the
                    # source's MOV (0x8B) into a LEA (0x8D); restore
                    # the MOV opcode before hashing. .cold has no
                    # kind-42 relocation, so this never fires here.
                    assert zeroed[o - 2] == 0x8D
                    zeroed[o - 2] = 0x8B
            source_hash = hashlib.sha256(bytes(zeroed)).hexdigest()
            assert source_hash == rec["source_body_sha256"], name
            relocs = ";".join(
                "%d:kind%d%s" % (r["offset"], r["kind"],
                                 "(mov-lea)" if r.get("relaxation")
                                 == "gotpcrelx-mov-lea" else "")
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
                "callers": [],
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
    main_calls = [s for s in sites if s["target"] == "0x604e140"]
    cold_jumps = [s for s in sites if s["target"] == "0x604e01c"]
    functions["0x604e140"]["callers"] = [s["site"] for s in main_calls]
    functions["0x604e01c"]["callers"] = [s["site"] for s in cold_jumps]
    functions["0x604e140"]["model"] = (
        "3533-byte IOStatus WriteBuffered(const char* data, size_t "
        "size, Env::IOPriority priority) (sret 16-byte out-pointer "
        "in rdi, WritableFileWriter* in rsi, data in rdx, size in "
        "rcx, priority in r8d). Seen-error gate (0x604e17a): byte "
        "this+0x89 set -> return IOStatus code 5 'Writer has "
        "previous error.' (27-byte heap state_, old sret state_ "
        "delete[]'d first), nothing else touched. IOOptions + file "
        "priority (0x604e18d..0x604e26b): the file's GetIOPriority "
        "(vtable slot 16, devirtualized when the slot equals the "
        "RELATIVE reloc at 0x64ecf30, else the virtual call at "
        "0x604ee59) feeds DecideRateLimiterPriority (0x604c800, "
        "census-bound, pure) with the op priority; a 0x58-byte "
        "IOOptions is built on the stack with the exact defaults "
        "(timeout 0, prio kIOLow 0, rate_limiter_priority the Decide "
        "result, type kUnknown 7, property_bag an empty "
        "unordered_map, force_dir_fsync 0, do_not_recurse 0). "
        "Zero-size short-circuit (0x604e26b -> 0x604ee85): size 0 "
        "returns OK at once (code 0, empty state_) -- but "
        "buf_.cursize_ is still cleared to 0 and "
        "buffered_data_crc32c_checksum_ reset to 0 (0x604e7cd). "
        "Chunk loop (0x604e2b0 back-edge, while remaining > 0): "
        "(a) rate-limiter grant -- when rate_limiter_ (this+0xa0) "
        "is non-null AND the decided priority != IO_TOTAL (4), "
        "granted = rate_limiter_->RequestToken(remaining, alignment "
        "0, decided priority, stats_ (this+0xa8), OpType kWrite = "
        "1) through vtable slot 6 (base impl 0x61c43f0, "
        "census-bound); otherwise granted = remaining (0x604e850). "
        "(b) TEST_SYNC_POINT #1 (0x604e2ec) and the nanos-guard "
        "setup: armed iff perf_level > 2 (clock = "
        "*SystemClock::Default() 0x5fe2680, dereferenced once; "
        "start = NowNanos, vtable slot 20). (c) "
        "file->GetFileSize(io_options, nullptr) (0x604e3c5, vtable "
        "slot 18) -- the uint64 return is DISCARDED by the caller "
        "(stored to a stack slot the listener-event path overwrites "
        "with next_write_offset_ before any read); the method is "
        "identified by its signature plus the "
        "FSWritableFileTracingWrapper::GetFileSize symbol "
        "(0x600a770, census-bound), but why upstream calls it here "
        "is an open unknown. (d) Listener start times (0x604e3d0): "
        "only when listeners_ (this+0xb0) is non-empty, "
        "steady_clock::now() + system_clock::now(); "
        "next_write_offset_ is saved for the event. (e) perf_level "
        "save (0x604e40f): GetPerfLevel() (0x606ddd0) reads the TLS "
        "byte; restored after the Append (0x604e5d0, 0x606ddb0). "
        "(f) TEST_SYNC_POINT #2 (0x604e414) and the CPU-guard "
        "setup: armed iff perf_level > 3 (clock = this->clock_ or "
        "Default() when null; start = the CPU-time accessor, "
        "vtable slot 22). (g) Checksum dispatch (0x604e4c0): when "
        "perform_data_verification_ (this+0xd1) is set, the chunk "
        "CRC is computed by the 19-byte helper at 0x604c7e0 -- crc "
        "= crc32c::Extend(0, data, granted) through the 0x61c25f0 "
        "dispatch thunk, written to a 4-byte stack buffer -- and "
        "file->Append(Slice{data, granted}, io_options, "
        "Slice{&crc, 4}, nullptr) is called (vtable slot 3, "
        "0x604e999); otherwise file->Append(Slice{data, granted}, "
        "io_options, nullptr) (vtable slot 2, 0x604e520). Both "
        "return IOStatus by value into a 16-byte sret at rsp+0xa0. "
        "(h) On a non-OK Append status (0x604e5b9): buf_.cursize_ "
        "is cleared to 0 and buffered_data_crc32c_checksum_ reset "
        "to 0 at once. (i) perf_level restore (0x604e5d0). (j) "
        "CPU-guard stop (0x604ea60): the CPU-time accessor is "
        "called whenever the guard started; the TLS counter at "
        "fs-0x3f8+0x58 advances by the elapsed time only when "
        "perf_level > 3 (re-checked). (k) Listener events "
        "(0x604e5de..0x604e740, 0x604eae8..): only when listeners_ "
        "is non-empty. Finish event (always): {FileOperationType "
        "type = 1 (kWrite), WritableFileWriter* this, bool "
        "[this+0xd9], uint64 offset = next_write_offset_, uint64 "
        "length = granted, uint64 elapsed_nanos, TimePoint* "
        "&start_times, Status status (CopyState deep copy at "
        "0x61cf610)} through vtable slot 34 (0x110), skipping the "
        "base no-op 0x604c660. Failure event (only when the Append "
        "status is not OK): {Status status (CopyState deep copy), "
        "FileOperationType type = 8, std::string file_name_, uint64 "
        "granted, uint64 next_write_offset_} through vtable slot 47 "
        "(0x178), skipping the base no-op 0x6042c20. The failure "
        "type 8 is FileOperationType::kAppend (v8.1.1 "
        "listener.h:236-248) -- exactly upstream NotifyOnIOError(s, "
        "kAppend, file_name(), allowed, old_size); the trailing u64s "
        "(granted, next_write_offset_) are the (allowed, old_size) "
        "arguments. This resolves the open unknown the prior draft "
        "recorded; the model emits 8 exactly as the binary does. (l) Failure "
        "return (0x604e9b0): seen_error_ = 1 AFTER the "
        "notifications; the sret is built (byte 2 forced to 0); "
        "the nanos guard stops at 0x604e9fd; no retry, no further "
        "chunks; flushed_size_ is NOT advanced for the failed "
        "chunk. (m) Success path: nanos-guard stop (0x604eaa0, "
        "elapsed -> the TLS counter at fs-0x3f8+0x28), TEST_SYNC_"
        "POINT #3 (0x604e767), then -- when the TLS flag at "
        "fs-0x3f8+0x98 is clear -- TEST_SYNC_POINT #4 (0x604e78f) "
        "and the TLS counter at fs-0x3f8+0x8 advances by the "
        "granted bytes (the flag's identity is an open unknown). "
        "(n) Advance (0x604e7b2..0x604e7c7): data += granted, "
        "flushed_size_ (this+0x78) += granted, remaining -= "
        "granted; loop while remaining != 0. Epilogue (0x604e7cd): "
        "buf_.cursize_ = 0, buffered_data_crc32c_checksum_ = 0, "
        "the working status is copied into the sret (byte 2 forced "
        "to 0), the IOOptions property_bag is destroyed "
        "(0x5d36110), the stack canary is checked and "
        "__stack_chk_fail fires on mismatch.")
    functions["0x604e01c"]["model"] = (
        "285-byte .cold landing pad, entered by the single tail jump "
        "at 0x604eeae (one of the ten endbr64 stubs at the main FDE "
        "tail, 0x604eea7..0x604ef07): delete[] the sret state_ when "
        "non-null, destroy the failure-event strings, stop both "
        "timer guards through the shared destructor 0x604c6b6, "
        "destroy the IOOptions property_bag, check the stack "
        "canary, then _Unwind_Resume or __stack_chk_fail. "
        "Unwind-only; no case exercises it.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-writable-file-writer-flush-115 "
            "(open, PR #6057): reconstructs WritableFileWriter::Flush "
            "0x6051a20, which calls WriteBuffered at 0x6051cc5 "
            "(verified by this packet's caller census) and which "
            "took WriteBuffered as an input oracle, leaving it as "
            "the direct follow-up. This packet supersedes that "
            "oracle note with the full body model.",
            "RE-002-node115-rocksdb-writable-file-writer-append-115 "
            "(open, PR #6041): reconstructs WritableFileWriter::Append "
            "0x6054680, which calls WriteBuffered at 0x6054d23 "
            "(verified by this packet's caller census) -- two call "
            "sites in its write loop take WriteBuffered as their "
            "engine callee -- and pins the same 0xe0 writer layout, "
            "the same seen-error gate (code 5, 27-byte heap state_) "
            "and the same sret move-assign shape.",
            "RE-002-node115-rocksdb-writable-file-writer-pad-115 "
            "(open, PR #6070): reconstructs WritableFileWriter::Pad "
            "0x60525b0, which reaches WriteBuffered through Flush; "
            "its tool and packet scaffolding are the template for "
            "this packet.",
            "RE-002-node115-vendor-census: WriteBuffered itself has "
            "NO census record (body hash only, per the #5992 "
            "no-census convention); WriteBuffered.cold IS "
            "census-bound (body hash matches target_body_sha256 "
            "exactly; source hash reproduced by zeroing the 14 "
            "recorded relocations, kinds 2/4; no kind-42 "
            "relocation, so no GOTPCRELX restoration applies).",
            "facebook/rocksdb v8.1.1, read live this cycle: "
            "file/writable_file_writer.cc WriteBuffered (lines "
            "1040-1217) confirms the packet step for step -- the "
            "seen-error gate (AssertFalseAndGetStatusForPrevError), "
            "the IOOptions build with DecideRateLimiterPriority, "
            "the rate-limiter grant loop, the TEST_SYNC_POINT "
            "gates, the IOSTATS_TIMER_GUARD halves, the "
            "GetFileSize call, the listener start times and the "
            "perf-level save/restore, the checksum dispatch "
            "(AppendWithChecksum vs Append), the failure path "
            "(buf clear, checksum reset, seen_error_ after the "
            "notifications), and the epilogue. CORRECTION: the "
            "prior draft cited lines 124-196 -- that range is "
            "inside Append; WriteBuffered is 1040-1217 (verified "
            "against the raw v8.1.1 file this cycle; an earlier "
            "in-PR correction citing 544-636 was itself wrong -- "
            "that range is inside Close/Flush -- and was fixed "
            "while cross-checking PR #6094). RESOLVED this cycle: "
            "the failure event type 8 "
            "is FileOperationType::kAppend "
            "(include/rocksdb/listener.h:236-248, implicit 0-based: "
            "kRead 0, kWrite 1, kTruncate 2, kClose 3, kFlush 4, "
            "kSync 5, kFsync 6, kRangeSync 7, kAppend 8) -- exactly "
            "upstream NotifyOnIOError(s, kAppend, file_name(), "
            "allowed, old_size); the finish event 1 = kWrite, "
            "Flush's failure event 4 = kFlush, RangeSync's 7 = "
            "kRangeSync, all from the same enum. Binary-vs-source "
            "observations, recorded not hidden: the GetFileSize "
            "return is discarded by the caller even though the "
            "call is made every chunk (upstream overwrites old_size "
            "with next_write_offset_ when listeners exist); the "
            "binary has a separate zero-size branch (0x604e26b -> "
            "0x604ee85) while upstream has none -- the while loop "
            "is simply skipped and the epilogue clears buf_ and "
            "resets the checksum, same observable behaviour; "
            "upstream's post-loop 'if (!s.ok()) set_seen_error()' "
            "is unreachable in practice (failures return early "
            "in-loop) and has no counterpart in the binary "
            "epilogue; upstream's assert(!use_direct_io()) is "
            "compiled out; upstream names the loop's TEST_SYNC_POINT "
            "'WritableFileWriter::Flush:BeforeAppend' and the "
            "success-path kill point 'WritableFileWriter::WriteBuffered:0' "
            "(TEST_KILL_RANDOM), while the binary's string literals "
            "are stripped, so per-site names are not pinned from "
            "the binary.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "targets, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "WritableFileWriter::WriteBuffered 0x604e140: exactly "
                "2 direct calls, 0 tail jumps, 0 LEA refs. The "
                "callers are rocksdb::WritableFileWriter::Flush "
                "0x6051a20..0x605257c (call site 0x6051cc5) and "
                "rocksdb::WritableFileWriter::Append 0x6054680.."
                "0x605518b (call site 0x6054d23) -- the two members "
                "whose packets took WriteBuffered as an input oracle. "
                "No other caller exists in the whole .text.",
                "WritableFileWriter::WriteBuffered.cold 0x604e01c: "
                "exactly 1 tail jump at 0x604eeae (the endbr64 stub "
                "at the main FDE tail) -- the exception landing-pad "
                "entry. No call sites. (The main FDE tail holds ten "
                "endbr64 stubs at 0x604eea7..0x604ef07; the census "
                "validates the one that jumps to .cold.)",
                "WriteBuffered calls file->Append (vtable slots 2/3) "
                "and file->GetFileSize (vtable slot 18) through the "
                "file pointer, not by direct call -- so no direct "
                "call sites for those appear in the scan; the slot "
                "numbers are pinned by the disassembly and the "
                "bindings group. WriteBuffered calls no other "
                "WritableFileWriter member directly: no Flush, Pad, "
                "RangeSync or WriteDirect call exists in the FDE.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 gate (seen-error, zero/non-zero size, entry "
                     "cursize/capacity, verification flags, priorities "
                     "0..4, tracer selection, perf level 0..5, sync "
                     "point, clock pairs, flag_d9, file names, "
                     "scripted Append failures, iostats flag) + "
                     "600 grant_loop (the chunking matrix: size vs "
                     "the scripted rate-limiter grants -- single "
                     "chunk, exact split, grant exhaustion, tiny "
                     "grants -- Append failures on the 2nd/3rd chunk, "
                     "listeners + both guards armed, iostats flag, "
                     "file image pre-filled) + 600 checksum "
                     "(perform_data_verification on/off x sizes x "
                     "grant splits -- the per-chunk crc32c::Value "
                     "pinned in the file_append events -- plus "
                     "Append failures with verification on and the "
                     "zero-size reset) + 600 bindings (body hashes "
                     "for WriteBuffered, .cold, Flush, "
                     "WriteBufferedWithChecksum, WriteDirect, "
                     "WriteDirectWithChecksum, RangeSync, Append, "
                     "DecideRateLimiterPriority, UpdateFileChecksum, "
                     "the CRC value helper, the timer-guard "
                     "destructor; seven census records; 3 "
                     "caller-census sites; vtable slots 2/3/16/18/34/"
                     "35/37/47; 30 writer-layout offsets; IOOptions "
                     "defaults; 25-cell priority matrix; "
                     "FileOperationType 1/4/7/8; WriteBuffered "
                     "call-site constants; CRC vectors incl. check "
                     "vector '123456789' -> 0xE3069283, Combine "
                     "identities, AlignedBuffer unit rows, "
                     "write_zeros rows, timer-guard thresholds for "
                     "both halves, file-selection matrix)",
            "tests": "tests/test_writable_file_writer_writebuffered115.py",
            "tool": "tools/writable_file_writer_writebuffered115.py",
            "what_is_checked": [
                "gate: seen_error returns code 5 with the 27-byte "
                "heap state_ and writes nothing; zero-size returns "
                "OK but still clears buf_ and resets the buffer "
                "checksum; a single chunk needs no limiter; a "
                "decided IO_TOTAL priority skips RequestToken even "
                "when a limiter exists; tracer selection picks the "
                "raw file vs the tracing wrapper; the file image "
                "pre-fill is visible to GetFileSize (recorded, "
                "discarded)",
                "grant_loop: the chunking matrix is replayed exactly "
                "(grant sizes, chunk counts, file bytes, cursize_, "
                "flushed_size_, wb_grants, wb_append_calls, "
                "wb_get_file_size_calls); an Append failure on the "
                "2nd/3rd chunk keeps the earlier chunks' advance, "
                "does not advance flushed_size_ for the failed "
                "chunk, sets seen_error_ after the notifications, "
                "and stops the loop; grant exhaustion falls back to "
                "granted = remaining for the tail chunk",
                "checksum: verification off calls the plain Append "
                "slot 2 with no checksum; verification on calls the "
                "checksum Append slot 3 with crc32c::Value(chunk) "
                "per chunk -- a fresh Value from 0, not a running "
                "checksum; an Append failure with verification on "
                "clears buf_ and resets the checksum at once; "
                "zero-size with verification on still resets the "
                "checksum to 0",
                "bindings: all twelve FDE body hashes match the "
                "binary; the .cold source hash is reproduced by "
                "zeroing its 14 recorded relocations; the 2 call "
                "sites and 1 jump site are pinned; vtable slots 2/3/"
                "16/18 and the listener slots 34/35/37/47; the 30 "
                "writer-layout offsets incl. the unnamed bool at "
                "+0xd9; IOOptions defaults (0x58 B image, type 7, "
                "rate_limiter_priority at +0x0c); the 25-cell "
                "DecideRateLimiterPriority matrix; FileOperationType "
                "kWrite 1 / kFlush 4 / kRangeSync 7 and the observed "
                "failure type 8; the four TEST_SYNC_POINT sites; the "
                "timer-guard thresholds (nanos armed iff perf_level "
                "> 2, CPU armed iff perf_level > 3); CRC check "
                "vector, Combine == Value(a+b), Mask/Unmask "
                "round-trip; file selection raw vs wrapper",
            ],
        },
        "engine_callees": {
            "0x6051a20": "WritableFileWriter::Flush (census-bound, "
                        "2908 B + 228 B .cold): the oracle this packet "
                        "uses for the live check's final flush; it "
                        "calls WriteBuffered at 0x6051cc5. "
                        "Implemented here at the #6057 fidelity: "
                        "buffered/direct write step, listener start "
                        "times + finish/failure events, IOOptions with "
                        "DecideRateLimiterPriority, file_->Flush, and "
                        "the RangeSync arm.",
            "0x6054680": "WritableFileWriter::Append (census-bound, "
                        "2827 B + 124 B .cold): the oracle whose write "
                        "loop calls WriteBuffered at 0x6054d23. "
                        "Implemented here at the #6041 fidelity.",
            "0x604f080": "WritableFileWriter::WriteBufferedWithChecksum "
                        "(no census, oracle): as WriteBuffered, with the "
                        "buffered_data_crc32c_checksum_ passed as the "
                        "handoff checksum.",
            "0x604fe80": "WritableFileWriter::WriteDirect (no census, "
                        "oracle): page-pads the buffer, writes it "
                        "positionally, refits the tail.",
            "0x6050c80": "WritableFileWriter::WriteDirectWithChecksum "
                        "(no census, oracle): as WriteDirect, with the "
                        "buffered checksum recomputed as Value of the "
                        "remaining buffer.",
            "0x604d7b0": "WritableFileWriter::RangeSync (no census, "
                        "oracle): the member the Flush oracle's arm "
                        "calls; own seen-error gate, TEST_SYNC_POINT, "
                        "timer guard, listener events, file->RangeSync "
                        "slot 23.",
            "0x604c800": "WritableFileWriter::DecideRateLimiterPriority "
                        "(census-bound, 39 B): both IO_TOTAL -> "
                        "IO_TOTAL; file TOTAL -> op; op TOTAL -> file; "
                        "else op. Called by the WriteBuffered IOOptions "
                        "build (0x604e1c3) and by the Flush oracle.",
            "0x604c7e0": "The 19-byte CRC value helper (no census): "
                        "xor edi,edi; call 0x61c25f0 -- crc32c::Extend"
                        "(0, data, size), the per-chunk CRC the "
                        "checksum dispatch writes to a 4-byte stack "
                        "buffer before the slot-3 Append.",
            "0x61c25f0": "crc32c::Extend dispatch thunk: the CRC "
                        "helper calls it as Extend(0, data, size). "
                        "Resolves to ExtendImpl<Slow_CRC32> 0x61c21d0 "
                        "per the #6012 packet; the table-driven Python "
                        "Extend is bit-identical to the slow path.",
            "0x61c43f0": "RateLimiter::RequestToken (base impl, "
                        "census-bound, 359 B): the virtual call the "
                        "grant step makes through vtable slot 6 with "
                        "(remaining, alignment 0, decided priority, "
                        "stats_, OpType kWrite = 1). The model takes "
                        "the granted count from the scripted limiter "
                        "oracle; the base impl's own body is not "
                        "reconstructed here.",
            "0x5fe2680": "SystemClock::Default (census-bound, 214 B): "
                        "returns the default clock handle; the binary "
                        "dereferences it once (mov r15,[rax] at "
                        "0x604e871, mov r13,[rax] at 0x604ed35) to get "
                        "the clock object used by both timer-guard "
                        "halves.",
            "0x600a770": "FSWritableFileTracingWrapper::GetFileSize "
                        "(census-bound, 1208 B): the tracing wrapper's "
                        "GetFileSize(const IOOptions&, IODebugContext*) "
                        "-- the signature match that identifies the "
                        "slot-18 call at 0x604e3c5.",
            "0x604c6b6": "IOSTATS_TIMER_GUARD destructor (no census, "
                        "82 B): dispatches on the guard's cpu-flag "
                        "byte (+1): 0 -> NowNanos (slot 20), 1 -> the "
                        "CPU-time accessor (slot 22); adds the elapsed "
                        "time to the guard's counter when the armed "
                        "flag (+0) is set; calls the second clock's "
                        "CPU-time accessor with the guard id when the "
                        "second clock (+0x20) is non-null (null in "
                        "WriteBuffered). Runs only from .cold (unwind); "
                        "the main-FDE stops are inline.",
            "0x61cf610": "Status state_ deep copy (census-bound, 63 "
                        "B; the census labels it Status::CopyState, "
                        "but the call sites pass (dst, src) -- a "
                        "two-argument store form, so the name is "
                        "recorded as an open unknown): allocates a "
                        "copy of the source C-string and stores the "
                        "new pointer at *dst. Used for the status in "
                        "both listener events.",
            "0x606ddd0": "GetPerfLevel (no census): reads the TLS "
                        "perf_level byte (fs:0-0x10b0) saved at "
                        "0x604e40f and restored after the Append.",
            "0x606ddb0": "SetPerfLevel (no census): writes the TLS "
                        "perf_level byte at 0x604e5d0 (the restore).",
            "0x606d9f0": "TEST_SYNC_POINT helper (no census): the "
                        "sync-point gate, called from the four sites "
                        "0x604e2ec, 0x604e414, 0x604e767, 0x604e78f "
                        "when the sync-point global *0x64ed5d0 is "
                        "non-null. The string names are not asserted.",
            "0x604c660": "Base EventListener no-op skipped by the "
                        "write-finish notification (vtable slot 34).",
            "0x604c670": "Base EventListener no-op skipped by the "
                        "flush-finish notification (vtable slot 35).",
            "0x604c690": "Base EventListener no-op skipped by the "
                        "range-sync-finish notification (vtable slot "
                        "37).",
            "0x6042c20": "Base EventListener no-op skipped by the "
                        "failure notification (vtable slot 47, shared "
                        "by WriteBuffered, Flush and RangeSync).",
            "0x5df6e90": "Base FSWritableFile::GetIOPriority ('mov "
                        "0x18(%rdi),%eax; ret'): the devirtualization "
                        "guard compares vtable slot 16 against the "
                        "RELATIVE reloc at 0x64ecf30; when equal the "
                        "binary reads file+0x18 directly.",
            "0x5d36110": "std::_Hashtable dtor for the IOOptions "
                        "property_bag, called on every WriteBuffered "
                        "exit path (zero-size, success epilogue, "
                        "failure return).",
            "0x63f0d70": "PLT __stack_chk_fail (the stack-canary "
                        "failure path in the main epilogue and in .cold).",
            "0x63f0dc0": "PLT operator delete[] _ZdaPv (the seen-error "
                        "gate's delete of the old sret state_, the "
                        "working-status state_ delete after each Append "
                        "return, and the .cold deletes).",
            "0x63f0e30": "PLT operator new[] _Znam (the 27-byte heap "
                        "state_ in the seen-error gate).",
            "0x63f0a50": "PLT _Unwind_Resume (the .cold landing pad).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this "
                               "VM. The target binary is never executed. "
                               "The tool models the routine in Python; "
                               "the callees Flush, Append, "
                               "WriteBufferedWithChecksum, WriteDirect, "
                               "WriteDirectWithChecksum, RangeSync and "
                               "the file's Flush/RangeSync/Append/"
                               "GetFileSize are taken as scripted "
                               "oracles, and the live engine check "
                               "drives the model against a real file "
                               "and asserts the model's file image "
                               "equals the real file bytes after every "
                               "WriteBuffered (a real file, not the node "
                               "binary). make verify/test/catalogue-check "
                               "in a tooled environment is still owed "
                               "upstream.",
        "functions": functions,
        "layouts": {
            "writer_0xe0": {
                "+0x00": "file_name_ (std::string, 32 B) -- copied "
                         "into the failure event",
                "+0x20": "writable_file_ (FSWritableFilePtr: io_tracer_ "
                         "+0x20/+0x28, fs_tracer_ +0x30) -- the file "
                         "selection reads io_tracer_ (null or +0x68 "
                         "clear -> raw file at wrapper+0x28, else the "
                         "tracing wrapper at this+0x30)",
                "+0x38": "clock_ (SystemClock*, 8) -- the CPU-guard "
                         "clock when non-null, else Default()",
                "+0x40": "buf_ (AlignedBuffer: alignment_ +0x40, buf_ "
                         "+0x48, capacity_ +0x50, cursize_ +0x58, "
                         "bufstart_ +0x60) -- read: nothing (only "
                         "cleared); written: cursize_ = 0 on every "
                         "exit path",
                "+0x58": "buf_.cursize_ (size_t, 8) -- written: = 0 "
                         "on the zero-size path, on a failed Append, "
                         "and in the epilogue",
                "+0x68": "max_buffer_size_ (size_t, 8) -- not read",
                "+0x70": "filesize_ (uint64, 8) -- not read or "
                         "written here (the file's own size is queried "
                         "per chunk via GetFileSize and discarded)",
                "+0x78": "flushed_size_ (uint64, 8) -- written: += "
                         "granted per successful chunk (NOT advanced "
                         "for a failed chunk)",
                "+0x80": "next_write_offset_ (uint64, 8) -- read: "
                         "into both listener events",
                "+0x88": "pending_sync_ (bool, 1) -- not read or "
                         "written here",
                "+0x89": "seen_error_ (bool, 1) -- read: the gate "
                         "(first read in the FDE); written: = 1 on a "
                         "failed Append, after the notifications",
                "+0x90": "last_sync_size_ (uint64, 8) -- not read",
                "+0x98": "bytes_per_sync_ (uint64, 8) -- not read",
                "+0xa0": "rate_limiter_ (RateLimiter*, 8) -- read: "
                         "the grant step (null -> granted = remaining)",
                "+0xa8": "stats_ (Statistics*, 8) -- passed to "
                         "RequestToken",
                "+0xb0": "listeners_ (24 B) -- read: empty or not "
                         "(ShouldNotifyListeners); the events iterate "
                         "it",
                "+0xc8": "checksum_generator_ "
                         "(FileChecksumGenerator*, 8) -- NOT read by "
                         "WriteBuffered (UpdateFileChecksum is the "
                         "member that uses it)",
                "+0xd0": "checksum_finalized_ (bool, 1) -- not read",
                "+0xd1": "perform_data_verification_ (bool, 1) -- "
                         "read: the checksum-dispatch gate",
                "+0xd4": "buffered_data_crc32c_checksum_ (uint32, 4) "
                         "-- written: = 0 on the zero-size path, on "
                         "a failed Append, and in the epilogue",
                "+0xd8": "buffered_data_with_checksum_ (bool, 1) -- "
                         "NOT consulted by WriteBuffered",
                "+0xd9": "UNNAMED bool (1) -- read into the finish "
                         "event; not named by the Append layout; open "
                         "unknown",
                "+0xdc": "temperature_ (Temperature, 4) -- not read",
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
                "+0x0c": "rate_limiter_priority (int, 4) -- the "
                         "DecideRateLimiterPriority result",
                "+0x10": "type (uint8, 1) -- 7 = kUnknown",
                "+0x18": "property_bag (unordered_map, 56 B) -- empty, "
                         "self-pointer bucket, count 1, max_load 1.0f",
                "+0x50": "force_dir_fsync (bool, 1) -- 0",
                "+0x51": "do_not_recurse (bool, 1) -- 0",
            },
            "write_buffered_chunk": {
                "grant": "RequestToken(remaining, 0, decided, stats_, "
                         "kWrite) when rate_limiter_ non-null and "
                         "decided != IO_TOTAL; else granted = remaining",
                "nanos_guard": "armed iff perf_level > 2; clock = "
                               "*SystemClock::Default(); start = "
                               "NowNanos (slot 20); counter at "
                               "fs-0x3f8+0x28; stops inline at "
                               "0x604eaa0 (success) / 0x604e9fd "
                               "(failure, after the sret build)",
                "cpu_guard": "armed iff perf_level > 3; clock = "
                             "clock_ or Default(); start = the CPU-time "
                             "accessor (slot 22); counter at "
                             "fs-0x3f8+0x58; stops inline at 0x604ea60 "
                             "(before the events, both paths)",
                "get_file_size": "file->GetFileSize(io_options, "
                                 "nullptr) (slot 18); return discarded",
                "append": "slot 3 with Slice{&crc32c::Extend(0, "
                          "chunk), 4} when verification on; slot 2 "
                          "plain otherwise",
                "failure": "buf_.cursize_ = 0; checksum = 0; perf "
                           "restore; CPU stop; finish + failure "
                           "events; seen_error_ = 1; nanos stop; "
                           "return status (byte 2 = 0)",
                "success": "finish event; nanos stop; sync-point #3; "
                           "sync-point #4 + bytes counter += granted "
                           "(flag clear); flushed_size_ += granted; "
                           "remaining -= granted; loop",
            },
            "status_16": {
                "+0x00": "code (uint8)",
                "+0x01": "subcode (uint8)",
                "+0x02": "severity (uint8) -- forced to 0 on every "
                         "WriteBuffered return path (gate, failure "
                         "return, OK epilogue)",
                "+0x03": "retryable (uint8)",
                "+0x04": "data_loss (uint8)",
                "+0x05": "scope (uint8)",
                "+0x06..+0x07": "padding",
                "+0x08..+0x0f": "state_ pointer (uint64) -- 0 = null, "
                               "else a heap message",
            },
        },
        "observations": [
            "The two timer-guard halves stop asymmetrically: the CPU "
            "guard stops at 0x604ea60 BEFORE the listener events on "
            "both paths, while the nanos guard stops AFTER the "
            "events -- at 0x604eaa0 on the success path and at "
            "0x604e9fd (after the sret build) on the failure path. "
            "The shared destructor 0x604c6b6 runs only from .cold "
            "(unwind); the main-FDE stops are inline calls to the "
            "clock methods. The model follows this order exactly, "
            "including that a failed chunk's nanos elapsed time is "
            "still recorded (failure-path stop) but its bytes are "
            "never added to the IOStats counter.",
            "Four TEST_SYNC_POINT gates fire per successful chunk "
            "(0x604e2ec, 0x604e414, 0x604e767, 0x604e78f), all "
            "through the helper 0x606d9f0 when the sync-point global "
            "*0x64ed5d0 is non-null. The fourth gate fires only when "
            "the IOStats-bytes flag is clear -- it sits between the "
            "flag check and the bytes add. The string names are not "
            "asserted; the model records the site addresses.",
            "file->GetFileSize is called once per chunk and its "
            "return is discarded: the uint64 is stored to a stack "
            "slot ([rsp+0x20]) that the listener-event path "
            "overwrites with next_write_offset_ before any read "
            "(verified by grepping all [rsp+0x20] reads: only "
            "0x604e6db and 0x604ec5f, both in event construction "
            "after the overwrite). The method is identified by its "
            "signature plus the FSWritableFileTracingWrapper::"
            "GetFileSize symbol (0x600a770); why upstream calls it "
            "here is open.",
            "The checksum is a fresh crc32c::Value per chunk, not a "
            "running checksum: the helper at 0x604c7e0 computes "
            "Extend(0, data, granted) for each chunk independently, "
            "so a multi-chunk write with verification on produces "
            "one Value per chunk. The live check pins this (grants "
            "[5, 6] over 'hello world' give Value('hello') and "
            "Value(' world')).",
            "The zero-size path is a clearing write: it returns OK "
            "but still clears buf_.cursize_ and resets the buffer "
            "checksum to 0 -- the same epilogue stores as the "
            "success path, reached from 0x604ee85.",
            "A decided IO_TOTAL priority skips the rate limiter "
            "entirely: the grant step tests rate_limiter_ != null "
            "AND decided != IO_TOTAL, so a writer with a limiter "
            "still writes in one chunk when the file or op priority "
            "is IO_TOTAL. The live check pins this (limiter.calls "
            "== []).",
            "The failure event's type 8 IS FileOperationType::kAppend "
            "-- resolved this cycle by the live v8.1.1 read "
            "(include/rocksdb/listener.h:236-248, implicit 0-based: "
            "kRead 0, kWrite 1, kTruncate 2, kClose 3, kFlush 4, "
            "kSync 5, kFsync 6, kRangeSync 7, kAppend 8, "
            "kPositionedAppend 9, kOpen 10), matching upstream "
            "NotifyOnIOError(s, kAppend, file_name(), allowed, "
            "old_size) in WriteBuffered (lines 613-615). It follows "
            "the sibling pattern exactly: Flush's failure event "
            "carries its own op (4 = kFlush) and RangeSync's carries "
            "7 = kRangeSync. The two trailing u64 fields are ordered "
            "(granted, next_write_offset_), swapped vs the finish "
            "event's (offset, length) -- those are the (allowed, "
            "old_size) arguments. The model emits 8 exactly as "
            "observed. (The prior draft recorded this as an open "
            "unknown because the 6.11 listener.h on docs.rs has no "
            "FileOperationType at all; the v8.1.1 enum resolves it.)",
            "The 0x61cf610 helper is a two-argument deep copy: the "
            "call sites set rdi = &dst (a stack slot) and rsi = "
            "src, and read the copy back from the slot after the "
            "call. The vendor census labels it Status::CopyState "
            "(one-arg signature), which does not match the observed "
            "calling convention; the name is recorded as an open "
            "unknown and the behaviour (deep copy, store at *dst) "
            "is what the model pins.",
            "SystemClock::Default() returns a handle the binary "
            "dereferences once: both guard setups do mov "
            "r15/r13,[rax] after the call (0x604e871, 0x604ed35), "
            "and the slow path of Default() itself stores a wrapper "
            "whose +0x0 points at the clock object (0x5fe2722). "
            "The model treats the clock as an oracle object with "
            "NowNanos (slot 20) and the CPU-time accessor (slot 22).",
            "WriteBuffered itself has no census record, while its "
            ".cold does -- the same split as Flush (#6057) and "
            "Append (#6041), whose mains are also body-hash-only. "
            "The packet binds the main by its recomputed body hash "
            "and the .cold by the census record (14 relocations).",
            "The perf_level save/restore exists because the file "
            "Append may clobber the TLS perf_level byte: the binary "
            "reads it at 0x604e40f (0x606ddd0), restores it at "
            "0x604e5d0 (0x606ddb0) before the CPU-guard stop, and "
            "the CPU stop re-checks perf_level > 3 before adding "
            "to the counter.",
        ],
        "unknowns": [
            "file->GetFileSize (slot 18) per chunk: the return is "
            "discarded, so its purpose in WriteBuffered is open. "
            "It is called with the same IOOptions as the Append and "
            "with a null debug context; the tracing wrapper's "
            "GetFileSize (0x600a770) is the only symbol that matches "
            "the signature.",
            "The TLS flag byte at fs-0x3f8+0x98 gating the IOStats "
            "bytes counter (+0x8) add: its identity is open. "
            "Modelled as iostats_bytes_flag (default clear = count).",
            "The 0x61cf610 helper's symbol: the census labels it "
            "Status::CopyState (one arg) but the call sites pass "
            "(dst, src). Recorded as an open unknown; the deep-copy "
            "behaviour is pinned.",
            "The TEST_SYNC_POINT string names in WriteBuffered: the "
            "binary's literals are stripped (verified absent from "
            "the node #115 binary), so no per-site name is pinned "
            "from the binary. Upstream v8.1.1 names the loop's "
            "TEST_SYNC_POINT 'WritableFileWriter::Flush:BeforeAppend' "
            "and the success-path kill point "
            "'WritableFileWriter::WriteBuffered:0' (TEST_KILL_RANDOM); "
            "the binary calls the sync-point helper 0x606d9f0 from "
            "four sites per chunk (0x604e2ec, 0x604e414, 0x604e767, "
            "0x604e78f) while upstream shows two named points per "
            "iteration -- the extra two sites are an open mapping "
            "question. The model records the four site addresses.",
            "Vtable slot 22 (0xb0) is the CPU-time accessor: "
            "inferred from the timer-guard destructor dispatching "
            "on the guard's cpu-flag byte (0 -> NowNanos slot 20, "
            "1 -> slot 22). NowNanos is slot 20 per the Flush "
            "packet.",
            "The listener method name for vtable slot 47: the slot "
            "is the binary's observed position; no name is asserted.",
            "The bool at this+0xd9, read into the finish event: it "
            "is not named by the Append packet's writer layout and "
            "no upstream header in the 2019 mirror has a member at "
            "that offset. Modelled as flag_d9 and listed here as an "
            "open unknown (shared with the Flush packet).",
            "Flush, Append, WriteBufferedWithChecksum, WriteDirect, "
            "WriteDirectWithChecksum and the RangeSync member are "
            "taken as oracles here (their bodies are separate FDEs; "
            "only WriteBuffered.cold is census-bound in this "
            "packet). Their internal steps are modelled from the "
            "#6057/#6041 contracts and upstream source, not from "
            "their own binary bodies in this packet; the Write* "
            "routines are the natural follow-ups.",
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
