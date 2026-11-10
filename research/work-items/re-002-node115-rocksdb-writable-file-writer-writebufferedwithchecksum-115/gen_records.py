#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
range. WriteBufferedWithChecksum itself has NO vendor census record (body hash
only, per the #5992 no-census convention); WriteBufferedWithChecksum.cold IS
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
    ("0x604f080", "0x604fd97",
     "rocksdb::WritableFileWriter::WriteBufferedWithChecksum",
     "writable-file-writer-writebufferedwithchecksum-604f080", False),
    ("0x604ef0e", "0x604f079",
     "rocksdb::WritableFileWriter::WriteBufferedWithChecksum.cold",
     "writable-file-writer-writebufferedwithchecksum-cold-604ef0e", True),
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
    main_calls = [s for s in sites if s["target"] == "0x604f080"]
    cold_jumps = [s for s in sites if s["target"] == "0x604ef0e"]
    functions["0x604f080"]["callers"] = [s["site"] for s in main_calls]
    functions["0x604ef0e"]["callers"] = [s["site"] for s in cold_jumps]
    functions["0x604f080"]["model"] = (
        "3351-byte IOStatus WriteBufferedWithChecksum(const char* data, size_t "
        "size, Env::IOPriority priority) (sret 16-byte out-pointer "
        "in rdi, WritableFileWriter* in rsi, data in rdx, size in "
        "rcx, priority in r8d). Seen-error gate (0x604f0ae): byte "
        "this+0x89 set -> return IOStatus code 5 'Writer has "
        "previous error.' (27-byte heap state_, old sret state_ "
        "delete[]'d first), nothing else touched. IOOptions + file "
        "priority (0x604f0bd..0x604f1a1): the file's GetIOPriority "
        "(vtable slot 16, devirtualized when the slot equals the "
        "RELATIVE reloc at 0x64ecf30, else the virtual call at "
        "0x604f948) feeds DecideRateLimiterPriority (0x604c800, "
        "census-bound, pure) with the op priority; a 0x58-byte "
        "IOOptions is built on the stack with the exact defaults "
        "(timeout 0, prio kIOLow 0, rate_limiter_priority the Decide "
        "result, type kUnknown 7, property_bag an empty "
        "unordered_map, force_dir_fsync 0, do_not_recurse 0). "
        "Rate-limiter DRAIN loop (0x604f1a2..0x604f1e7), NOT a chunk "
        "loop: when rate_limiter_ (this+0xa0) is non-null AND the "
        "decided priority != IO_TOTAL (4) AND size != 0, while "
        "data_size > 0: granted = rate_limiter_->RequestToken"
        "(data_size, buf_.Alignment() (this+0x40), decided priority, "
        "stats_ (this+0xa8), OpType kWrite = 1) through vtable slot 6 "
        "(base impl 0x61c43f0, census-bound); data_size -= granted. "
        "The grants are DISCARDED -- no write happens in the loop; "
        "exactly ONE file Append follows (upstream TODO: 'need to be "
        "improved since it sort of defeats the purpose of the rate "
        "limiter'). PINNED DIFFERENCE from WriteBuffered, which "
        "passes alignment 0 (xor edx,edx at 0x604e2d8): here the "
        "alignment is buf_.Alignment() (mov 0x40(%rbx),%rdx at "
        "0x604f1ca). (b) TEST_SYNC_POINT #1 (0x604f1e9) and the "
        "nanos-guard setup: armed iff perf_level > 2 (clock = "
        "*SystemClock::Default() 0x5fe2680, dereferenced once; "
        "start = NowNanos, vtable slot 20). (c) "
        "file->GetFileSize(io_options, nullptr) (0x604f2c9, vtable "
        "slot 18) -- the uint64 return is DISCARDED by the caller "
        "(stored to [rsp+0x8], overwritten with next_write_offset_ "
        "at 0x604f306 when listeners exist, and read only at "
        "0x604f55a and 0x604fad6 in event construction); the method "
        "is identified by its signature plus the "
        "FSWritableFileTracingWrapper::GetFileSize symbol "
        "(0x600a770, census-bound), but why upstream calls it here "
        "is an open unknown. (d) Listener start times (0x604f2d4): "
        "only when listeners_ (this+0xb0) is non-empty, "
        "steady_clock::now() + system_clock::now(); "
        "next_write_offset_ is saved for the event. (e) perf_level "
        "save (0x604f310): GetPerfLevel() (0x606ddd0) reads the TLS "
        "byte; restored after the Append (0x604f475, 0x606ddb0). "
        "(f) TEST_SYNC_POINT #2 (0x604f315) and the CPU-guard "
        "setup: armed iff perf_level > 3 (clock = this->clock_ or "
        "Default() when null, 0x604fb40; start = the CPU-time "
        "accessor, vtable slot 22). (g) Checksum handoff "
        "(0x604f3cd..0x604f3ef): EncodeFixed32(checksum_buf, "
        "buffered_data_crc32c_checksum_ (this+0xd4)) -- the checksum "
        "handed to the file is the writer's ACCUMULATED buffered "
        "value, NOT a fresh crc32c::Extend over the data (that is "
        "WriteBuffered's per-chunk dispatch); there is NO "
        "verification gate in the binary (the upstream asserts "
        "are compiled out), so the checksum arm is always taken. "
        "(h) Single file->Append (0x604f432, vtable slot 3): "
        "writable_file_->Append(Slice{data, size}, io_options, "
        "DataVerificationInfo{Slice{&crc, 4}}, nullptr). No loop "
        "and NO zero-size short-circuit (unlike WriteBuffered): "
        "size 0 still runs one zero-length Append. The result is "
        "written to a 16-byte stack IOStatus at rsp+0x70 and then "
        "copied (bytes 0-1, 3-4, 5, 8-15; byte 2 forced to 0 in "
        "the epilogue). (i) perf_level restore (0x604f475). (j) "
        "CPU-guard stop (0x604f8b8): the CPU-time accessor is "
        "called whenever the guard started; the TLS counter at "
        "fs-0x3f8+0x58 advances by the elapsed time only when "
        "perf_level > 3 (re-checked). Runs BEFORE the listener "
        "events on both paths. (k) Listener events "
        "(0x604f483..0x604f5cc, 0x604f960..): only when listeners_ "
        "is non-empty. Finish event (always): {FileOperationType "
        "type = 1 (kWrite), WritableFileWriter* this, bool "
        "[this+0xd9], uint64 offset = next_write_offset_, uint64 "
        "length = size, uint64 elapsed_nanos, TimePoint* "
        "&start_times, Status status (CopyState deep copy at "
        "0x61cf610)} through vtable slot 34 (0x110), skipping the "
        "base no-op 0x604c660. Failure event (only when the Append "
        "status is not OK): {Status status (CopyState deep copy), "
        "FileOperationType type = 8, std::string file_name_, uint64 "
        "left = size, uint64 old_size} through vtable slot 47 "
        "(0x178), skipping the base no-op 0x6042c20. The failure "
        "type 8 is FileOperationType::kAppend (v8.1.1 "
        "listener.h:236-248) -- exactly upstream NotifyOnIOError(s, "
        "kAppend, file_name(), left, old_size); the trailing u64s "
        "(left, old_size) are the (allowed, old_size) arguments. "
        "PINNED DIFFERENCE from WriteBuffered: its failure event "
        "trails (granted, next_write_offset_). (l) Failure return "
        "(0x604f7fb): buf_.cursize_ is cleared to 0 and "
        "buffered_data_crc32c_checksum_ reset to 0 in the failure "
        "epilogue -- AFTER the notifications (pinned difference "
        "from WriteBuffered, which clears immediately after the "
        "failed Append); seen_error_ = 1 AFTER the notifications; "
        "the sret is built (byte 2 forced to 0); the nanos guard "
        "stops at 0x604f849..0x604f8ad; no retry; flushed_size_ is "
        "NOT advanced. (m) Success path: nanos-guard stop "
        "(0x604f900, elapsed -> the TLS counter at fs-0x3f8+0x28), "
        "TEST_SYNC_POINT #3 (0x604f5f9, the TEST_KILL_RANDOM "
        "'WritableFileWriter::WriteBuffered:0' site), then -- when "
        "the TLS flag at fs-0x3f8+0x98 is clear -- TEST_SYNC_POINT "
        "#4 (0x604f62b) and the TLS counter at fs-0x3f8+0x8 "
        "advances by the size (the flag's identity is an open "
        "unknown). Epilogue (0x604f644..0x604f699): buf_.Size(0), "
        "buffered_data_crc32c_checksum_ = 0, flushed_size_ "
        "(this+0x78) += size, the working status is copied into "
        "the sret (byte 2 forced to 0), the IOOptions property_bag "
        "is destroyed (0x5d36110), the stack canary is checked and "
        "__stack_chk_fail fires on mismatch.")
    functions["0x604ef0e"]["model"] = (
        "363-byte .cold landing pad, entered by the four tail jumps "
        "at 0x604fca8, 0x604fd2c, 0x604fd38 and 0x604fd44 (four of the "
        "twenty-one endbr64 stubs at the main FDE tail, 0x604fca1.."
        "0x604fd95; the other seventeen jump to interior .cold "
        "addresses, and the last stub at 0x604fd91 jumps to the "
        "stub at 0x604fd71): delete[] the sret state_ when "
        "non-null, destroy "
        "the failure-event strings, stop both timer guards through "
        "the shared destructor 0x604c6b6, destroy the IOOptions "
        "property_bag, check the stack canary, then _Unwind_Resume "
        "or __stack_chk_fail. Unwind-only; no case exercises it.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-writable-file-writer-writebuffered-115 "
            "(open, PR #6088): reconstructs WritableFileWriter::WriteBuffered "
            "0x604e140, which took WriteBufferedWithChecksum as an input "
            "oracle (its checksum dispatch calls the slot-3 Append with a "
            "fresh crc32c::Extend per chunk) and left it as the direct "
            "follow-up; its tool and packet scaffolding are the template "
            "for this packet. This packet supersedes that oracle note "
            "with the full body model. CORRECTION (found this cycle "
            "while cross-checking): the #6088 packet cites WriteBuffered "
            "as upstream lines 544-636, but the raw v8.1.1 file "
            "writable_file_writer.cc puts WriteBuffered at lines "
            "1040-1217 (its 544-636 range is inside Close/Flush); the "
            "line citation in #6088 is wrong and is fixed in-PR "
            "separately. The binary model in #6088 is unaffected.",
            "RE-002-node115-rocksdb-writable-file-writer-flush-115 "
            "(open, PR #6057): reconstructs WritableFileWriter::Flush "
            "0x6051a20, which calls WriteBufferedWithChecksum at "
            "0x6052490 (verified by this packet's caller census) and "
            "which took it as an input oracle, leaving it as a "
            "follow-up. This packet supersedes that oracle note with "
            "the full body model.",
            "RE-002-node115-rocksdb-writable-file-writer-append-115 "
            "(open, PR #6041): reconstructs WritableFileWriter::Append "
            "0x6054680, which calls WriteBufferedWithChecksum at "
            "0x6054ed9 and 0x605507b (verified by this packet's caller "
            "census) -- its two verification arms take "
            "WriteBufferedWithChecksum as their engine callee -- and "
            "pins the same 0xe0 writer layout, the same seen-error "
            "gate (code 5, 27-byte heap state_) and the same sret "
            "move-assign shape.",
            "RE-002-node115-vendor-census: WriteBufferedWithChecksum "
            "itself has NO census record (body hash only, per the "
            "#5992 no-census convention); WriteBufferedWithChecksum"
            ".cold IS census-bound (body hash matches "
            "target_body_sha256 exactly; source hash reproduced by "
            "zeroing the 14 recorded relocations, kinds 2/4; no "
            "kind-42 relocation, so no GOTPCRELX restoration "
            "applies).",
            "facebook/rocksdb v8.1.1, read live this cycle (raw file): "
            "file/writable_file_writer.cc WriteBufferedWithChecksum "
            "(lines 1220-1395) confirms the packet step for step -- "
            "the seen-error gate (AssertFalseAndGetStatusForPrevError), "
            "the IOOptions build with DecideRateLimiterPriority, the "
            "rate-limiter DRAIN loop (RequestToken(data_size, "
            "buf_.Alignment(), ...) with the upstream TODO that it "
            "'sort of defeats the purpose of the rate limiter'), the "
            "TEST_SYNC_POINT gate, the IOSTATS_TIMER_GUARD halves, "
            "the GetFileSize call, the listener start times and the "
            "perf-level save/restore, the checksum handoff "
            "(EncodeFixed32(checksum_buf, "
            "buffered_data_crc32c_checksum_) then a single "
            "writable_file_->Append(Slice(src, left), io_options, "
            "v_info, nullptr)), the failure path (buf_.Size(0), "
            "checksum reset, set_seen_error(), return s -- AFTER the "
            "listener events in the source, matching the binary's "
            "failure epilogue at 0x604f7fb), and the success epilogue "
            "(IOSTATS_ADD(bytes_written, left), TEST_KILL_RANDOM, "
            "buf_.Size(0), checksum reset, flushed_size_ += left). "
            "The failure event type 8 is FileOperationType::kAppend "
            "(include/rocksdb/listener.h:236-248, implicit 0-based: "
            "kRead 0, kWrite 1, kTruncate 2, kClose 3, kFlush 4, "
            "kSync 5, kFsync 6, kRangeSync 7, kAppend 8) -- exactly "
            "upstream NotifyOnIOError(s, kAppend, file_name(), left, "
            "old_size); the finish event 1 = kWrite, Flush's failure "
            "event 4 = kFlush, RangeSync's 7 = kRangeSync, all from "
            "the same enum. Binary-vs-source observations, recorded "
            "not hidden: the GetFileSize return is discarded by the "
            "caller even though the call is made (upstream overwrites "
            "old_size with next_write_offset_ when listeners exist); "
            "the binary has NO zero-size branch -- size 0 still runs "
            "one zero-length Append (upstream has no zero-size branch "
            "either, the same observable behaviour); the binary runs "
            "the TEST_KILL_RANDOM sync point BEFORE the "
            "IOSTATS_ADD(bytes_written) while upstream lists the "
            "bytes add first (same observable behaviour, a "
            "scheduling difference); upstream's post-epilogue "
            "'if (!s.ok()) set_seen_error()' is unreachable in "
            "practice (failures return early) and has no counterpart "
            "in the binary epilogue; upstream's asserts "
            "(!use_direct_io(); perform_data_verification_ && "
            "buffered_data_with_checksum_) are compiled out; "
            "upstream names the loop's TEST_SYNC_POINT "
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
                "WritableFileWriter::WriteBufferedWithChecksum "
                "0x604f080: exactly 3 direct calls, 0 tail jumps, 0 "
                "LEA refs. The callers are rocksdb::WritableFileWriter"
                "::Flush 0x6051a20..0x605257c (call site 0x6052490) and "
                "rocksdb::WritableFileWriter::Append 0x6054680.."
                "0x605518b (call sites 0x6054ed9 and 0x605507b, its two "
                "verification arms) -- the members whose packets took "
                "WriteBufferedWithChecksum as an input oracle. No other "
                "caller exists in the whole .text.",
                "WritableFileWriter::WriteBufferedWithChecksum.cold "
                "0x604ef0e: exactly 4 tail jumps at 0x604fca8, "
                "0x604fd2c, 0x604fd38 and 0x604fd44 (four of the "
                "twenty-one endbr64 stubs at the main FDE tail) -- the "
                "exception landing-pad entries. No call sites. (The "
                "other seventeen stubs jump to interior .cold "
                "addresses; the last stub at 0x604fd91 jumps to the "
                "stub at 0x604fd71.)",
                "WriteBufferedWithChecksum calls file->Append (vtable "
                "slot 3, with checksum) and file->GetFileSize (vtable "
                "slot 18) through the file pointer, not by direct call "
                "-- so no direct call sites for those appear in the "
                "scan; the slot numbers are pinned by the disassembly "
                "and the bindings group. It calls no other "
                "WritableFileWriter member directly: no Flush, Pad, "
                "RangeSync, WriteBuffered or WriteDirect call exists "
                "in the FDE.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 gate (seen-error, zero/non-zero size, entry "
                     "cursize/capacity, verification flags -- "
                     "perform_data_verification_ and "
                     "buffered_data_with_checksum_ vary freely, the "
                     "binary takes the checksum arm unconditionally -- "
                     "priorities 0..4, tracer selection, perf level "
                     "0..5, sync point, clock pairs, flag_d9, file "
                     "names, scripted single-Append failures, "
                     "iostats flag) + 600 grant_loop (the DRAIN "
                     "matrix: size vs the scripted rate-limiter "
                     "grants -- single grant, exact split, grant "
                     "exhaustion, tiny grants -- the drain consumes "
                     "the FULL size before the one Append; a scripted "
                     "Append failure hits the single Append; "
                     "listeners + both guards armed, iostats flag, "
                     "file image pre-filled) + 600 checksum (the "
                     "HANDOFF checksum is the entry "
                     "buffered_data_crc32c_checksum_, pinned in the "
                     "file_append events for every size x grant "
                     "split; perform_data_verification on/off x "
                     "buffered_data_with_checksum on/off; Append "
                     "failures reset buf_ + checksum; the zero-size "
                     "case still runs one zero-length Append carrying "
                     "the checksum) + 600 bindings (body hashes for "
                     "WriteBufferedWithChecksum, .cold, "
                     "WriteBuffered, .cold, Flush, WriteDirect, "
                     "WriteDirectWithChecksum, RangeSync, Append, "
                     "DecideRateLimiterPriority, UpdateFileChecksum, "
                     "the CRC value helper, the timer-guard "
                     "destructor; eight census records; 7 "
                     "caller-census sites; vtable slots 2/3/16/18/34/"
                     "35/37/47; 30 writer-layout offsets; IOOptions "
                     "defaults; 25-cell priority matrix; "
                     "FileOperationType 1/4/7/8; "
                     "WriteBufferedWithChecksum call-site constants; "
                     "CRC vectors incl. check vector '123456789' -> "
                     "0xE3069283, Combine identities, AlignedBuffer "
                     "unit rows, write_zeros rows, timer-guard "
                     "thresholds for both halves, file-selection "
                     "matrix)",
            "tests": "tests/test_writable_file_writer_writebufferedwithchecksum115.py",
            "tool": "tools/writable_file_writer_writebufferedwithchecksum115.py",
            "what_is_checked": [
                "gate: seen_error returns code 5 with the 27-byte "
                "heap state_ and writes nothing; zero-size still runs "
                "ONE zero-length Append (no short-circuit) and "
                "returns OK, clearing buf_ and resetting the buffer "
                "checksum; a decided IO_TOTAL priority skips "
                "RequestToken even when a limiter exists; tracer "
                "selection picks the raw file vs the tracing "
                "wrapper; the file image pre-fill is visible to "
                "GetFileSize (recorded, discarded); the verification "
                "flags do not change the outcome (the checksum arm "
                "is always taken)",
                "grant_loop: the drain matrix is replayed exactly "
                "(grant sizes, drain counts, file bytes, cursize_, "
                "flushed_size_, wbc_grants, wbc_append_calls, "
                "wbc_get_file_size_calls); the drain consumes the "
                "FULL size before the one Append and the grants are "
                "discarded; an Append failure on the single Append "
                "does not advance flushed_size_, sets seen_error_ "
                "after the notifications, and clears buf_ + checksum "
                "in the failure epilogue; grant exhaustion falls "
                "back to granted = remaining for the tail grant",
                "checksum: the handoff checksum in every file_append "
                "event equals the entry "
                "buffered_data_crc32c_checksum_ -- never a fresh "
                "crc32c::Value over the data; an Append failure "
                "resets buf_ + checksum; zero-size still hands the "
                "buffered checksum to the zero-length Append",
                "bindings: all thirteen FDE body hashes match the "
                "binary; the .cold source hash is reproduced by "
                "zeroing its 14 recorded relocations; the 3 call "
                "sites and 4 jump sites are pinned; vtable slots "
                "2/3/16/18 and the listener slots 34/35/37/47; the "
                "30 writer-layout offsets incl. the unnamed bool at "
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
                        "calls WriteBufferedWithChecksum at 0x6052490 "
                        "(the caller-census site in this packet) and "
                        "WriteBuffered at 0x6051cc5. "
                        "Implemented here at the #6057 fidelity: "
                        "buffered/direct write step, listener start "
                        "times + finish/failure events, IOOptions with "
                        "DecideRateLimiterPriority, file_->Flush, and "
                        "the RangeSync arm.",
            "0x6054680": "WritableFileWriter::Append (census-bound, "
                        "2827 B + 124 B .cold): the oracle whose write "
                        "loop calls WriteBufferedWithChecksum at "
                        "0x6054ed9 and 0x605507b (its two verification "
                        "arms, the caller-census sites in this packet) "
                        "and WriteBuffered at 0x6054d23. "
                        "Implemented here at the #6041 fidelity.",
            "0x604e140": "WritableFileWriter::WriteBuffered "
                        "(no census, oracle): 3533 B, reconstructed in "
                        "#6088. It differs from the function "
                        "reconstructed here in exactly the pinned "
                        "ways -- its rate-limiter loop is a CHUNK loop "
                        "(one Append per grant, alignment 0, per-chunk "
                        "crc32c::Extend dispatch between slot 2 and "
                        "slot 3), its zero-size path is a clearing "
                        "write with no Append, and its failure clears "
                        "buf_ + checksum immediately after the failed "
                        "Append, before the notifications. Its tool "
                        "and packet scaffolding are the template for "
                        "this packet; its upstream line citation "
                        "(544-636) is WRONG -- the correct range is "
                        "1040-1217 (see bound_context).",
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
                        "else op. Called by the "
                        "WriteBufferedWithChecksum IOOptions build "
                        "(0x604f10c) and by the Flush oracle.",
            "0x604c7e0": "The 19-byte CRC value helper (no census): "
                        "xor edi,edi; call 0x61c25f0 -- crc32c::Extend"
                        "(0, data, size), the per-chunk CRC helper "
                        "WriteBuffered's checksum dispatch uses. "
                        "WriteBufferedWithChecksum does NOT call it -- "
                        "its handoff uses the buffered value instead; "
                        "listed here only because the model depends on "
                        "the distinction.",
            "0x61c25f0": "crc32c::Extend dispatch thunk: the CRC "
                        "helper calls it as Extend(0, data, size). "
                        "Resolves to ExtendImpl<Slow_CRC32> 0x61c21d0 "
                        "per the #6012 packet; the table-driven Python "
                        "Extend is bit-identical to the slow path.",
            "0x61c43f0": "RateLimiter::RequestToken (base impl, "
                        "census-bound, 359 B): the virtual call the "
                        "grant step makes through vtable slot 6 with "
                        "(data_size, buf_.Alignment(), decided "
                        "priority, stats_, OpType kWrite = 1). The "
                        "model takes "
                        "the granted count from the scripted limiter "
                        "oracle; the base impl's own body is not "
                        "reconstructed here.",
            "0x5fe2680": "SystemClock::Default (census-bound, 214 B): "
                        "returns the default clock handle; the binary "
                        "dereferences it once (mov r13,[rax] at "
                        "0x604f731) to get "
                        "the clock object used by both timer-guard "
                        "halves.",
            "0x600a770": "FSWritableFileTracingWrapper::GetFileSize "
                        "(census-bound, 1208 B): the tracing wrapper's "
                        "GetFileSize(const IOOptions&, IODebugContext*) "
                        "-- the signature match that identifies the "
                        "slot-18 call at 0x604f2c9.",
            "0x604c6b6": "IOSTATS_TIMER_GUARD destructor (no census, "
                        "82 B): dispatches on the guard's cpu-flag "
                        "byte (+1): 0 -> NowNanos (slot 20), 1 -> the "
                        "CPU-time accessor (slot 22); adds the elapsed "
                        "time to the guard's counter when the armed "
                        "flag (+0) is set; calls the second clock's "
                        "CPU-time accessor with the guard id when the "
                        "second clock (+0x20) is non-null (null in "
                        "WriteBufferedWithChecksum). Runs only from "
                        ".cold (unwind); the main-FDE stops are inline: "
                        "the nanos guard stops at 0x604f849..0x604f8ad "
                        "(failure) and 0x604f900 (success), the CPU "
                        "guard at 0x604f8b8 (before the events).",
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
                        "0x604f310 and restored after the Append "
                        "(0x604f475).",
            "0x606ddb0": "SetPerfLevel (no census): writes the TLS "
                        "perf_level byte at 0x604f475 (the restore).",
            "0x606d9f0": "TEST_SYNC_POINT helper (no census): the "
                        "sync-point gate, called from the four sites "
                        "0x604f1e9, 0x604f315, 0x604f5f9, 0x604f621 "
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
                        "by WriteBufferedWithChecksum, WriteBuffered, "
                        "Flush and RangeSync).",
            "0x5df6e90": "Base FSWritableFile::GetIOPriority ('mov "
                        "0x18(%rdi),%eax; ret'): the devirtualization "
                        "guard compares vtable slot 16 against the "
                        "RELATIVE reloc at 0x64ecf30; when equal the "
                        "binary reads file+0x18 directly.",
            "0x5d36110": "std::_Hashtable dtor for the IOOptions "
                        "property_bag, called on every "
                        "WriteBufferedWithChecksum exit path (success "
                        "epilogue, failure return).",
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
                               "WriteBuffered, WriteDirect, "
                               "WriteDirectWithChecksum, RangeSync and "
                               "the file's Flush/RangeSync/Append/"
                               "GetFileSize are taken as scripted "
                               "oracles, and the live engine check "
                               "drives the model against a real file "
                               "and asserts the model's file image "
                               "equals the real file bytes after every "
                               "WriteBufferedWithChecksum (a real file, "
                               "not the node binary). make verify/test/"
                               "catalogue-check in a tooled environment "
                               "is still owed upstream.",
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
                         "bufstart_ +0x60) -- read: alignment_ by the "
                         "DRAIN loop (0x604f1ca, the pinned difference "
                         "from WriteBuffered, which passes 0); "
                         "written: cursize_ = 0 on every exit path",
                "+0x58": "buf_.cursize_ (size_t, 8) -- written: = 0 "
                         "in the failure epilogue and the success "
                         "epilogue",
                "+0x68": "max_buffer_size_ (size_t, 8) -- not read",
                "+0x70": "filesize_ (uint64, 8) -- not read or "
                         "written here (the file's own size is queried "
                         "once via GetFileSize and discarded)",
                "+0x78": "flushed_size_ (uint64, 8) -- written: += "
                         "size on success only (NOT advanced on "
                         "failure)",
                "+0x80": "next_write_offset_ (uint64, 8) -- read: "
                         "into both listener events",
                "+0x88": "pending_sync_ (bool, 1) -- not read or "
                         "written here",
                "+0x89": "seen_error_ (bool, 1) -- read: the gate "
                         "(first read in the FDE); written: = 1 on a "
                         "failed Append, after the notifications, in "
                         "the failure epilogue",
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
                         "NOT read by WriteBufferedWithChecksum (the "
                         "upstream assert is compiled out; the checksum "
                         "arm is always taken)",
                "+0xd4": "buffered_data_crc32c_checksum_ (uint32, 4) "
                         "-- read: the checksum HANDOFF (EncodeFixed32 "
                         "copies it into the 4-byte v_info slice "
                         "before the single Append); written: = 0 in "
                         "the failure epilogue and the success "
                         "epilogue",
                "+0xd8": "buffered_data_with_checksum_ (bool, 1) -- "
                         "NOT consulted by WriteBufferedWithChecksum "
                         "(the upstream assert is compiled out)",
                "+0xd9": "UNNAMED bool (1) -- read into the finish "
                         "event; not named by the Append layout; open "
                         "unknown (shared with the Flush packet)",
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
            "write_buffered_with_checksum_call": {
                "grant": "DRAIN loop: RequestToken(data_size, "
                         "buf_.Alignment(), decided, stats_, kWrite) "
                         "when rate_limiter_ non-null and decided != "
                         "IO_TOTAL and size != 0; the grants are "
                         "discarded (no write in the loop); exactly "
                         "ONE Append follows",
                "nanos_guard": "armed iff perf_level > 2; clock = "
                               "*SystemClock::Default(); start = "
                               "NowNanos (slot 20); counter at "
                               "fs-0x3f8+0x28; stops inline at "
                               "0x604f900 (success) / 0x604f849.."
                               "0x604f8ad (failure, after the sret "
                               "build)",
                "cpu_guard": "armed iff perf_level > 3; clock = "
                             "clock_ or Default(); start = the CPU-time "
                             "accessor (slot 22); counter at "
                             "fs-0x3f8+0x58; stops inline at 0x604f8b8 "
                             "(before the events, both paths)",
                "get_file_size": "file->GetFileSize(io_options, "
                                 "nullptr) (slot 18, once); return "
                                 "discarded (stored to [rsp+0x8], "
                                 "overwritten with next_write_offset_ "
                                 "when listeners exist)",
                "append": "slot 3 with Slice{&EncodeFixed32("
                          "buffered_data_crc32c_checksum_), 4} -- the "
                          "handoff checksum, always; no slot-2 arm",
                "failure": "perf restore; CPU stop; finish + failure "
                           "events; buf_.cursize_ = 0; checksum = 0; "
                           "seen_error_ = 1 (all three AFTER the "
                           "notifications); nanos stop; return status "
                           "(byte 2 = 0)",
                "success": "finish event; nanos stop; sync-point #3 "
                           "(TEST_KILL_RANDOM); sync-point #4 + bytes "
                           "counter += size (flag clear); "
                           "flushed_size_ += size; buf_.Size(0); "
                           "checksum = 0",
            },
            "status_16": {
                "+0x00": "code (uint8)",
                "+0x01": "subcode (uint8)",
                "+0x02": "severity (uint8) -- forced to 0 on every "
                         "WriteBufferedWithChecksum return path (gate, "
                         "failure return, OK epilogue)",
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
            "guard stops at 0x604f8b8 BEFORE the listener events on "
            "both paths, while the nanos guard stops AFTER the "
            "events -- at 0x604f900 on the success path and at "
            "0x604f849..0x604f8ad (after the sret build) on the failure "
            "path. The shared destructor 0x604c6b6 runs only from .cold "
            "(unwind); the main-FDE stops are inline calls to the "
            "clock methods. The model follows this order exactly, "
            "including that a failed call's nanos elapsed time is "
            "still recorded (failure-path stop) but its bytes are "
            "never added to the IOStats counter.",
            "Four TEST_SYNC_POINT gates fire per call (0x604f1e9, "
            "0x604f315, 0x604f5f9, 0x604f621), all through the helper "
            "0x606d9f0 when the sync-point global *0x64ed5d0 is "
            "non-null. The third gate (0x604f5f9) is the TEST_KILL_RANDOM "
            "'WritableFileWriter::WriteBuffered:0' site; the fourth gate "
            "fires only when the IOStats-bytes flag is clear -- it sits "
            "between the flag check and the bytes add. The string names "
            "are not asserted; the model records the site addresses. "
            "The binary runs the kill-random gate BEFORE the "
            "IOSTATS_ADD(bytes_written) while upstream lists the bytes "
            "add first (line 1369 vs 1371) -- same observable behaviour, "
            "a scheduling difference.",
            "file->GetFileSize is called ONCE and its return is "
            "discarded: the uint64 is stored to a stack slot "
            "([rsp+0x8]) that the listener-event path overwrites with "
            "next_write_offset_ before any read (verified by grepping "
            "all [rsp+0x8] reads: only 0x604f55a and 0x604fad6, both in "
            "event construction after the overwrite at 0x604f306). "
            "The method is identified by its signature plus the "
            "FSWritableFileTracingWrapper::GetFileSize symbol "
            "(0x600a770); why upstream calls it here is open.",
            "The checksum is a HANDOFF, not a fresh computation: the "
            "binary EncodeFixed32's the writer's accumulated "
            "buffered_data_crc32c_checksum_ into the 4-byte v_info "
            "slice and never calls the crc32c::Value helper (0x604c7e0) "
            "-- WriteBuffered's per-chunk crc32c::Extend dispatch is "
            "absent here. The live check pins this (the file_append "
            "events carry the entry buffered value 0x12345678 for "
            "every size).",
            "There is NO zero-size short-circuit: size 0 still runs one "
            "zero-length Append carrying the buffered checksum, then "
            "the success epilogue (upstream has no zero-size branch "
            "either). The live check pins this (zero_size_one_append).",
            "A decided IO_TOTAL priority skips the rate limiter "
            "entirely: the drain step tests rate_limiter_ != null "
            "AND decided != IO_TOTAL AND size != 0, so a writer with a "
            "limiter still writes with one Append when the file or op "
            "priority is IO_TOTAL. The live check pins this "
            "(limiter.calls == []).",
            "The drain loop consumes the FULL size before the one "
            "Append, and the grants are discarded -- the binary "
            "RequestToken's data_size, buf_.Alignment(), and loops "
            "until data_size hits 0, with no write inside the loop. "
            "The live check pins this (drain_loop_real_file 5000 B: "
            "the grants [2000, 2000, 1000] drain exactly, then one "
            "Append of 5000 B).",
            "The failure event's type 8 IS FileOperationType::kAppend "
            "-- resolved by the live v8.1.1 read (include/rocksdb/"
            "listener.h:236-248, implicit 0-based: kRead 0, kWrite 1, "
            "kTruncate 2, kClose 3, kFlush 4, kSync 5, kFsync 6, "
            "kRangeSync 7, kAppend 8, kPositionedAppend 9, kOpen 10), "
            "matching upstream NotifyOnIOError(s, kAppend, file_name(), "
            "left, old_size) in WriteBufferedWithChecksum (lines "
            "1390-1393). It follows the sibling pattern exactly: "
            "Flush's failure event carries its own op (4 = kFlush) "
            "and RangeSync's carries 7 = kRangeSync. The two trailing "
            "u64 fields are ordered (left, old_size) -- those are the "
            "(allowed, old_size) arguments. The model emits 8 exactly "
            "as observed. PINNED DIFFERENCE from WriteBuffered, whose "
            "failure event trails (granted, next_write_offset_).",
            "The failure epilogue clears buf_ and resets the checksum "
            "and sets seen_error_ AFTER the listener notifications "
            "(0x604f7fb), while WriteBuffered clears immediately "
            "after the failed Append, before the events -- a pinned "
            "ordering difference between the siblings.",
            "The 0x61cf610 helper is a two-argument deep copy: the "
            "call sites set rdi = &dst (a stack slot) and rsi = "
            "src, and read the copy back from the slot after the "
            "call. The vendor census labels it Status::CopyState "
            "(one-arg signature), which does not match the observed "
            "calling convention; the name is recorded as an open "
            "unknown and the behaviour (deep copy, store at *dst) "
            "is what the model pins.",
            "SystemClock::Default() returns a handle the binary "
            "dereferences once: the nanos-guard setup does mov "
            "r13,[rax] after the call (0x604f731), and the slow path "
            "of Default() itself stores a wrapper whose +0x0 points "
            "at the clock object (0x5fe2722). The model treats the "
            "clock as an oracle object with NowNanos (slot 20) and "
            "the CPU-time accessor (slot 22).",
            "WriteBufferedWithChecksum itself has no census record, "
            "while its .cold does -- the same split as Flush (#6057) "
            "and Append (#6041), whose mains are also body-hash-only. "
            "The packet binds the main by its recomputed body hash "
            "and the .cold by the census record (14 relocations).",
            "The perf_level save/restore exists because the file "
            "Append may clobber the TLS perf_level byte: the binary "
            "reads it at 0x604f310 (0x606ddd0), restores it at "
            "0x604f475 (0x606ddb0) before the CPU-guard stop, and "
            "the CPU stop re-checks perf_level > 3 before adding "
            "to the counter.",
        ],
        "unknowns": [
            "file->GetFileSize (slot 18) once: the return is "
            "discarded, so its purpose in WriteBufferedWithChecksum "
            "is open. It is called with the same IOOptions as the "
            "Append and with a null debug context; the tracing "
            "wrapper's GetFileSize (0x600a770) is the only symbol "
            "that matches the signature.",
            "The TLS flag byte at fs-0x3f8+0x98 gating the IOStats "
            "bytes counter (+0x8) add: its identity is open. "
            "Modelled as iostats_bytes_flag (default clear = count).",
            "The 0x61cf610 helper's symbol: the census labels it "
            "Status::CopyState (one arg) but the call sites pass "
            "(dst, src). Recorded as an open unknown; the deep-copy "
            "behaviour is pinned.",
            "The TEST_SYNC_POINT string names in "
            "WriteBufferedWithChecksum: the binary's literals are "
            "stripped (verified absent from the node #115 binary), "
            "so no per-site name is pinned from the binary. Upstream "
            "v8.1.1 names the loop's TEST_SYNC_POINT "
            "'WritableFileWriter::Flush:BeforeAppend' and the "
            "success-path kill point 'WritableFileWriter::WriteBuffered:0' "
            "(TEST_KILL_RANDOM); the binary calls the sync-point "
            "helper 0x606d9f0 from four sites (0x604f1e9, 0x604f315, "
            "0x604f5f9, 0x604f621) while upstream shows two named "
            "points -- the extra two sites are an open mapping "
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
            "Flush, Append, WriteBuffered, WriteDirect, "
            "WriteDirectWithChecksum and the RangeSync member are "
            "taken as oracles here (their bodies are separate FDEs; "
            "only WriteBufferedWithChecksum.cold is census-bound in "
            "this packet). Their internal steps are modelled from "
            "the #6057/#6041/#6088 contracts and upstream source, "
            "not from their own binary bodies in this packet; the "
            "Write* routines are the natural follow-ups.",
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
