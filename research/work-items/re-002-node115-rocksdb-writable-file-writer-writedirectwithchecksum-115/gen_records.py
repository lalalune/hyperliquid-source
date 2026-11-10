#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
range. WriteDirectWithChecksum itself has NO vendor census record
(body hash only, per the #5992 no-census convention);
WriteDirectWithChecksum.cold IS census-bound: its body hash
matches the census target_body_sha256 exactly and its source hash
is reproduced by zeroing the recorded relocations (12
relocations, kinds 2/4; no kind-42 relocation, so no GOTPCRELX
mov-lea restoration applies).
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
    ("0x6050c80", "0x6051937",
     "rocksdb::WritableFileWriter::WriteDirectWithChecksum",
     "writable-file-writer-writedirectwithchecksum-6050c80", False),
    ("0x6050b8a", "0x6050c7d",
     "rocksdb::WritableFileWriter::WriteDirectWithChecksum.cold",
     "writable-file-writer-writedirectwithchecksum-cold-6050b8a", True),
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
    main_calls = [s for s in sites if s["target"] == "0x6050c80"]
    cold_jumps = [s for s in sites if s["target"] == "0x6050b8a"]
    functions["0x6050c80"]["callers"] = [s["site"] for s in main_calls]
    functions["0x6050b8a"]["callers"] = [s["site"] for s in cold_jumps]
    functions["0x6050c80"]["model"] = (
        "3255-byte IOStatus WriteDirectWithChecksum(Env::IOPriority "
        "priority) (sret 16-byte out-pointer in rdi, "
        "WritableFileWriter* in rsi, priority in rdx). (1) "
        "Seen-error gate (0x6050cb0): byte this+0x89 set -> return "
        "IOStatus code 5 'Writer has previous error.' (27-byte heap "
        "state_, old sret state_ delete[]'d first), nothing else "
        "touched; the gate return is INLINE in the main FDE "
        "(0x6050cbb..0x6050d2e) -- .cold is unwind-only. (2) Page "
        "pad (0x6050d30..0x6050d5b + 0x6051488): pad = Roundup"
        "(cursize_, alignment_) - cursize_ via the div at 0x6050d4f; "
        "if pad != 0, memset(bufstart_ + cursize_, 0, pad) and "
        "cursize_ += pad (PadToAlignmentWith(0)). (3) Checksum "
        "recompute over the pad (0x6050d61..0x6050d95), "
        "UNCONDITIONAL -- no perform_data_verification_ / "
        "buffered_data_with_checksum_ gate: buffered_data_crc32c_"
        "checksum_ = Crc32cCombine(old, crc32c::Extend(0, bufstart_ "
        "+ ENTRY cursize_, pad), pad) through the 0x61c25f0 Extend "
        "dispatch thunk and the 0x61c2600 Combine; the pad path "
        "(0x6051488) rejoins here after the memset, so the Extend "
        "reads the zeroed pad bytes. pad == 0 gives Extend(0, ptr, "
        "0) = 0 and Combine(old, 0, 0) = old ^ 0 = old (the "
        "degenerate combine has no len2==0 early return). "
        "file_advance = TruncateToPageBoundary(alignment_, ENTRY "
        "cursize_) and leftover_tail = entry cursize_ - "
        "file_advance are computed LAZILY at the success epilogue "
        "(0x60513e0..0x6051402) from the saved entry cursize_ (r13) "
        "and alignment (-0x210). (4) IOOptions + priority "
        "(0x6050d82..0x6050e79): the file's GetIOPriority (vtable "
        "slot 16, devirtualized when the slot equals the RELATIVE "
        "reloc at 0x64ecf30, else the virtual call at 0x6051740) "
        "feeds DecideRateLimiterPriority (0x604c800, census-bound, "
        "pure) with the op priority; a 0x58-byte IOOptions is built "
        "on the stack with the exact defaults (timeout 0, prio "
        "kIOLow 0, rate_limiter_priority the Decide result, type "
        "kUnknown 7, property_bag an empty unordered_map, "
        "force_dir_fsync 0, do_not_recurse 0). NO GetFileSize call "
        "and NO perf_level save/restore (both pinned differences "
        "from WriteBufferedWithChecksum). (5) Rate-limiter DRAIN "
        "(0x6050e80..0x6050ecf): while remaining > 0, "
        "RequestToken(remaining, buf_.Alignment(), decided, stats_ "
        "(this+0xa8), OpType kWrite = 1) through vtable slot 6 "
        "(base impl 0x61c43f0, census-bound); the grants are "
        "DISCARDED -- the write below is one PositionedAppend of "
        "the whole padded buffer. The drain runs only when "
        "rate_limiter_ (this+0xa0) is non-null AND the decided "
        "priority != IO_TOTAL (4) AND left != 0. (6) TEST_SYNC_POINT "
        "gate (0x6050ed1, helper 0x606d9f0; upstream name "
        "'WritableFileWriter::Flush:BeforeAppend', binary literals "
        "stripped). (7) Nanos-guard setup: armed iff perf_level > 2 "
        "(clock = *SystemClock::Default() 0x5fe2680, dereferenced "
        "once; start = NowNanos, vtable slot 20; TLS counter at "
        "fs-0x3f8+0x28). The CPU half is DEAD in this FDE: the "
        "flag byte -0x18f is written 0 at 0x6050eff and never set, "
        "the second clock slot -0x170 is never filled, and no "
        "clock-or-default helper is called, so the slot-22 stop at "
        "0x6051331 is unreachable and the stop always takes the "
        "NowNanos branch (0x6051768). (8) Listener start times "
        "(0x6050f7e..0x6050fb0): only when listeners_ (this+0xb0) is "
        "non-empty, steady_clock::now() + system_clock::now(). (9) "
        "Checksum handoff (0x6050fb7..0x6050fd3), UNCONDITIONAL: "
        "checksum_buf = EncodeFixed32(buffered_data_crc32c_"
        "checksum_) -- the value AFTER the pad recompute -- and "
        "v_info.checksum = Slice(checksum_buf, 4); there is no "
        "verification gate, so the PositionedAppend ALWAYS goes "
        "through vtable slot 5 (with checksum) -- the pinned "
        "difference from WriteDirect, whose per-chunk checksum is "
        "a FRESH Extend gated ONLY on perform_data_verification_. "
        "(10) The single PositionedAppend (0x6050fda..0x6051043): "
        "file->PositionedAppend(Slice{bufstart_, left}, "
        "write_offset, io_options, v_info, nullptr) through "
        "vtable slot 5 (0x605101b). It runs even when left == 0 -- "
        "the entry-empty path makes a ZERO-LENGTH PositionedAppend "
        "carrying the recomputed buffered checksum, unlike "
        "WriteDirect, which skips its loop entirely. The result "
        "is saved to a 16-byte stack IOStatus at -0x160(%rbp), "
        "then copied as bytes 0-1, 3-4, 5, 8-15 with byte 2 forced "
        "to 0. (11) Listener events: finish always (type 1 = "
        "kWrite, vtable slot 34 = 0x110, skipping the base no-op "
        "0x604c660; offset = write_offset, length = left, elapsed "
        "= steady now - start steady, status CopyState deep copy "
        "at 0x61cf610); failure only when the status is not OK "
        "(type 9 = kPositionedAppend, vtable slot 47 = 0x178, "
        "skipping the base no-op 0x6042c20; trailing u64s (size, "
        "write_offset) -- exactly upstream NotifyOnIOError(s, "
        "kPositionedAppend, file_name(), size, write_offset)). "
        "(12) Failure return (0x60512ad..0x6051377): cursize_ = "
        "ENTRY cursize_ (buf_.Size(file_advance + leftover_tail)); "
        "the buffered checksum is recomputed FRESH as "
        "crc32c::Extend(0, bufstart_, ENTRY cursize_) -- seed 0, "
        "NOT a Combine; seen_error_ = 1 AFTER the notifications; "
        "the sret is built (byte 2 forced to 0); the nanos guard "
        "stops at 0x6051315..0x6051365 after the sret build; the "
        "IOOptions property_bag is destroyed (0x5d36110); no "
        "retry; flushed_size_ is NOT advanced. (13) Success path "
        "(0x6051380..0x6051480): the nanos guard stops at 0x60516f0 "
        "when armed; TEST_SYNC_POINT at 0x6051398; then -- when "
        "the TLS flag at fs-0x3f8+0x98 is clear -- a third "
        "TEST_SYNC_POINT at 0x60513c0 and the TLS counter at "
        "fs-0x3f8+0x8 advances by left; flushed_size_ += left "
        "(the PADDED cursize). (14) Success epilogue "
        "(0x60513e0..0x6051480): if leftover_tail != 0, "
        "buf_.RefitTail(file_advance, leftover_tail) (memmove at "
        "0x6051750); the buffered checksum is recomputed FRESH as "
        "crc32c::Extend(0, bufstart_, leftover_tail) -- seed 0, "
        "so an entry-empty success RESETS it to 0; "
        "next_write_offset_ += file_advance; cursize_ = "
        "leftover_tail; the sret copy (byte 0 forced to 0 -- the "
        "status is OK -- byte 2 forced to 0); the property_bag is "
        "destroyed; the stack canary is checked. filesize_ is "
        "NEVER advanced here.")
    functions["0x6050b8a"]["model"] = (
        "243-byte .cold landing pad, entered by the single tail "
        "jump at 0x60518de (one of the fourteen endbr64 stubs at "
        "the main FDE tail, 0x6051895..0x6051932; twelve others "
        "jump to interior .cold addresses and one jumps to "
        "another stub): destroy the file_name_ string copy, "
        "delete[] the saved sret state_ when non-null, stop the "
        "timer guard through the shared destructor 0x604c6b6, "
        "destroy the IOOptions property_bag, check the stack "
        "canary, then _Unwind_Resume or __stack_chk_fail. "
        "Unwind-only; no case exercises it.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-writable-file-writer-flush-115 "
            "(open, PR #6057): reconstructs WritableFileWriter::Flush "
            "0x6051a20, which calls WriteDirectWithChecksum at "
            "0x60523b1 (verified by this packet's caller census -- "
            "the ONLY caller in the whole .text, its direct-I/O "
            "write step, only when pending_sync_ is set) and which "
            "took it as an input oracle, leaving it as a follow-up. "
            "This packet supersedes that oracle note with the full "
            "body model.",
            "RE-002-node115-rocksdb-writable-file-writer-append-115 "
            "(open, PR #6041): reconstructs WritableFileWriter::Append "
            "0x6054680 and pins the same 0xe0 writer layout, the "
            "same seen-error gate (code 5, 27-byte heap state_) and "
            "the same sret move-assign shape; its tool scaffolding "
            "is the template for this packet's oracles.",
            "RE-002-node115-rocksdb-writable-file-writer-writebuffered-115 "
            "(open, PR #6088): reconstructs WritableFileWriter::WriteBuffered "
            "0x604e140, whose per-chunk crc32c::Extend dispatch "
            "(slots 2/3) is the closest sibling to WriteDirect's "
            "verification arm. CORRECTION (found during the #6094 "
            "cycle while cross-checking): the #6088 packet cites "
            "WriteBuffered as upstream lines 544-636, but the raw "
            "v8.1.1 file writable_file_writer.cc puts WriteBuffered "
            "at lines 1040-1217 (its 544-636 range is inside "
            "Close/Flush); the line citation in #6088 is wrong and "
            "is fixed in-PR separately. The binary model in #6088 "
            "is unaffected.",
            "RE-002-node115-rocksdb-writable-file-writer-writebufferedwithchecksum-115 "
            "(open, PR #6094): reconstructs "
            "WritableFileWriter::WriteBufferedWithChecksum "
            "0x604f080; its tool and packet scaffolding are the "
            "direct template for this packet. "
            "WriteDirectWithChecksum differs from it in the pinned "
            "ways: a DRAIN loop plus ONE PositionedAppend (slot 5, "
            "always with the checksum) instead of a DRAIN loop plus "
            "one Append (slot 3); the buffered checksum RECOMPUTED "
            "over the pad (Combine with a fresh Extend) and handed "
            "off, instead of the buffered value handed off as-is; "
            "NO GetFileSize call and NO perf_level save/restore; a "
            "DEAD CPU timer-guard half instead of one armed iff "
            "perf_level > 3; a failure event of type 9 "
            "(kPositionedAppend, trailing (size, write_offset)) "
            "instead of type 8 (kAppend, trailing (left, "
            "old_size)); a failure epilogue that restores cursize_ "
            "to the ENTRY value AND recomputes the buffered "
            "checksum fresh over the entry buffer, instead of "
            "clearing buf_ and resetting the checksum to 0; and a "
            "zero-length PositionedAppend on the entry-empty path "
            "instead of a zero-length Append.",
            "RE-002-node115-rocksdb-writable-file-writer-writedirect-115 "
            "(open, PR #6204): reconstructs "
            "WritableFileWriter::WriteDirect 0x604fe80; its tool "
            "and packet scaffolding are the direct template for "
            "this packet. WriteDirectWithChecksum differs from it "
            "in the pinned ways: the checksum is RECOMPUTED over "
            "the pad (Combine) and handed off, UNCONDITIONALLY, "
            "instead of a FRESH crc32c::Extend per chunk gated ONLY "
            "on perform_data_verification_; the rate-limiter loop "
            "is a DRAIN whose grants are discarded, followed by ONE "
            "PositionedAppend (slot 5, always), instead of a "
            "per-chunk grant loop with one PositionedAppend per "
            "chunk (slots 4/5); the entry-empty path makes a "
            "zero-length PositionedAppend instead of skipping the "
            "loop; the failure path recomputes the buffered "
            "checksum fresh over the entry buffer instead of "
            "leaving it untouched; the success epilogue recomputes "
            "it fresh over the leftover tail instead of leaving it "
            "untouched.",
            "RE-002-node115-vendor-census: WriteDirectWithChecksum "
            "itself has NO census record (body hash only, per the "
            "#5992 no-census convention); "
            "WriteDirectWithChecksum.cold IS census-bound (body "
            "hash matches target_body_sha256 exactly; source hash "
            "reproduced by zeroing the 12 recorded relocations, "
            "kinds 2/4; no kind-42 relocation, so no GOTPCRELX "
            "restoration applies).",
            "facebook/rocksdb v8.1.1, read live this cycle (raw "
            "files): file/writable_file_writer.cc "
            "WriteDirectWithChecksum (lines 1645-1857) confirms "
            "the packet step for step -- the seen-error gate "
            "(AssertFalseAndGetStatusForPrevError), the page pad "
            "(PadToAlignmentWith(0)), the checksum recompute over "
            "the pad (buffered_data_crc32c_checksum_ = "
            "Crc32cCombine(buffered, Crc32c::Value of the pad "
            "bytes, pad)), the IOOptions build with "
            "DecideRateLimiterPriority, the rate-limiter drain "
            "(RequestToken(remaining, buf_.Alignment(), ...) until "
            "the remainder is 0, grants discarded), the single "
            "PositionedAppend carrying the recomputed buffered "
            "checksum, the listener events (NotifyOnWriteCompleted "
            "/ NotifyOnIOError with kPositionedAppend), the "
            "failure path (buf_.Size(file_advance + "
            "leftover_tail), the buffered checksum recomputed as "
            "Value of the remaining buffer, set_seen_error() after "
            "the events, return s), and the success epilogue "
            "(RefitTail, next_write_offset_ += file_advance, "
            "cursize_ = leftover_tail, the buffered checksum "
            "recomputed as Value of the tail). WriteDirect (lines "
            "1449-1642) is the sibling this packet is templated "
            "on. "
            "util/aligned_buffer.h pins the AlignedBuffer layout "
            "(alignment_ +0x00, buf_ +0x08, capacity_ +0x10, "
            "cursize_ +0x18, bufstart_ +0x20) and "
            "file/writable_file_writer.h pins the writer layout. "
            "The failure event type 9 is "
            "FileOperationType::kPositionedAppend "
            "(include/rocksdb/listener.h:449-473, implicit 0-based: "
            "kRead 0, kWrite 1, kTruncate 2, kClose 3, kFlush 4, "
            "kSync 5, kFsync 6, kRangeSync 7, kAppend 8, "
            "kPositionedAppend 9, kOpen 10) -- exactly upstream "
            "NotifyOnIOError(s, kPositionedAppend, file_name(), "
            "size, write_offset) in WriteDirectWithChecksum (lines 1783-1785). "
            "Binary-vs-source observations, recorded not hidden: "
            "the binary has NO GetFileSize call and NO perf_level "
            "save/restore, while WriteBufferedWithChecksum has "
            "both; the binary's CPU timer-guard half is dead "
            "(upstream's IOSTATS_TIMER_GUARD has both halves, but "
            "the binary never arms the CPU side here); the binary "
            "computes file_advance / leftover_tail lazily at the "
            "epilogue from the saved entry cursize_, while upstream "
            "computes them up front; the binary runs the "
            "success-path sync point (0x6051398) BEFORE the "
            "IOSTATS_ADD(bytes_written) while upstream lists the "
            "bytes add first (same observable behaviour, a "
            "scheduling difference); upstream's post-epilogue "
            "'if (!s.ok()) set_seen_error()' is unreachable in "
            "practice (failures return early) and has no "
            "counterpart in the binary epilogue; upstream names "
            "the loop's TEST_SYNC_POINT "
            "'WritableFileWriter::Flush:BeforeAppend', while the "
            "binary's string literals are stripped, so per-site "
            "names are not pinned from the binary; the binary "
            "recomputes the buffered checksum over the pad "
            "UNCONDITIONALLY (upstream's WriteDirectWithChecksum "
            "asserts perform_data_verification_ and "
            "buffered_data_with_checksum_ -- the asserts are "
            "compiled out, so the binary takes the checksum path "
            "for every call).",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "targets, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "WritableFileWriter::WriteDirectWithChecksum "
                "0x6050c80: exactly 1 direct call, 0 tail jumps, 0 "
                "LEA refs. The only caller is "
                "rocksdb::WritableFileWriter::Flush "
                "0x6051a20..0x605257c (call site 0x60523b1) -- its "
                "direct-I/O write step, only when pending_sync_ is "
                "set. No other caller exists in the whole .text.",
                "WritableFileWriter::WriteDirectWithChecksum.cold "
                "0x6050b8a: exactly 1 tail jump at 0x60518de (one of "
                "the fourteen endbr64 stubs at the main FDE tail, "
                "0x6051895..0x6051932) -- the exception landing-pad "
                "entry. No call sites. (Twelve other stubs jump to "
                "interior .cold addresses; one jumps to another "
                "stub.)",
                "WriteDirectWithChecksum calls "
                "file->PositionedAppend (vtable slot 5, with "
                "checksum, ALWAYS) through the file pointer, not by "
                "direct call -- so no direct call sites for those "
                "appear in the scan; the slot number is pinned by "
                "the disassembly and the bindings group. It calls "
                "no other WritableFileWriter member directly: no "
                "Flush, Pad, RangeSync, WriteBuffered or WriteDirect "
                "call exists in the FDE.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 gate (seen-error, entry cursize/capacity/"
                     "alignment, priorities 0..4, perf level 0..5, "
                     "sync point, clock pairs, flag_d9, file names, "
                     "scripted PositionedAppend failures, iostats "
                     "flag; the verification flags vary only as "
                     "inert state -- the checksum recompute and "
                     "handoff are UNCONDITIONAL; a zero cursize "
                     "still makes ONE zero-length PositionedAppend "
                     "carrying the recomputed buffered checksum, and "
                     "the success epilogue resets the buffered "
                     "checksum to 0) + 600 drain (the grant matrix: "
                     "cursize vs the scripted rate-limiter grants -- "
                     "single grant, exact split, grant exhaustion, "
                     "tiny grants -- the grants are DISCARDED and "
                     "the write is ONE PositionedAppend of the whole "
                     "padded buffer at next_write_offset_; a "
                     "scripted PositionedAppend failure restores "
                     "cursize_ to the entry value, recomputes the "
                     "buffered checksum fresh over the entry buffer, "
                     "and advances nothing; listeners + the nanos "
                     "guard armed, the CPU half never armed; iostats "
                     "flag; file image pre-filled; "
                     "next_write_offset_ starts) + 600 checksum (the "
                     "pad recompute is pinned -- buffered = "
                     "Combine(old, Extend(0, pad bytes, pad), pad) "
                     "-- for pad 0 and pad > 0; the handoff is the "
                     "recomputed buffered value through slot 5 "
                     "whatever the verification flags say; "
                     "PositionedAppend failures recompute the "
                     "buffered checksum fresh over the entry buffer; "
                     "success recomputes it fresh over the leftover "
                     "tail, or to 0 when the leftover is 0; refit "
                     "rows) + 600 bindings (body hashes for "
                     "WriteDirectWithChecksum, .cold, "
                     "WriteBufferedWithChecksum, .cold, WriteBuffered, "
                     ".cold, Flush, WriteDirect, RangeSync, Append, "
                     "DecideRateLimiterPriority, UpdateFileChecksum, "
                     "the CRC value helper, the timer-guard "
                     "destructor; two census records; 2 "
                     "caller-census sites; vtable slots 4/5/6/16/34/"
                     "47; 30 writer-layout offsets; IOOptions "
                     "defaults; 25-cell priority matrix; "
                     "FileOperationType 1/9; "
                     "WriteDirectWithChecksum call-site constants; "
                     "CRC vectors incl. check vector '123456789' -> "
                     "0xE3069283, Combine identities, checksum-"
                     "recompute unit rows, AlignedBuffer unit rows "
                     "incl. pad_to_alignment and refit_tail, "
                     "timer-guard thresholds with cpu_armed always "
                     "False, file-selection matrix)",
            "tests": "tests/test_writable_file_writer_writedirectwithchecksum115.py",
            "tool": "tools/writable_file_writer_writedirectwithchecksum115.py",
            "what_is_checked": [
                "gate: seen_error returns code 5 with the 27-byte "
                "heap state_ and writes nothing; entry-empty "
                "cursize 0 returns OK with ONE zero-length "
                "PositionedAppend (no file write, no flushed_size_ "
                "advance, no refit) and the buffered checksum reset "
                "to 0; a decided IO_TOTAL priority skips "
                "RequestToken even when a limiter exists; the pad "
                "rounds cursize_ up to the alignment with zeros; "
                "the verification flags do NOT change the outcome "
                "(the checksum recompute and handoff are "
                "unconditional)",                "drain: the grant matrix is replayed exactly "
                "(grant sizes, file bytes, cursize_, flushed_size_, "
                "next_write_offset_, wdwc_grants, "
                "wdwc_positioned_appends, wdwc_pad, "
                "wdwc_file_advance, wdwc_leftover_tail); the grants "
                "are discarded and the write is ONE PositionedAppend "
                "of the whole padded buffer at next_write_offset_; "
                "the pad + positional write lands at "
                "next_write_offset_ and the tail is refit (memmove) "
                "with next_write_offset_ advanced by file_advance "
                "only; a PositionedAppend failure restores cursize_ "
                "to the ENTRY value, recomputes the buffered "
                "checksum fresh over the entry buffer, sets "
                "seen_error_ after the notifications, and advances "
                "nothing; grant exhaustion falls back to granted = "
                "remaining for the tail grant",                "checksum: the checksum in the positioned_append "
                "event equals Combine(entry buffered, Extend(0, pad "
                "bytes, pad), pad) -- the recomputed buffered value, "
                "never a fresh per-chunk Extend and never the entry "
                "value alone when pad > 0; the append ALWAYS goes "
                "through slot 5 whatever the verification flags say; "
                "a PositionedAppend failure recomputes the buffered "
                "checksum fresh as Extend(0, entry buffer); a "
                "success recomputes it fresh over the leftover tail, "
                "or to 0 when the leftover is 0",                "bindings: both FDE body hashes match the binary; "
                "the .cold source hash is reproduced by zeroing its "
                "12 recorded relocations; the 1 call site and 1 "
                "jump site are pinned; vtable slots 5/6/16 and "
                "the listener slots 34/47; the 30 writer-layout "
                "offsets incl. the unnamed bool at +0xd9; IOOptions "
                "defaults (0x58 B image, type 7, "
                "rate_limiter_priority at +0x0c); the 25-cell "
                "DecideRateLimiterPriority matrix; FileOperationType "
                "kWrite 1 and the observed failure type 9; the three "
                "TEST_SYNC_POINT sites; the timer-guard thresholds "
                "(nanos armed iff perf_level > 2, CPU NEVER armed); "
                "CRC check vector, Combine == Value(a+b), "
                "Mask/Unmask round-trip; checksum-recompute unit "
                "rows (Combine == Value(data + pad zeros)); "
                "pad_to_alignment and refit_tail unit rows; file "
                "selection raw vs wrapper",
            ],
        },
        "engine_callees": {
            "0x6051a20": "WritableFileWriter::Flush (census-bound, "
                        "2908 B + 228 B .cold): the oracle this packet "
                        "uses for the live check's final flush; it "
                        "calls WriteDirectWithChecksum at 0x60523b1 "
                        "(the caller-census site in this packet, its "
                        "direct-I/O write step, only when "
                        "pending_sync_ is set), WriteDirect at "
                        "0x60520b9, and WriteBuffered at 0x6051cc5. "
                        "Implemented here at the #6057 "
                        "fidelity: buffered/direct write step, "
                        "listener start times + finish/failure events, "
                        "IOOptions with DecideRateLimiterPriority, "
                        "file_->Flush, and the RangeSync arm.",
            "0x6054680": "WritableFileWriter::Append (census-bound, "
                        "2827 B + 124 B .cold): the oracle that pins "
                        "the writer layout; it calls "
                        "WriteBufferedWithChecksum at 0x6054ed9 and "
                        "0x605507b (its two verification arms) and "
                        "WriteBuffered at 0x6054d23. Implemented here "
                        "at the #6041 fidelity.",
            "0x604e140": "WritableFileWriter::WriteBuffered "
                        "(no census, oracle): 3533 B, reconstructed in "
                        "#6088. It differs from the function "
                        "reconstructed here in exactly the pinned "
                        "ways -- its rate-limiter loop passes "
                        "alignment 0 (not buf_.Alignment()), its "
                        "zero-size path is a clearing write with no "
                        "Append, its checksum dispatch is per-chunk "
                        "between slot 2 and slot 3, and its failure "
                        "clears buf_ + checksum immediately after the "
                        "failed Append, before the notifications. Its "
                        "tool and packet scaffolding are the template "
                        "for this packet; its upstream line citation "
                        "(544-636) is WRONG -- the correct range is "
                        "1040-1217 (see bound_context).",
            "0x604f080": "WritableFileWriter::WriteBufferedWithChecksum "
                        "(no census, oracle): 3351 B, reconstructed in "
                        "#6094. Its tool and packet scaffolding are "
                        "the direct template for this packet; it "
                        "differs from WriteDirect in the pinned ways "
                        "listed in bound_context (DRAIN loop + one "
                        "Append, buffered-checksum handoff, GetFileSize "
                        "call, perf save/restore, live CPU guard, "
                        "failure type 8, failure clears buf_).",
            "0x604fe80": "WritableFileWriter::WriteDirect "
                        "(no census, oracle): 3338 B, reconstructed in "
                        "#6204. It differs from the function "
                        "reconstructed here in exactly the pinned "
                        "ways -- its rate-limiter loop is per-chunk "
                        "(one PositionedAppend per grant, slots 4/5), "
                        "its checksum is a FRESH crc32c::Extend per "
                        "chunk gated ONLY on perform_data_verification_, "
                        "its entry-empty path skips the loop entirely "
                        "(no PositionedAppend), and its failure and "
                        "success epilogues leave the buffered checksum "
                        "untouched. Its tool and packet scaffolding "
                        "are the direct template for this packet.",
            "0x6050c80": "WritableFileWriter::WriteDirectWithChecksum "
                        "(no census): 3255 B -- THE FUNCTION "
                        "RECONSTRUCTED IN THIS PACKET (see the model "
                        "field of functions['0x6050c80']).",
            "0x604d7b0": "WritableFileWriter::RangeSync (no census, "
                        "oracle): the member the Flush oracle's arm "
                        "calls; own seen-error gate, TEST_SYNC_POINT, "
                        "timer guard, listener events, file->RangeSync "
                        "slot 23.",
            "0x604c800": "WritableFileWriter::DecideRateLimiterPriority "
                        "(census-bound, 39 B): both IO_TOTAL -> "
                        "IO_TOTAL; file TOTAL -> op; op TOTAL -> file; "
                        "else op. Called by the WriteDirect IOOptions "
                        "build (0x604ff7e..0x605007d) and by the Flush "
                        "oracle.",
            "0x604c7e0": "The 19-byte CRC value helper (no census): "
                        "xor edi,edi; call 0x61c25f0 -- crc32c::Extend"
                        "(0, data, size), the per-chunk CRC helper. "
                        "WriteDirect CALLS it once per chunk when "
                        "perform_data_verification_ is set; "
                        "WriteDirectWithChecksum does NOT call it -- "
                        "it calls the 0x61c25f0 Extend dispatch thunk "
                        "directly (0x6050d6d, 0x60512ba, 0x6051418) "
                        "for the pad / failure / success recomputes.",
            "0x61c2600": "crc32c::Crc32cCombine dispatch thunk: "
                        "WriteDirectWithChecksum calls it at 0x6050d7d "
                        "to fold the pad Extend into the buffered "
                        "checksum (Combine(old, pad_crc, pad)). "
                        "Combine(crc1, crc2, 0) returns crc1 ^ crc2 "
                        "-- there is no len2==0 early return (the "
                        "degenerate combine is live, per #6041 / "
                        "#5726).",
            "0x61c25f0": "crc32c::Extend dispatch thunk: the CRC "
                        "helper calls it as Extend(0, data, size). "
                        "Resolves to ExtendImpl<Slow_CRC32> 0x61c21d0 "
                        "per the #6012 packet; the table-driven Python "
                        "Extend is bit-identical to the slow path.",
            "0x61c43f0": "RateLimiter::RequestToken (base impl, "
                        "census-bound, 359 B): the virtual call the "
                        "drain step makes through vtable slot 6 with "
                        "(remaining, buf_.Alignment(), decided "
                        "priority, stats_, OpType kWrite = 1). The "
                        "model takes the granted count from the "
                        "scripted limiter oracle; the base impl's own "
                        "body is not reconstructed here.",
            "0x5fe2680": "SystemClock::Default (census-bound, 214 B): "
                        "returns the default clock handle; the binary "
                        "dereferences it once to get the clock object "
                        "used by the nanos timer guard.",
            "0x604c6b6": "IOSTATS_TIMER_GUARD destructor (no census, "
                        "82 B): dispatches on the guard's cpu-flag "
                        "byte (+1): 0 -> NowNanos (slot 20), 1 -> the "
                        "CPU-time accessor (slot 22); adds the elapsed "
                        "time to the guard's counter when the armed "
                        "flag (+0) is set; calls the second clock's "
                        "CPU-time accessor with the guard id when the "
                        "second clock (+0x20) is non-null (null in "
                        "WriteDirectWithChecksum). Runs only from "
                        ".cold (unwind); the main-FDE stops are "
                        "inline: the nanos guard stops at 0x60516f0 "
                        "(success) and 0x6051315..0x6051365 (failure, "
                        "after the sret build); the slot-22 stop at "
                        "0x6051331 is UNREACHABLE -- the CPU half is "
                        "never armed.",
            "0x61cf610": "Status state_ deep copy (census-bound, 63 "
                        "B; the census labels it Status::CopyState, "
                        "but the call sites pass (dst, src) -- a "
                        "two-argument store form, so the name is "
                        "recorded as an open unknown): allocates a "
                        "copy of the source C-string and stores the "
                        "new pointer at *dst. Used for the status in "
                        "both listener events.",
            "0x606d9f0": "TEST_SYNC_POINT helper (no census): the "
                        "sync-point gate, called from the three sites "
                        "0x6050ed1, 0x6051398, 0x60513c0 when the "
                        "sync-point global *0x64ed5d0 is non-null. The "
                        "string names are not asserted.",
            "0x604c660": "Base EventListener no-op skipped by the "
                        "write-finish notification (vtable slot 34).",
            "0x6042c20": "Base EventListener no-op skipped by the "
                        "failure notification (vtable slot 47, shared "
                        "by WriteDirect, WriteBufferedWithChecksum, "
                        "WriteBuffered, Flush and RangeSync).",
            "0x5df6e90": "Base FSWritableFile::GetIOPriority ('mov "
                        "0x18(%rdi),%eax; ret'): the devirtualization "
                        "guard compares vtable slot 16 against the "
                        "RELATIVE reloc at 0x64ecf30; when equal the "
                        "binary reads file+0x18 directly, else the "
                        "virtual call at 0x6051740.",
            "0x5d36110": "std::_Hashtable dtor for the IOOptions "
                        "property_bag, called on every WriteDirect "
                        "exit path (success epilogue, failure return, "
                        ".cold).",
            "0x63f0d70": "PLT __stack_chk_fail (the stack-canary "
                        "failure path in the main epilogue and in .cold).",
            "0x63f0dc0": "PLT operator delete[] _ZdaPv (the seen-error "
                        "gate's delete of the old sret state_ and the "
                        ".cold deletes).",
            "0x63f0e30": "PLT operator new[] _Znam (the 27-byte heap "
                        "state_ in the seen-error gate).",
            "0x63f0a50": "PLT _Unwind_Resume (the .cold landing pad).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this "
                               "VM. The target binary is never executed. "
                               "The tool models the routine in Python; "
                               "the callees Flush, Append, "
                               "WriteBuffered, "
                               "WriteBufferedWithChecksum, "
                               "WriteDirectWithChecksum, RangeSync and "
                               "the file's PositionedAppend are taken "
                               "as scripted oracles, and the live engine "
                               "check drives the model against a real "
                               "file and asserts the model's file image "
                               "equals the real file bytes after every "
                               "WriteDirect (a real file, not the node "
                               "binary). make verify/test/"
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
                "+0x38": "clock_ (SystemClock*, 8) -- not read here "
                         "(the CPU-guard clock is never consulted: "
                         "the CPU half is dead)",
                "+0x40": "buf_ (AlignedBuffer: alignment_ +0x40, buf_ "
                         "+0x48, capacity_ +0x50, cursize_ +0x58, "
                         "bufstart_ +0x60) -- read: alignment_ by the "
                         "grant step and the pad; written: cursize_ "
                         "+= pad, then = leftover_tail on success, "
                         "= entry cursize_ on failure",
                "+0x58": "buf_.cursize_ (size_t, 8) -- written: += "
                         "pad at the pad step; = leftover_tail in "
                         "the success epilogue; = entry cursize_ in "
                         "the failure return",
                "+0x68": "max_buffer_size_ (size_t, 8) -- not read",
                "+0x70": "filesize_ (uint64, 8) -- NEVER read or "
                         "written here (pinned: no GetFileSize call "
                         "and no advance in the epilogue)",
                "+0x78": "flushed_size_ (uint64, 8) -- written: += "
                         "left (the PADDED cursize) on success only "
                         "(NOT advanced on failure)",
                "+0x80": "next_write_offset_ (uint64, 8) -- read: "
                         "the write offset of every chunk and both "
                         "listener events; written: += file_advance "
                         "in the success epilogue",
                "+0x88": "pending_sync_ (bool, 1) -- not read or "
                         "written here (Flush reads it to decide "
                         "whether to call WriteDirect)",
                "+0x89": "seen_error_ (bool, 1) -- read: the gate "
                         "(first read in the FDE); written: = 1 on a "
                         "failed PositionedAppend, after the "
                         "notifications, in the failure return",
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
                         "(FileChecksumGenerator*, 8) -- NOT read "
                         "(UpdateFileChecksum is the member that uses "
                         "it)",
                "+0xd0": "checksum_finalized_ (bool, 1) -- not read",
                "+0xd1": "perform_data_verification_ (bool, 1) -- "
                         "NOT consulted here (pinned: the checksum "
                         "recompute and handoff are UNCONDITIONAL; "
                         "upstream's asserts are compiled out)",
                "+0xd4": "buffered_data_crc32c_checksum_ (uint32, 4) "
                         "-- READ and WRITTEN: the pad recompute "
                         "folds the pad Extend into it (Combine), the "
                         "handoff passes it, the failure path resets "
                         "it to Extend(0, entry buffer), and the "
                         "success epilogue resets it to Extend(0, "
                         "leftover tail)",
                "+0xd8": "buffered_data_with_checksum_ (bool, 1) -- "
                         "NOT consulted (pinned: the checksum "
                         "recompute and handoff are UNCONDITIONAL)",
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
            "write_direct_with_checksum_call": {
                "pad": "PadToAlignmentWith(0): pad = Roundup(cursize_, "
                       "alignment_) - cursize_ (div at 0x6050d4f); if "
                       "pad != 0, memset(bufstart_ + cursize_, 0, "
                       "pad) at 0x6051488 and cursize_ += pad. "
                       "file_advance = TruncateToPageBoundary"
                       "(alignment_, ENTRY cursize_) and leftover_tail "
                       "= entry cursize_ - file_advance are computed "
                       "LAZILY at the success epilogue "
                       "(0x60513e0..0x6051402).",
                "checksum_recompute": "buffered_data_crc32c_checksum_ "
                       "= Crc32cCombine(old, crc32c::Extend(0, "
                       "bufstart_ + ENTRY cursize_, pad), pad) at "
                       "0x6050d61..0x6050d95 (Extend thunk 0x61c25f0, "
                       "Combine 0x61c2600), UNCONDITIONAL; the pad "
                       "path rejoins here after the memset, so the "
                       "Extend reads the zeroed pad bytes. pad == 0 "
                       "gives Combine(old, 0, 0) = old.",
                "drain": "while remaining > 0 (0x6050e80..0x6050ecf): "
                        "RequestToken(remaining, alignment_, decided, "
                        "stats_, kWrite = 1) through vtable slot 6; "
                        "the grants are DISCARDED -- the write below "
                        "is one PositionedAppend of the whole padded "
                        "buffer. Runs only when rate_limiter_ is "
                        "non-null AND decided != IO_TOTAL AND left "
                        "!= 0.",
                "nanos_guard": "armed iff perf_level > 2; clock = "
                               "*SystemClock::Default(); start = "
                               "NowNanos (slot 20); counter at "
                               "fs-0x3f8+0x28; stops inline at "
                               "0x60516f0 (success) / "
                               "0x6051315..0x6051365 (failure, after "
                               "the sret build)",
                "cpu_guard": "NEVER armed in this FDE (pinned): the "
                             "flag byte -0x18f is written 0 at "
                             "0x6050eff and never set, the second clock "
                             "slot -0x170 is never filled, and no "
                             "clock-or-default helper is called, so the "
                             "slot-22 stop at 0x6051331 is unreachable "
                             "and the stop always takes the NowNanos "
                             "branch (0x6051768). wdwc_cpu_nanos is 0 "
                             "at every perf level.",
                "positioned_append": "slot 5 ALWAYS, with "
                                     "Slice{&EncodeFixed32(buffered_"
                                     "data_crc32c_checksum_), 4} -- the "
                                     "value AFTER the pad recompute. "
                                     "The result is saved to a "
                                     "16-byte stack IOStatus at "
                                     "-0x160(%rbp), then copied as "
                                     "bytes 0-1, 3-4, 5, 8-15 with byte "
                                     "2 forced to 0. Runs even when "
                                     "left == 0 (zero-length append).",
                "failure": "finish + failure events (type 9, trailing "
                           "(size, write_offset)); cursize_ = ENTRY "
                           "cursize_; the buffered checksum is "
                           "recomputed FRESH as Extend(0, bufstart_, "
                           "ENTRY cursize_); seen_error_ = 1 (AFTER "
                           "the notifications); nanos stop; return "
                           "status (byte 2 = 0); no retry; "
                           "flushed_size_ NOT advanced",
                "success": "finish event; nanos stop; sync-point "
                           "0x6051398; sync-point 0x60513c0 + bytes "
                           "counter += left (flag clear); "
                           "flushed_size_ += left (the PADDED "
                           "cursize); next_write_offset_ += "
                           "file_advance; cursize_ = leftover_tail; "
                           "the buffered checksum is recomputed FRESH "
                           "as Extend(0, bufstart_, leftover_tail); "
                           "RefitTail when leftover_tail != 0",
            },
            "status_16": {
                "+0x00": "code (uint8)",
                "+0x01": "subcode (uint8)",
                "+0x02": "severity (uint8) -- forced to 0 on every "
                         "WriteDirectWithChecksum return path (gate, "
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
            "The CPU half of the timer guard is DEAD in this FDE: "
            "the flag byte at -0x18f is written 0 at 0x6050eff and "
            "never set, the second clock slot at -0x170 is never "
            "filled, and no clock-or-default helper is called, so "
            "the slot-22 stop at 0x6051331 is unreachable and the "
            "stop always takes the NowNanos branch (0x6051768). The "
            "model records wdwc_cpu_nanos = 0 at every perf level, "
            "and the bindings group pins timer_guard_cpu_armed = "
            "False for perf levels 0..5. This is a pinned difference "
            "from both siblings, whose CPU halves are armed iff "
            "perf_level > 3.",
            "file_advance and leftover_tail are computed LAZILY at "
            "the success epilogue (0x60513e0..0x6051402) from the "
            "saved entry cursize_ (r13) and alignment (-0x210), "
            "not up front: the pad step only rounds cursize_ up, "
            "and the single PositionedAppend writes the whole "
            "padded buffer. The failure path restores cursize_ from "
            "the same two saved values (file_advance + leftover_tail "
            "= entry cursize_).",
            "Three TEST_SYNC_POINT gates fire PER CALL "
            "(0x6050ed1 drain-head, 0x6051398 success-path, "
            "0x60513c0 bytes-add), all through the helper 0x606d9f0 "
            "when the sync-point global *0x64ed5d0 is non-null. The "
            "bytes-add gate fires only when the IOStats-bytes flag "
            "is clear -- it sits between the flag check and the "
            "bytes add. The string names are not asserted; the "
            "model records the site addresses. The binary runs the "
            "success-path sync point BEFORE the "
            "IOSTATS_ADD(bytes_written) while upstream lists the "
            "bytes add first -- same observable behaviour, a "
            "scheduling difference.",
            "The checksum is RECOMPUTED over the pad and handed "
            "off, UNCONDITIONALLY: the binary calls the 0x61c25f0 "
            "Extend dispatch thunk with (0, bufstart_ + ENTRY "
            "cursize_, pad) and the 0x61c2600 Combine with (old, "
            "pad_crc, pad) before the write, with no "
            "perform_data_verification_ / buffered_data_with_"
            "checksum_ gate anywhere in the FDE, and passes the "
            "result through vtable slot 5 on every call. The live "
            "check pins this (the positioned_append event carries "
            "Combine(0x12345678, Value(501 zero bytes), 501), never "
            "the entry buffered value alone and never a fresh "
            "per-chunk Extend). This is the pinned difference from "
            "WriteDirect (fresh per-chunk Extend, gated ONLY on "
            "perform_data_verification_) and from "
            "WriteBufferedWithChecksum (handoff of the buffered "
            "value as-is, no pad recompute). The failure and "
            "success epilogues recompute the buffered checksum "
            "FRESH (seed 0) over the entry buffer and the leftover "
            "tail respectively -- so an entry-empty success resets "
            "it to 0.",
            "The rate-limiter drain DISCARDS its grants: the binary "
            "loops RequestToken until the remainder is 0, then "
            "makes ONE PositionedAppend of the whole padded buffer. "
            "The grants change nothing about the write -- only "
            "whether the drain runs at all (limiter non-null AND "
            "decided != IO_TOTAL AND left != 0). The live check "
            "pins this (grants [4096, 4096] drain, one 8192-byte "
            "append).",
            "The entry-empty path makes ONE zero-length "
            "PositionedAppend: cursize 0 skips the drain (je "
            "0x6050ed1) but the call at 0x6050fda still runs with "
            "size 0, carrying the recomputed buffered checksum "
            "(pad 0, so Combine leaves it unchanged). The success "
            "epilogue then runs with file_advance = 0, leftover = "
            "0, no file write, no flushed_size_ advance and no "
            "refit -- and the buffered checksum is reset to 0 "
            "(fresh Extend over 0 bytes). The live check pins this "
            "(empty_buffer_zero_length_append). This is the pinned "
            "difference from WriteDirect, which skips its loop "
            "entirely, and the parallel of "
            "WriteBufferedWithChecksum's zero-length Append.",
            "WriteDirectWithChecksum makes NO GetFileSize call "
            "and does NO perf_level save/restore -- both pinned "
            "differences "
            "from WriteBufferedWithChecksum, which calls GetFileSize "
            "once (return discarded) and saves/restores the TLS "
            "perf_level byte around the Append. filesize_ is never "
            "read or written here.",
            "The failure event's type 9 IS "
            "FileOperationType::kPositionedAppend -- resolved by "
            "the live v8.1.1 read (include/rocksdb/listener.h:"
            "449-473, implicit 0-based: kRead 0, kWrite 1, "
            "kTruncate 2, kClose 3, kFlush 4, kSync 5, kFsync 6, "
            "kRangeSync 7, kAppend 8, kPositionedAppend 9, kOpen "
            "10), matching upstream NotifyOnIOError(s, "
            "kPositionedAppend, file_name(), size, write_offset) "
            "in WriteDirectWithChecksum (lines 1783-1785). It "
            "follows the "
            "sibling pattern exactly: Flush's failure event "
            "carries its own op (4 = kFlush) and RangeSync's "
            "carries 7 = kRangeSync. The two trailing u64 fields "
            "are ordered (size, write_offset) -- the values passed to "
            "upstream NotifyOnIOError(s, kPositionedAppend, "
            "file_name(), size, write_offset) -- and size is the "
            "PADDED size (left), not a drain grant. The model "
            "emits 9 exactly as observed. PINNED DIFFERENCE from "
            "WriteBufferedWithChecksum, whose failure event trails "
            "(left, old_size) with type 8.",
            "The failure return restores cursize_ to the ENTRY "
            "value (buf_.Size(file_advance + leftover_tail)), "
            "recomputes the buffered checksum FRESH as Extend(0, "
            "bufstart_, ENTRY cursize_), and sets seen_error_ AFTER "
            "the listener notifications (0x60512ad..0x60512c5), "
            "while WriteBufferedWithChecksum clears buf_ and resets "
            "the checksum to 0 after the events and WriteBuffered "
            "clears immediately after the failed Append, before the "
            "events -- a pinned ordering difference between the "
            "three siblings. The nanos guard stops after the sret "
            "build on the failure path (0x6051315..0x6051365), so a "
            "failed call's nanos elapsed time is still recorded but "
            "its bytes are never added to the IOStats counter.",
            "The success epilogue recomputes the buffered checksum "
            "FRESH as Extend(0, bufstart_, leftover_tail) AFTER "
            "the RefitTail memmove -- so the Extend reads the tail "
            "bytes at their new position (the buffer start), not "
            "their old one. An entry-empty success (leftover 0) "
            "resets the checksum to 0. The live check pins this "
            "(the buffered checksum after the 5000-byte write "
            "equals Value of the 904-byte tail).",
            "The 0x61cf610 helper is a two-argument deep copy: the "
            "call sites set rdi = &dst (a stack slot) and rsi = "
            "src, and read the copy back from the slot after the "
            "call. The vendor census labels it Status::CopyState "
            "(one-arg signature), which does not match the observed "
            "calling convention; the name is recorded as an open "
            "unknown and the behaviour (deep copy, store at *dst) "
            "is what the model pins.",
            "The 16-byte IOStatus copy drops byte 2 on every return "
            "path: the working status is copied as bytes 0-1, 3-4, "
            "5, 8-15 with byte 2 forced to 0 (the code bytes spill "
            "at -0x1d1..-0x1d5, the high bytes of the low qword in "
            "reverse order, byte 2 never stored). The same shape "
            "holds in the siblings; the model reproduces it via "
            "Status.out_bytes().",
            "WriteDirectWithChecksum itself has no census record, "
            "while its .cold does -- the same split as Flush "
            "(#6057), Append (#6041) and "
            "WriteBufferedWithChecksum (#6094), whose mains are also "
            "body-hash-only. The packet binds the main by its "
            "recomputed body hash and the .cold by the census record "
            "(12 relocations).",
            "The only caller in the whole .text is Flush "
            "(0x6051a20 at 0x60523b1) -- WriteDirectWithChecksum is "
            "Flush's direct-I/O write step, reached only when "
            "pending_sync_ is set. No other member calls it; "
            "Append's verification arms call "
            "WriteBufferedWithChecksum, not WriteDirectWithChecksum; "
            "WriteDirect is Flush's other direct-I/O step (site "
            "0x60520b9).",
        ],
        "unknowns": [
            "The TLS flag byte at fs-0x3f8+0x98 gating the IOStats "
            "bytes counter (+0x8) add: its identity is open. "
            "Modelled as iostats_bytes_flag (default clear = count).",
            "The 0x61cf610 helper's symbol: the census labels it "
            "Status::CopyState (one arg) but the call sites pass "
            "(dst, src). Recorded as an open unknown; the deep-copy "
            "behaviour is pinned.",
            "The TEST_SYNC_POINT string names in "
            "WriteDirectWithChecksum: the binary's literals are "
            "stripped (verified absent from the node #115 binary), "
            "so no per-site name is pinned from the binary. "
            "Upstream v8.1.1 names the loop's TEST_SYNC_POINT "
            "'WritableFileWriter::Flush:BeforeAppend'; the binary "
            "calls the sync-point helper 0x606d9f0 from three sites "
            "(0x6050ed1, 0x6051398, 0x60513c0). The model records "
            "the three site addresses.",
            "The bool at this+0xd9, read into the finish event: it "
            "is not named by the Append packet's writer layout and "
            "no upstream header in the 2019 mirror has a member at "
            "that offset. Modelled as flag_d9 and listed here as an "
            "open unknown (shared with the Flush packet).",
            "The initial v_info checksum-pointer lea at 0x6050db4 "
            "(lea 0x4376fd into -0x1c0(%rbp)): it is overwritten "
            "with the checksum_buf address at 0x6050fd3 before the "
            "PositionedAppend, so the initial value is never read "
            "by the call; its target (a static address in .rodata) "
            "is not named here.",
            "Flush, Append, WriteBuffered, "
            "WriteBufferedWithChecksum, WriteDirect and "
            "the RangeSync member are taken as oracles here (their "
            "bodies are separate FDEs; only "
            "WriteDirectWithChecksum.cold is census-bound in this "
            "packet). Their internal steps are modelled from the "
            "#6057/#6041/#6088/#6094/#6204 contracts and upstream "
            "source, not from their own binary bodies in this "
            "packet.",
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
