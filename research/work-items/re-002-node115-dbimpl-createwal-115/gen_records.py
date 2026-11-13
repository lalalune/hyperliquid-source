#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
range. CreateWAL AND CreateWAL.cold are BOTH census-bound: each
body hash matches the census target_body_sha256 exactly and each
source hash is reproduced by zeroing the recorded relocations
(main: 52 relocations, kinds 2/4/42, with the GOTPCRELX mov-lea
opcode restored at the two relaxed sites; .cold: 13 kind-4
relocations).
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
    ("0x5e5c270", "0x5e5c9a3",
     "rocksdb::DBImpl::CreateWAL",
     "dbimpl-createwal-5e5c270", True),
    ("0x5e5c1a0", "0x5e5c26e",
     "rocksdb::DBImpl::CreateWAL.cold",
     "dbimpl-createwal-cold-5e5c1a0", True),
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
        assert census_bound, name
        rec = by_start[start]
        assert body_hash == rec["target_body_sha256"], name
        zeroed = bytearray(body)
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
            if rel.get("relaxation") == "gotpcrelx-mov-lea":
                # GOTPCRELX relaxation: the linker rewrote the
                # source's MOV (0x8B) into a LEA (0x8D); restore
                # the MOV opcode before hashing.
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
    main_calls = [s for s in sites if s["target"] == "0x5e5c270"]
    cold_jumps = [s for s in sites if s["target"] == "0x5e5c1a0"]
    functions["0x5e5c270"]["callers"] = [s["site"] for s in main_calls]
    functions["0x5e5c1a0"]["callers"] = [s["site"] for s in cold_jumps]
    functions["0x5e5c270"]["model"] = (
        "1843-byte IOStatus DBImpl::CreateWAL(uint64_t log_file_num, "
        "uint64_t recycle_log_number, size_t preallocate_block_size, "
        "log::Writer** new_log) (sret 16-byte out-pointer in rdi, "
        "DBImpl* in rsi, log_file_num in rdx, recycle_log_number in "
        "rcx, preallocate_block_size in r8, new_log in r9). (1) "
        "BuildDBOptions (0x60c2e20) into a stack DBOptions temp "
        "(-0x2d0) from immutable_db_options_ (this+0x330) and "
        "mutable_db_options_ (this+0x5a0); the temp is destroyed "
        "at the epilogue (DBOptions dtor 0x5d354b0). (2) fs "
        "selection + OptimizeForLogWrite (0x5e5c2fd..0x5e5c379): "
        "the fs_ FileSystemPtr at this+0x570 is {shared_ptr fs "
        "+0x570/+0x578, shared_ptr io_tracer_ +0x580/+0x588, "
        "shared_ptr fs_with_tracer_ +0x590/+0x598}; if io_tracer_ "
        "is null, or the byte at +0x68 of the tracer object is 0, "
        "the raw fs_ is used, else the tracer-wrapped fs at "
        "+0x590; the selected shared_ptr is copied (refcount++, "
        "plain or lock addl by the __gthread_active_p flag at "
        "0x64ed290) and released after the call "
        "(_Sp_counted_base::M_release 0x5d350c0); the virtual call "
        "is fs->OptimizeForLogWrite(&opt_file_options, "
        "&file_options_ [this+0x838], &db_options) through vtable "
        "slot 0x198, and the returned FileOptions (stack, -0x3d0) "
        "is the options used for every later file call. (3) "
        "wal_dir (0x5e5c379..0x5e5c3aa): GetWalDir (0x60a1500, not "
        "in the vendor census) returns a pointer to a std::string: "
        "&wal_dir (immutable+0x98) when its size (+0xa0) is "
        "non-zero, else the string pointer stored at immutable+0x60 "
        "(the dbname string) -- exactly upstream wal_dir.empty() ? "
        "dbname : wal_dir; the local wal_dir copy (-0x330) is built "
        "from the returned string's [ptr, ptr+size) by the libstdc++ "
        "range helper 0x5e57bf0. (4) log_fname "
        "(0x5e5c3af..0x5e5c3ca): LogFileName (0x603d050, "
        "census-bound) into -0x310: MakeFileName (0x603cb70) formats "
        '"%06llu.%s" with the number and "log" (format string at '
        "0x4394a1, type string \"log\" at 0x44fd57) and joins "
        "wal_dir + \"/\" + that. (5) Recycle branch, only when "
        "recycle_log_number != 0 (0x5e5c7c8..0x5e5c86f): "
        "ROCKS_LOG_INFO (0x5fcf060) on immutable_db_options_.info_log "
        "(this+0x360) with \"reusing log %llu from recycle list\"; "
        "old_log_fname = LogFileName(wal_dir, recycle_log_number) "
        "(-0x2f0); then fs->ReuseWritableFile(log_fname, "
        "old_log_fname, opt_file_options, &lfile, nullptr) through "
        "vtable slot 0xc8, with the fs selected by a FileSystemPtr "
        "copy (0x5d50400). The two upstream TEST_SYNC_POINTs have NO "
        "binary call in this FDE -- compiled out. The non-recycle "
        "branch (0x5e5c3f9..0x5e5c429) calls the free function "
        "NewWritableFile (0x6048500, census-bound): "
        "NewWritableFile(fs, log_fname, &lfile, opt_file_options). "
        "(6) Status check (0x5e5c42e..0x5e5c497): the returned "
        "IOStatus is moved into the return slot (rbx); if not OK, "
        "return at once -- no writer is built and *new_log is never "
        "written. (7) On OK (0x5e5c49d..0x5e5c535): "
        "lfile->SetWriteLifeTimeHint (vtable slot 0x70) with the "
        "constant 2 (WriteLifeTimeHint kWLTHShort) -- "
        "CalculateWALWriteHint() has no separate call site; its "
        "result is the constant 2 in this build -- then "
        "lfile->SetPreallocationBlockSize (vtable slot 0x98) with "
        "preallocate_block_size. (8) WritableFileWriter "
        "(0x5e5c4c6..0x5e5c535): operator new 0xe0 bytes, then the "
        "ctor (0x5e5ba60, census-bound) with (std::move(lfile), "
        "log_fname, opt_file_options, immutable_db_options_.clock "
        "[this+0x540], io_tracer_ [this+0x320], nullptr stats, "
        "listeners [this+0x470], nullptr checksum_gen, "
        "Contains(kWalFile), Contains(kWalFile)) -- the two trailing "
        "bools are the SAME value pushed twice: (this+0x520 & 1), the "
        "bit-0 test on checksum_handoff_file_types; the ctor stores "
        "bool 1 into perform_data_verification_ (+0xd1) and bool 2 "
        "into buffered_data_with_checksum_ (+0xd8), verified in the "
        "ctor body (0x5e5bd3f..0x5e5bd5e). (9) log::Writer "
        "(0x5e5c53e..0x5e5c58a): operator new 0x58 bytes, then the "
        "ctor (0x5f04c00, census-bound) with (std::move(file_writer), "
        "log_file_num, recycle_log_file_num > 0 [this+0x400 != 0], "
        "manual_wal_flush [this+0x4c5 byte], wal_compression "
        "[this+0x4c6 byte]); the recycle flag comes from the IMMUTABLE "
        "option recycle_log_file_num, not from the recycle_log_number "
        "argument. The ctor moves the file_writer pointer into its "
        "dest_ and zeroes the source slot (0x5f04c2e: movq $0, "
        "(%rsi)). (10) *new_log = the new log::Writer "
        "(0x5e5c58f..0x5e5c5a0), THEN io_s = "
        "(*new_log)->AddCompressionTypeRecord() (0x5f041d0, "
        "census-bound; sret into the io_s slot) -- so on an "
        "AddCompressionTypeRecord failure the caller still receives "
        "the writer in *new_log and the failure status. (11) Dead "
        "Close guard (0x5e5c60c..0x5e5c70e): after the status is "
        "copied to the return slot, the binary loads the file_writer "
        "slot (-0x3f0) and, if non-null, calls "
        "WritableFileWriter::Close (0x6052b80, census-bound) and then "
        "runs the inlined WritableFileWriter destructor (release "
        "checksum_generator_, clear listeners_, free buf_, tear down "
        "the FSWritableFile wrapper with devirtualization, dispose "
        "file_name_, operator delete 0xe0). The slot is NULLED by the "
        "log::Writer ctor's move (step 9), so on the normal path the "
        "guard is false and the sequence is skipped; the Close result, "
        "if it ran, would land in the already-moved-from io_s slot and "
        "be discarded (the return value was already copied to rbx). "
        "The upstream v8.1.1 source has no Close call here. (12) "
        "Epilogue (0x5e5c713..0x5e5c79c): dispose the log_fname / "
        "wal_dir / old_log_fname strings, destroy the DBOptions temp, "
        "release the fs shared_ptr copy, check the stack canary, "
        "return the status in rbx.")
    functions["0x5e5c1a0"]["model"] = (
        "206-byte .cold landing pad, entered by the single tail jump "
        "at 0x5e5c94a (one of the eight endbr64 stubs at the main FDE "
        "tail, 0x5e5c937..0x5e5c99e; the other seven jump to interior "
        ".cold addresses): delete the file_writer storage (0xe0) when "
        "non-null, dispose the log_fname / wal_dir strings, destroy "
        "the FileOptions property_bag (0x5d36110), destroy the "
        "DBOptions temp (0x5d354b0), release the fs shared_ptr copy "
        "(vtable slot 8), delete[] the saved sret state_ when "
        "non-null, check the stack canary, then _Unwind_Resume or "
        "__stack_chk_fail. Unwind-only; no case exercises it.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-writable-file-writer-append-115 "
            "(open, PR #6041): reconstructs "
            "WritableFileWriter::Append 0x6054680 and pins the 0xe0 "
            "writer layout (perform_data_verification_ +0xd1, "
            "buffered_data_with_checksum_ +0xd8, checksum_generator_ "
            "+0xc8, listeners_ +0xb0, buf_ +0x40) and the same sret "
            "move-assign shape this packet reuses; its "
            "DecideRateLimiterPriority / IOOptions notes are the "
            "template for the options handling here.",
            "RE-002-node115-rocksdb-writable-file-writer-flush-115 "
            "(open, PR #6057): reconstructs "
            "WritableFileWriter::Flush 0x6051a20, which calls "
            "CreateWAL's callees WriteBuffered / WriteDirect as its "
            "write step; it also names FDE 0x6052b80 as "
            "WritableFileWriter::Close (vendor-census symbol, "
            "verified live in this packet's disassembly: the seen-"
            "error gate at +0x89) -- the Close this packet's dead "
            "guard would call.",
            "RE-002-node115-rocksdb-writable-file-writer-writedirectwithchecksum-115 "
            "(open, PR #6215): reconstructs "
            "WritableFileWriter::WriteDirectWithChecksum 0x6050c80; "
            "its tool and packet scaffolding are the direct template "
            "for this packet.",
            "RE-002-node115-log-writer-addcompressiontyperecord-115 "
            "(submitted in the resumed run): reconstructs "
            "log::Writer::AddCompressionTypeRecord 0x5f041d0, the "
            "call CreateWAL makes last; this packet scripts that "
            "call's status (default OK) and does not model its "
            "record bytes.",
            "RE-002-node115-vendor-census: CreateWAL AND "
            "CreateWAL.cold are BOTH census-bound (member "
            "4d429ab1cb2d8f8b-db_impl_open.o, librocksdb-sys "
            "0.11.0+8.1.1): each body hash matches target_body_sha256 "
            "exactly and each source hash is reproduced by zeroing "
            "the recorded relocations (main: 52, kinds 2/4/42, two "
            "gotpcrelx-mov-lea restorations at offsets 1052 and "
            "1111; .cold: 13, kind 4). CORRECTION to the census "
            "symbol for 0x5d50400: the census names it "
            "FileSystemPtr::operator->, but its body is the "
            "FileSystemPtr COPY constructor (dest=rdi, src=rsi, "
            "copies src+0x00 or src+0x20 by the tracer rule, "
            "refcount++); the disassembly, not the census label, "
            "is what this packet follows.",
            "facebook/rocksdb v8.1.1, read live this cycle (the "
            "repo has since moved to meta/rocksdb): "
            "db/db_impl/db_impl_open.cc CreateWAL (lines 1715-1759) "
            "confirms the packet step for step -- BuildDBOptions, "
            "OptimizeForLogWrite, GetWalDir, LogFileName, the recycle "
            "branch (ROCKS_LOG_INFO 'reusing log %llu from recycle "
            "list', old LogFileName, ReuseWritableFile) vs "
            "NewWritableFile, the OK gate, SetWriteLifeTimeHint "
            "(CalculateWALWriteHint()) + SetPreallocationBlockSize, "
            "the WritableFileWriter construction (clock, io_tracer_, "
            "listeners, Contains(kWalFile) twice), the log::Writer "
            "construction (recycle_log_file_num > 0, manual_wal_flush, "
            "wal_compression), and AddCompressionTypeRecord as the "
            "last step. Binary-vs-source observations, recorded not "
            "hidden: the binary has NO TEST_SYNC_POINT call in the "
            "recycle branch (upstream names two, "
            "'DBImpl::CreateWAL:BeforeReuseWritableFile1/2'); the "
            "binary passes the constant 2 to SetWriteLifeTimeHint "
            "(CalculateWALWriteHint() has no separate call site); "
            "the binary contains a guarded WritableFileWriter::Close "
            "+ destroy sequence after AddCompressionTypeRecord that "
            "upstream does not have, and that sequence is unreachable "
            "on the normal path because the log::Writer ctor nulls "
            "the file_writer slot; the binary's GetWalDir returns a "
            "string POINTER (the caller copies it), while upstream "
            "declares a by-value return -- the observable behaviour "
            "(wal_dir when non-empty, else dbname) is identical.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "targets, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "DBImpl::CreateWAL 0x5e5c270: exactly 2 direct calls, "
                "0 tail jumps, 0 LEA refs. The callers are "
                "rocksdb::DBImpl::Open 0x5e62c50..0x5e65462 (call site "
                "0x5e63ea0) and rocksdb::DBImpl::SwitchMemtable "
                "0x5e8a890..0x5e8c518 (call site 0x5e8a9c6) -- both "
                "census-bound symbols. No other caller exists in the "
                "whole .text.",
                "DBImpl::CreateWAL.cold 0x5e5c1a0: exactly 1 tail jump "
                "at 0x5e5c94a (one of the eight endbr64 stubs at the "
                "main FDE tail, 0x5e5c937..0x5e5c99e) -- the exception "
                "landing-pad entry. No call sites. (The other seven "
                "stubs jump to interior .cold addresses.)",
                "CreateWAL calls its helpers through direct calls "
                "(BuildDBOptions, GetWalDir, LogFileName, "
                "NewWritableFile, the two ctors, "
                "AddCompressionTypeRecord, Close) and through vtable "
                "slots (OptimizeForLogWrite 0x198, "
                "ReuseWritableFile 0xc8, SetWriteLifeTimeHint 0x70, "
                "SetPreallocationBlockSize 0x98) -- the slots are "
                "pinned by the disassembly, not by the scan.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 gate (recycle vs new, scripted "
                     "NewWritableFile / ReuseWritableFile failures, "
                     "scripted AddCompressionTypeRecord failures, old "
                     "log contents 0/11/100 bytes; the open failure "
                     "returns the status with no writer and *new_log "
                     "untouched, while the compression-record failure "
                     "returns the status WITH *new_log assigned) + 600 "
                     "filenames (wal_dir empty vs set, dbname variants, "
                     "log numbers 0..123456789 incl. the 999999 / "
                     "1000000 boundary where %06llu grows to 7 digits, "
                     "recycle numbers incl. 999999 / 1000000; the join "
                     "is unconditional so an empty wal_dir gives "
                     "'/000007.log') + 600 writer_params (the "
                     "checksum-handoff bit matrix 0/1/2/3, recycle_log_"
                     "file_num 0/1/7/42, manual_wal_flush, "
                     "wal_compression 0/1/2, listener counts, tracer "
                     "present/enabled; both writer bools follow bit 0 "
                     "only, and the log::Writer recycle flag follows "
                     "the immutable option, not the recycle argument) "
                     "+ 600 bindings (full end-to-end traces incl. "
                     "open failures, compression-record failures, "
                     "recycle renames with 0/7/4096-byte old logs; the "
                     "Close guard is False in every case; body hashes "
                     "for CreateWAL and .cold; the 2 caller-census "
                     "sites + 1 .cold jump site; vtable slots "
                     "0x70/0x98/0xc8/0x198; the FileSystemPtr layout; "
                     "the DBImpl member offsets read by this FDE)",
            "tests": "tests/test_dbimpl_createwal115.py",
            "tool": "tools/dbimpl_createwal115.py",
            "what_is_checked": [
                "gate: the recycle branch renames the old log to the "
                "new name (bytes preserved, old name gone) and logs "
                "'reusing log N from recycle list'; a missing old log "
                "fails with code 5 and creates nothing; an open "
                "failure returns the status with no writer and "
                "*new_log untouched; an AddCompressionTypeRecord "
                "failure returns the status WITH *new_log assigned; "
                "the two TEST_SYNC_POINTs are recorded absent",
                "filenames: LogFileName is wal_dir + '/' + '%06llu' "
                "% n + '.log' for every tested n (0, 1, 7, 123, "
                "999999, 1000000, 1000001, 2**64-1, 123456789); an "
                "empty wal_dir falls back to dbname, and an empty "
                "wal_dir with dbname '' gives '/000007.log'",
                "writer_params: both WritableFileWriter bools "
                "(perform_data_verification_, "
                "buffered_data_with_checksum_) follow the bit-0 "
                "checksum-handoff test and nothing else; the "
                "log::Writer recycle flag follows "
                "recycle_log_file_num > 0 independently of the "
                "recycle_log_number argument; manual_wal_flush and "
                "wal_compression are recorded verbatim",
                "bindings: both FDE body hashes match the binary and "
                "both source hashes reproduce by zeroing the recorded "
                "relocations; the 2 call sites and 1 jump site are "
                "pinned; the Close guard is never taken; the live "
                "check drives real files and the model image equals "
                "the real file bytes after every CreateWAL",
            ],
        },
        "engine_callees": {
            "0x60c2e20": "BuildDBOptions (census-bound): "
                        "BuildDBOptions(immutable_db_options_, "
                        "mutable_db_options_) into the stack temp; the "
                        "temp is destroyed at the epilogue.",
            "0x60a1500": "ImmutableDBOptions::GetWalDir (NOT in the "
                        "vendor census): returns a pointer to a "
                        "std::string -- &wal_dir (immutable+0x98) when "
                        "its size (+0xa0) is non-zero, else the string "
                        "pointer stored at immutable+0x60 (the dbname "
                        "string). The local wal_dir copy is built from "
                        "[ptr, ptr+size).",
            "0x5e57bf0": "libstdc++ string range helper (NOT in the "
                        "census): builds the local wal_dir copy from "
                        "the returned string's [ptr, ptr+size).",
            "0x603d050": "LogFileName (census-bound): LogFileName(wal_"
                        "dir, number) -- MakeFileName (0x603cb70) "
                        "formats \"%06llu.%s\" (format at 0x4394a1, "
                        "type \"log\" at 0x44fd57) and joins "
                        "wal_dir + \"/\" + that.",
            "0x5d50400": "FileSystemPtr copy constructor (the census "
                        "names it FileSystemPtr::operator->, but the "
                        "body copies src+0x00 or src+0x20 by the "
                        "tracer rule, refcount++): dest=rdi, src=rsi. "
                        "Used in the recycle branch to materialize "
                        "the selected fs as a local shared_ptr.",
            "0x6048500": "NewWritableFile (census-bound): the free "
                        "function NewWritableFile(fs, log_fname, "
                        "&lfile, opt_file_options) on the non-recycle "
                        "branch.",
            "0x5e5ba60": "WritableFileWriter ctor (census-bound): "
                        "takes (file, fname, file_options, clock, "
                        "io_tracer, stats, listeners, checksum_gen, "
                        "bool, bool); stores bool 1 into "
                        "perform_data_verification_ (+0xd1) and bool 2 "
                        "into buffered_data_with_checksum_ (+0xd8); "
                        "takes use_direct_writes from FileOptions+0x90 "
                        "into +0xd9.",
            "0x5f04c00": "log::Writer ctor (census-bound): takes "
                        "(file_writer, log_number, recycle, "
                        "manual_wal_flush, wal_compression); moves the "
                        "file_writer pointer into dest_ and zeroes the "
                        "source unique_ptr (0x5f04c2e).",
            "0x5f041d0": "log::Writer::AddCompressionTypeRecord "
                        "(census-bound): the last call; its record "
                        "bytes are the sibling packet's subject, so "
                        "this model scripts its status (default OK).",
            "0x6052b80": "WritableFileWriter::Close (census-bound): "
                        "called only by the dead guard at 0x5e5c629 "
                        "(file_writer non-null) -- unreachable on the "
                        "normal path because the log::Writer ctor nulls "
                        "the slot.",
            "0x5fcf060": "ROCKS_LOG_INFO / Log (census-bound): the "
                        "'reusing log %llu from recycle list' line on "
                        "immutable_db_options_.info_log (this+0x360).",
            "0x5d350c0": "_Sp_counted_base::M_release (census-bound): "
                        "releases the copied fs shared_ptr after "
                        "OptimizeForLogWrite and in the epilogue / "
                        ".cold.",
            "0x5d354b0": "DBOptions dtor (census-bound): destroys the "
                        "stack DBOptions temp at the epilogue / .cold.",
            "0x5d36110": "std::_Hashtable dtor (census-bound): "
                        "destroys the FileOptions property_bag at the "
                        "epilogue / .cold.",
            "0x5d46140": "std::vector dtor (census-bound): clears the "
                        "listeners_ vector in the dead-guard "
                        "WritableFileWriter teardown.",
            "0x5e1b260": "Unidentified .cold helper (NOT in the "
                        "census): called once from the .cold landing "
                        "pad (0x5e5c24b) with a shared_ptr control "
                        "block; recorded as an open unknown, not "
                        "modelled.",
            "0x63f0d70": "PLT __stack_chk_fail (the stack-canary "
                        "failure path in the main epilogue and in "
                        ".cold).",
            "0x63f0dc0": "PLT operator delete[] _ZdaPv (the status "
                        "move-assign deletes and the .cold deletes).",
            "0x63f0a50": "PLT _Unwind_Resume (the .cold landing pad).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this "
                               "VM. The target binary is never executed. "
                               "The tool models the routine in Python; "
                               "the FileSystem, clock, listeners and "
                               "OptimizeForLogWrite internals are "
                               "recorded opaque calls, not reimplemented, "
                               "and the AddCompressionTypeRecord record "
                               "bytes are the sibling packet's subject. "
                               "The live engine check drives the model "
                               "against real files in a temp dir and "
                               "asserts the model file image equals the "
                               "real file bytes after every CreateWAL. "
                               "make verify/test/catalogue-check in a "
                               "tooled environment is still owed "
                               "upstream.",
        "functions": functions,
        "layouts": {
            "dbimpl_offsets": {
                "+0x320": "io_tracer_ (shared_ptr<IOTracer>, 16 B) -- "
                         "passed to the WritableFileWriter ctor (r9)",
                "+0x330": "immutable_db_options_ (ImmutableDBOptions) "
                         "-- BuildDBOptions arg 1; GetWalDir this; "
                         "info_log at +0x30 within it (this+0x360); "
                         "wal_dir string at +0x98 (size +0xa0); dbname "
                         "string pointer at +0x60",
                "+0x400": "immutable_db_options_.recycle_log_file_num "
                         "(uint64, 8) -- the log::Writer recycle flag "
                         "is (this+0x400 != 0)",
                "+0x470": "immutable_db_options_.listeners (vector, "
                         "24 B) -- passed to the WritableFileWriter "
                         "ctor",
                "+0x4c5": "immutable_db_options_.manual_wal_flush "
                         "(bool, 1) -- log::Writer ctor arg (r8)",
                "+0x4c6": "immutable_db_options_.wal_compression "
                         "(uint8, 1) -- log::Writer ctor arg (r9)",
                "+0x520": "immutable_db_options_.checksum_handoff_"
                         "file_types (FileTypeSet word, 8) -- bit 0 is "
                         "the kWalFile test, pushed twice to the "
                         "WritableFileWriter ctor",
                "+0x540": "immutable_db_options_.clock (SystemClock*, "
                         "8) -- WritableFileWriter ctor arg (r8)",
                "+0x570": "fs_ (FileSystemPtr, 48 B): shared_ptr fs "
                         "+0x570/+0x578, shared_ptr io_tracer_ "
                         "+0x580/+0x588, shared_ptr fs_with_tracer_ "
                         "+0x590/+0x598 -- the fs selection reads "
                         "io_tracer_ (null or +0x68 clear -> raw fs_ "
                         "at +0x570, else the wrapped fs at +0x590)",
                "+0x5a0": "mutable_db_options_ (MutableDBOptions) -- "
                         "BuildDBOptions arg 2",
                "+0x838": "file_options_ (FileOptions) -- "
                         "OptimizeForLogWrite arg",
            },
            "writer_0xe0": {
                "+0x00": "file_name_ (std::string, 32 B)",
                "+0x20": "writable_file_ (FSWritableFilePtr, 16 B)",
                "+0x38": "clock_ (SystemClock*, 8)",
                "+0x40": "buf_ (AlignedBuffer, 32 B)",
                "+0x68": "max_buffer_size_ (size_t, 8)",
                "+0x70": "filesize_ (uint64, 8)",
                "+0x78": "flushed_size_ (uint64, 8)",
                "+0x80": "next_write_offset_ (uint64, 8)",
                "+0x88": "pending_sync_ (bool, 1)",
                "+0x89": "seen_error_ (bool, 1) -- the Close gate",
                "+0x90": "last_sync_size_ (uint64, 8)",
                "+0x98": "bytes_per_sync_ (uint64, 8)",
                "+0xa0": "rate_limiter_ (shared_ptr, 16 B)",
                "+0xa8": "stats_ (shared_ptr, 16 B)",
                "+0xb0": "listeners_ (vector, 24 B)",
                "+0xc8": "checksum_generator_ (shared_ptr, 16 B)",
                "+0xd0": "checksum_finalized_ (bool, 1)",
                "+0xd1": "perform_data_verification_ (bool, 1) -- "
                         "ctor bool 1 (Contains(kWalFile))",
                "+0xd4": "buffered_data_crc32c_checksum_ (uint32, 4)",
                "+0xd8": "buffered_data_with_checksum_ (bool, 1) -- "
                         "ctor bool 2 (Contains(kWalFile))",
                "+0xd9": "bool (1) -- copied from the FileOptions "
                         "byte at +0x90 (the direct-write flag)",
            },
            "log_writer_0x58": {
                "+0x00": "dest_ (unique_ptr<WritableFileWriter>, 8) -- "
                         "moved in by the ctor, source nulled",
                "+0x08": "zero-initialized qword (name not pinned "
                         "from this FDE)",
                "+0x10": "log_number_ (uint64, 8) -- ctor arg rdx",
                "+0x18": "recycle flag (bool, 1) -- ctor arg cl "
                         "(recycle_log_file_num > 0)",
                "+0x1c": "type_crc_[10] (uint32 x 10) -- computed in "
                         "the ctor loop via the 0x61c25f0 Extend "
                         "dispatch thunk",
                "+0x44": "manual_flush (bool, 1) -- ctor arg r8b",
                "+0x45": "wal_compression (uint8, 1) -- ctor arg r9b",
            },
            "filesystem_ptr_0x30": {
                "+0x00": "fs_ (shared_ptr<FileSystem>, 16 B)",
                "+0x10": "io_tracer_ (shared_ptr<IOTracer>, 16 B) -- "
                         "its +0x68 byte is the tracing-enabled test",
                "+0x20": "fs_with_tracer_ (shared_ptr<FileSystem>, "
                         "16 B) -- used when the tracer is enabled",
            },
        },
        "observations": [
            "The two upstream TEST_SYNC_POINTs in the recycle branch "
            "have no binary call in this FDE (compiled out); the "
            "model records them as absent, with their upstream names.",
            "CalculateWALWriteHint() has no separate call site: the "
            "binary passes the constant 2 (kWLTHShort) to "
            "SetWriteLifeTimeHint (vtable slot 0x70).",
            "The dead Close guard (0x5e5c60c..0x5e5c70e) is the most "
            "notable binary-vs-source divergence in this packet: "
            "upstream v8.1.1 has no Close call in CreateWAL, but the "
            "binary loads the file_writer slot after "
            "AddCompressionTypeRecord and would Close + destroy it "
            "if non-null. The slot is provably null on the normal "
            "path (the log::Writer ctor zeroes it at 0x5f04c2e), so "
            "the sequence is recorded as a dead guard, never taken "
            "by the model.",
            "The census symbol for 0x5d50400 "
            "(FileSystemPtr::operator->) does not match its body, "
            "which is the FileSystemPtr copy constructor; the packet "
            "follows the disassembly.",
            "GetWalDir (0x60a1500) and the string range helper "
            "(0x5e57bf0) have no vendor census record; their behaviour "
            "is pinned from their bodies (GetWalDir: &wal_dir when "
            "non-empty, else the dbname string pointer at +0x60).",
            "The .cold helper 0x5e1b260 is unidentified (not in the "
            "census); it runs only on the unwind path and is not "
            "modelled.",
            "OptimizeForLogWrite's per-field tweaks are not modelled: "
            "the model passes the FileOptions through unchanged and "
            "records the call. The returned options are the ones used "
            "for NewWritableFile / ReuseWritableFile and for the "
            "WritableFileWriter ctor.",
            "The AddCompressionTypeRecord record bytes are not "
            "modelled here: that call is scripted (default OK) and "
            "its bytes are the sibling packet's subject. Live legs "
            "that assert file bytes use wal_compression 0.",
            "No /home/ paths appear in the packet excerpts: the "
            "objdump excerpts use the repo-relative binary path "
            "work/hl-node-115.bin (the #5857 defect class, avoided).",
        ],
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
    print("wrote records.json")


if __name__ == "__main__":
    main()
