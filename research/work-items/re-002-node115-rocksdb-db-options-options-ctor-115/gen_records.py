#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
ranges. Both FDEs are vendor-census-bound (member
d7ece8bd5f9dc186-options.o, librocksdb-sys 0.11.0+8.1.1); the source
hashes are reproduced exactly by zeroing the census relocations
(main: 28 relocations, kinds 2/4/42, no relaxation; .cold: 18
kind-4 relocations). The LSDA call-site tables were decoded from
.gcc_except_table with the repo's tools/fde_extents.py FDE index
(main LSDA at 0x422440, 53 bytes + 2-byte action table; .cold LSDA
at 0x42247c, 16 bytes; see records.json) and are recorded as data,
not re-derived here.
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
    ("0x60b3280", "0x60b3b87",
     "rocksdb::DBOptions::DBOptions",
     "db-options-options-ctor-60b3280", True),
    ("0x60b3154", "0x60b327a",
     "rocksdb::DBOptions::DBOptions.cold",
     "db-options-options-ctor-60b3154-cold", True),
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
        assert census_bound
        rec = by_start[start]
        assert body_hash == rec["target_body_sha256"], name
        zeroed = bytearray(body)
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
            if rel.get("relaxation") == "gotpcrelx-mov-lea":
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
    main_calls = [s for s in sites if s["target"] == "0x60b3280"]
    functions["0x60b3280"]["callers"] = [s["site"] for s in main_calls]
    functions["0x60b3280"]["model"] = (
        "2311-byte (explicit) Options constructor "
        "DBOptions::DBOptions(const Options&) (this in rdi = rbx; "
        "source Options in rsi = rbp; no +0x18 prologue bump). It "
        "memberwise-copies the DBOptions subobject out of an Options "
        "(Options inherits DBOptions first, so the subobject is at "
        "Options+0x00) into a whole 0x290-byte DBOptions. In binary "
        "order: (1) the 7 leading bools +0x00..0x06 as one u32 "
        "(+0x00), one u16 (+0x04) and one u8 (+0x06); env (+0x08) "
        "and the rate_limiter ptr word (+0x10) together in one "
        "movdqu (+0x08..+0x17); the rate_limiter ctrl word (+0x18) "
        "by plain mov, then the refcount at ctrl+0x8 bumped by the "
        "inlined addl/lock-addl pair (guard byte at GOT slot "
        "0x64ed290 selects the path; both increment by exactly 1). "
        "(2) Shared pointers, each as ptr word (plain mov or inside "
        "a 16-byte movdqu/movups chunk) + ctrl word (plain mov) + "
        "the inlined refcount bump: rate_limiter (+0x18), "
        "sst_file_manager (+0x28), info_log (+0x38), statistics "
        "(+0x60), write_buffer_manager (+0x160), row_cache (+0x200), "
        "file_checksum_gen_factory (+0x230), compaction_service "
        "(+0x280) -- eight field copies plus one per-element bump in "
        "the listeners loop (nine plain + nine lock addl sites in "
        "total). The copy SHARES each control block (refcount +1); "
        "it never deep-copies the pointed-to object. No call to the "
        "__shared_count copy helper 0x5d35c00 exists in this FDE. "
        "(3) Every scalar field copied verbatim by plain mov / "
        "movdqu / movups at the same offset as in the copy ctor "
        "(info_log_level, max_open_files, max_file_opening_threads, "
        "max_total_wal_size, use_fsync, "
        "delete_obsolete_files_period_micros, max_background_jobs, "
        "max_background_compactions, max_subcompactions, "
        "max_background_flushes, max_log_file_size, "
        "log_file_time_to_roll, keep_log_file_num, "
        "recycle_log_file_num, max_manifest_file_size, "
        "table_cache_numshardbits, WAL_ttl_seconds, "
        "WAL_size_limit_MB, manifest_preallocation_size, the "
        "mmap/direct bool quad (+0x128, u32), allow_fallocate / "
        "is_fd_close_on_exec (+0x12c, u16), stats_dump_period_sec, "
        "stats_persist_period_sec, persist_stats_to_disk, "
        "stats_history_buffer_size, advise_random_on_open, "
        "db_write_buffer_size, access_hint_on_compaction_start, "
        "compaction_readahead_size, random_access_max_buffer_size, "
        "writable_file_max_buffer_size, use_adaptive_mutex, "
        "bytes_per_sync, wal_bytes_per_sync, strict_bytes_per_sync, "
        "enable_thread_tracking, delayed_write_rate, the "
        "write-thread bool quad (+0x1d0, u32), "
        "max_write_batch_group_size_bytes, "
        "write_thread_max_yield_usec, write_thread_slow_yield_usec, "
        "the recovery quad (+0x1f0, u32), wal_filter (+0x208, raw "
        "ptr), the option-file bool run (+0x210..+0x217, u64), "
        "atomic_flush / avoid_unnecessary_blocking_io (+0x218, "
        "u16), write_dbid_to_manifest, log_readahead_size, "
        "best_efforts_recovery, max_bgerror_resume_count, "
        "bgerror_resume_retry_interval, allow_data_in_errors, "
        "checksum_handoff_file_types, lowest_used_cache_tier / "
        "enforce_single_del_contracts (+0x288, u16)). Padding bytes "
        "are never written. (4) db_paths vector (+0x70): zeroed "
        "first; if non-empty, byte size bounds-checked against "
        "0x7ffffffffffffff8 (else __throw_bad_array_new_length), "
        "operator new(size) allocates exactly size bytes (cap == "
        "end, no slack), then an INLINED element loop "
        "copy-constructs each DbPath (0x28 bytes: string at +0x0 "
        "via the inlined _M_construct pattern, target_size u64 at "
        "+0x20) and stores the new end. No call to __do_uninit_copy "
        "0x5d386a0 exists in this FDE. (5) Strings db_log_dir "
        "(+0x88), wal_dir (+0xa8), db_host_id (+0x250): each built "
        "by the INLINED _M_construct pattern (_M_create + memcpy "
        "for len > 15, SSO copy for len <= 15 with the len == 1 "
        "single-byte fast path and the len == 0 NUL-only path) "
        "after the dst ptr word is preset to its own SSO buffer; "
        "no call to basic_string::_M_construct 0x5d2e540 exists in "
        "this FDE. (6) listeners vector (+0x1a8): zeroed first; if "
        "non-empty, byte size bounds-checked against "
        "0x7ffffffffffffff0 (else __throw_bad_array_new_length), "
        "operator new(size) allocates exactly size bytes, then the "
        "inline loop copies each shared_ptr<EventListener> element "
        "(ptr word by movdqu, ctrl word by mov, refcount bumped by "
        "the inlined addl/lock-addl pair -- refcount +1 per "
        "element, shared not deep-copied). (7) Epilogue: "
        "stack-canary check, add $0x38,%rsp; pop "
        "rbx/rbp/r12/r13/r14/r15; ret.")
    functions["0x60b3154"]["model"] = (
        "294-byte .cold landing-pad FDE for DBOptions::DBOptions"
        "(const Options&). Entered only through the six endbr64 "
        "stubs at the end of the main FDE. It destroys the "
        "partially built object in reverse construction order and "
        "resumes unwinding: the db_paths element-copy pad "
        "(0x60b3154) begins a catch, _M_dispose's each constructed "
        "DbPath string walking FORWARD 0x28 at a time from the "
        "buffer start to the first unconstructed element, and "
        "rethrows; the rethrow call maps in this FDE's own LSDA to "
        "pad 0x60b324d (__cxa_end_catch, raw delete[] of the "
        "db_paths buffer, then the chain). The other entries "
        "release, in order, the file_checksum_gen_factory ctrl "
        "(+0x230), row_cache ctrl (+0x200), listeners vector dtor "
        "(0x5d46140), write_buffer_manager ctrl (+0x160), wal_dir "
        "string (r14), db_log_dir string (r13), db_paths vector "
        "dtor (0x5d35cb0), then the chain (statistics +0x60, "
        "info_log +0x38, sst_file_manager +0x28, rate_limiter "
        "+0x18, each _M_release if non-null) and _Unwind_Resume. "
        "It never touches the strings whose _M_create threw (still "
        "SSO) or compaction_service (+0x278, copied after the "
        "guarded region).")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-db-options-default-ctor-115 (open, "
            "PR #6337): reconstructs DBOptions::DBOptions() 0x60b2db0, "
            "which builds the 93 defaults this Options ctor copies "
            "field by field from the Options' DBOptions subobject. "
            "Copying the default image yields the default image "
            "byte-for-byte (sha256 "
            "ea59a732051f16d90fc6be9592a41045d12fd8786ba1a215acefb9fbd6c94533), "
            "verified by the tool's live check -- the two packets "
            "agree on the layout.",
            "RE-002-node115-rocksdb-db-options-copy-ctor-115 (open, "
            "PR #6338): reconstructs DBOptions::DBOptions(const "
            "DBOptions&) 0x5d38750, the same memberwise copy from a "
            "DBOptions source, with the shared_ptr/vector/string "
            "helpers as out-of-line calls (0x5d35c00, 0x5d386a0, "
            "0x5d2e540). This Options ctor inlines all of those "
            "helpers; the observable behaviour (field map, throw "
            "sites, landing-pad destruction lists) is identical.",
            "RE-002-node115-vendor-census: both FDEs are census-bound "
            "(member d7ece8bd5f9dc186-options.o, librocksdb-sys "
            "0.11.0+8.1.1). Body 7c4707c2... / source e9bc1ce7... "
            "(main, 28 relocations, kinds 2/4/42, no relaxation); "
            "body f1428783... / source de25ebd7... (.cold, 18 "
            "kind-4 relocations).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "options/options.cc:128-130 defines this ctor as a "
            "delegation to the copy ctor (DBOptions(const Options& "
            "options) : DBOptions(*static_cast<const DBOptions*>"
            "(&options)) {}), but the binary contains NO call to "
            "the copy ctor 0x5d38750 -- the compiler inlined the "
            "implicit copy ctor's memberwise body into this FDE "
            "(same TU, options.o), with the helpers inlined as "
            "well. include/rocksdb/options.h declares struct "
            "DBOptions (:447) with only DBOptions() (:967) and "
            "explicit DBOptions(const Options& options) (:969), "
            "and struct Options : public DBOptions, public "
            "ColumnFamilyOptions (:1399) -- DBOptions is the first "
            "base, so the subobject is at Options+0x00, which is "
            "why the binary reads the source at the DBOptions "
            "offsets.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "target, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "DBOptions::DBOptions(const Options&) 0x60b3280: "
                "exactly 6 direct calls, 0 tail jumps, 0 LEA refs. "
                "Every DB open entry point that takes a const "
                "Options& builds its DBOptions through this ctor: "
                "rocksdb_optimistictransactiondb_open_column_families "
                "0x5d39590 (site 0x5d396ff, census-bound, c.o), "
                "rocksdb::DB::Open 0x5e65530 (site 0x5e65578, "
                "census-bound, db_impl_open.o), "
                "rocksdb::DB::OpenForReadOnly 0x5e73160 (site "
                "0x5e73442, census-bound, db_impl_readonly.o), "
                "rocksdb::CompactedDBImpl::Open 0x5e79c30 (site "
                "0x5e79d2e, census-bound, compacted_db_impl.o), "
                "rocksdb::DB::OpenAsSecondary 0x5e81f00 (site "
                "0x5e81f5a, census-bound, db_impl_secondary.o) and "
                "rocksdb::DBWithTTL::Open 0x6207740 (site 0x6207796, "
                "census-bound, db_ttl_impl.o). DBImpl::Open "
                "0x5e62c50 is NOT a caller -- it takes a DBOptions, "
                "not an Options.",
                "The main LSDA call-site table was decoded from "
                ".gcc_except_table (LSDA at 0x422440, 53 bytes, "
                "header ff 9b 39 01 30 + 8 call-site entries, all "
                "action 0 except the db_paths element-copy entry, "
                "action 1 = a catch pad) plus a 2-byte action table "
                "(01 00) at 0x422475. The .cold LSDA is at 0x42247c "
                "(16 bytes, header ff 9b 15 01 0b + 2 entries). The "
                "db_paths element-copy pad begins a catch, disposes "
                "the constructed prefix walking FORWARD 0x28 at a "
                "time, and rethrows; the rethrow call maps in the "
                ".cold LSDA to the delete[] + chain pad 0x60b324d. "
                "The type-table entry the action-1 record names "
                "was not resolved statically (open unknown); the pad "
                "body calls __cxa_begin_catch with no type test and "
                "rethrows, and _M_create can only throw "
                "std::bad_alloc, so the modelled behaviour does not "
                "depend on it.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 fields (each of the 93 fields x value / "
                     "raw-bytes / full-image-hash probes, cycled "
                     "deterministically, source = defaults with one "
                     "field varied) + 600 containers (db_paths / "
                     "listeners / string variants across the SSO/heap "
                     "boundary, with destination heap contents and "
                     "shared refcounts) + 600 throw (the eight "
                     "throwing sites x the exact landing-pad "
                     "destruction list, incl. the .cold catch pad's "
                     "forward prefix disposal count) + 600 bindings "
                     "(caller-independence: the same image hash for "
                     "every one of the 6 callers, with varied host_id "
                     "and env id)",
            "tests": "tests/test_db_options_options_ctor115.py",
            "tool": "tools/db_options_options_ctor115.py",
            "what_is_checked": [
                "fields: every one of the 93 fields is copied "
                "verbatim from a varied source (value, raw bytes and "
                "full-image hash probes)",
                "containers: vectors are deep-copied into fresh "
                "buffers with cap == end (exact allocation, no "
                "slack); DbPath strings are deep-copied (fresh heap "
                "ids, same bytes; SSO pointers point inside the "
                "vector buffer); strings are deep-copied via the "
                "inlined _M_construct pattern (SSO <= 15, heap "
                "above); shared_ptrs share their control blocks "
                "with refcount +1, including every listeners element",
                "throw: each of the eight throwing sites raises the "
                "right exception (BadAlloc / BadArrayNewLength) and "
                "runs exactly the landing pad its LSDA entry names, "
                "in pad order; the db_paths element-copy throw "
                "disposes the constructed prefix in the .cold catch "
                "pad first (forward walk), then frees the buffer "
                "and runs the chain",
                "bindings: the copy result depends only on the "
                "source, never on which of the 6 callers runs it; "
                "both FDE body and source hashes match the binary "
                "and the census; both LSDAs match the binary; the "
                "copy map covers every scalar/shared_ptr word; the "
                "inlined refcount bumps are 9 plain + 9 lock sites; "
                "copying the defaults yields the defaults "
                "byte-for-byte (ea59a732...)",
            ],
        },
        "engine_callees": {
            "0x5d35cb0": "std::vector destructor (117 B; census "
                         "labels the same address "
                         "vector<TableReader::Anchor>::~vector -- the "
                         "element loop strides 0x28, frees a heap "
                         "string at +0x0 (SSO buffer +0x10) and "
                         "skips the u64 at +0x20, which is exactly "
                         "DbPath's layout, so the two instantiations "
                         "share the folded address): destroys the "
                         "db_paths vector in the pads.",
            "0x5d46140": "std::vector destructor (225 B; census "
                         "labels the same address "
                         "vector<shared_ptr<const SnapshotImpl>>::"
                         "~vector -- the element loop strides 0x10 "
                         "and releases each element's ctrl at +0x8, "
                         "which is exactly "
                         "vector<shared_ptr<EventListener>>'s layout, "
                         "so the two instantiations share the folded "
                         "address): destroys the listeners vector in "
                         "the db_host_id pad.",
            "0x5d350c0": "_Sp_counted_base::_M_release (133 B, "
                         "census-bound, cache.o): releases each "
                         "non-null shared_ptr control block in the "
                         "landing pads.",
            "0x63f0dd0": "PLT operator new: the db_paths buffer "
                         "(0x60b33ac) and the listeners buffer "
                         "(0x60b3724).",
            "0x63f0d80": "PLT operator delete[]: the db_paths buffer "
                         "in the rethrow pad 0x60b324d.",
            "0x63f0db0": "PLT basic_string::_M_dispose: destroys "
                         "the db_log_dir (+0x88) and wal_dir (+0xa8) "
                         "strings in the pads (a no-op for SSO "
                         "strings), and each constructed DbPath "
                         "string in the .cold catch pad.",
            "0x63f0ec0": "PLT __throw_bad_array_new_length: the "
                         "db_paths size check (0x60b3b20) and the "
                         "listeners size check (0x60b3b35).",
            "0x63f0e10": "PLT basic_string::_M_create: the heap "
                         "allocation inside the inlined _M_construct "
                         "pattern (4 sites: one db_paths element + "
                         "db_log_dir, wal_dir, db_host_id).",
            "0x63f0a60": "PLT memcpy: the string bytes inside the "
                         "inlined _M_construct pattern (4 sites).",
            "0x63f0d70": "PLT __stack_chk_fail: the canary failure "
                         "at the epilogue and in the length-throw "
                         "paths.",
            "0x63f0a50": "PLT _Unwind_Resume: the cleanup epilogue "
                         "in .cold.",
            "0x63f0e60": "PLT __cxa_begin_catch: the .cold db_paths "
                         "element-copy pad.",
            "0x63f0e70": "PLT __cxa_rethrow: the .cold db_paths "
                         "element-copy pad (its call site maps in "
                         "the .cold LSDA to the delete[] + chain pad "
                         "0x60b324d).",
            "0x63f0e80": "PLT __cxa_end_catch: the delete[] + chain "
                         "pad 0x60b324d.",
            "0x64ed290": "GOT slot holding the guard-byte address "
                         "for the inlined shared_ptr refcount bumps: "
                         "zero selects the lock-addl path, non-zero "
                         "the plain addl path; both increment the "
                         "refcount at ctrl+0x8 by exactly 1. The "
                         "slot is statically zero (a load-time "
                         "relocation), so the flag's identity is not "
                         "pinned statically (open unknown).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this VM. "
            "The target binary is never executed. The tool models the "
            "Options ctor in Python; heap addresses (string heap buffers, "
            "vector buffers, shared_ptr control blocks, env) are "
            "deterministic ids, not real pointers; src and dst are "
            "modelled at the same slot address (THIS_BASE), so their "
            "SSO pointers coincide -- what the copy pins is the "
            "values, not the addresses; padding bytes the ctor never "
            "writes are modelled as zero (the binary leaves them "
            "uninitialized). The live check (--live) reads the binary: "
            "both FDE body/source hashes, both LSDAs plus the action "
            "table, the 6-site caller census, the engine-call counts, "
            "the 9 plain + 9 lock refcount-bump sites, the copy-map "
            "coverage of every scalar/shared_ptr word, and the "
            "copy-of-defaults identity (13/13 legs). make "
            "verify/test/catalogue-check in a tooled environment is "
            "still owed upstream.",
        "functions": functions,
        "layouts": {
            "db_options": {
                "+0x00": "create_if_missing, "
                         "create_missing_column_families, error_if_exists, "
                         "paranoid_checks, flush_verify_memtable_count, "
                         "track_and_verify_wals_in_manifest, "
                         "verify_sst_unique_id_in_manifest (7 bools, "
                         "copied as u32 + u16 + u8)",
                "+0x08": "env (Env*, verbatim copy)",
                "+0x10": "rate_limiter (shared_ptr, shared)",
                "+0x20": "sst_file_manager (shared_ptr, shared)",
                "+0x30": "info_log (shared_ptr, shared)",
                "+0x40": "info_log_level (u8)",
                "+0x44": "max_open_files (i32)",
                "+0x48": "max_file_opening_threads (i32)",
                "+0x50": "max_total_wal_size (u64)",
                "+0x58": "statistics (shared_ptr, shared)",
                "+0x68": "use_fsync (bool)",
                "+0x70": "db_paths (vector<DbPath>, deep copy, "
                         "exact-size allocation, inlined element loop)",
                "+0x88": "db_log_dir (string, deep copy, inlined "
                         "_M_construct pattern)",
                "+0xa8": "wal_dir (string, deep copy, inlined "
                         "_M_construct pattern)",
                "+0xc8": "delete_obsolete_files_period_micros (u64)",
                "+0xd0": "max_background_jobs (i32)",
                "+0xd4": "max_background_compactions (i32)",
                "+0xd8": "max_subcompactions (u32)",
                "+0xdc": "max_background_flushes (i32)",
                "+0xe0": "max_log_file_size (u64)",
                "+0xe8": "log_file_time_to_roll (u64)",
                "+0xf0": "keep_log_file_num (u64)",
                "+0xf8": "recycle_log_file_num (u64)",
                "+0x100": "max_manifest_file_size (u64)",
                "+0x108": "table_cache_numshardbits (i32)",
                "+0x110": "WAL_ttl_seconds (u64)",
                "+0x118": "WAL_size_limit_MB (u64)",
                "+0x120": "manifest_preallocation_size (u64)",
                "+0x128": "allow_mmap_reads, allow_mmap_writes, "
                         "use_direct_reads, "
                         "use_direct_io_for_flush_and_compaction "
                         "(4 bools, copied as one u32)",
                "+0x12c": "allow_fallocate (bool)",
                "+0x12d": "is_fd_close_on_exec (bool)",
                "+0x130": "stats_dump_period_sec (u32)",
                "+0x134": "stats_persist_period_sec (u32)",
                "+0x138": "persist_stats_to_disk (bool)",
                "+0x140": "stats_history_buffer_size (u64)",
                "+0x148": "advise_random_on_open (bool)",
                "+0x150": "db_write_buffer_size (u64)",
                "+0x158": "write_buffer_manager (shared_ptr, shared)",
                "+0x168": "access_hint_on_compaction_start (i32)",
                "+0x170": "compaction_readahead_size (u64)",
                "+0x178": "random_access_max_buffer_size (u64)",
                "+0x180": "writable_file_max_buffer_size (u64)",
                "+0x188": "use_adaptive_mutex (bool)",
                "+0x190": "bytes_per_sync (u64)",
                "+0x198": "wal_bytes_per_sync (u64)",
                "+0x1a0": "strict_bytes_per_sync (bool)",
                "+0x1a8": "listeners (vector<shared_ptr<EventListener>>, "
                         "fresh buffer, elements shared)",
                "+0x1c0": "enable_thread_tracking (bool)",
                "+0x1c8": "delayed_write_rate (u64)",
                "+0x1d0": "enable_pipelined_write, unordered_write, "
                         "allow_concurrent_memtable_write, "
                         "enable_write_thread_adaptive_yield "
                         "(4 bools, copied as one u32)",
                "+0x1d8": "max_write_batch_group_size_bytes (u64)",
                "+0x1e0": "write_thread_max_yield_usec (u64)",
                "+0x1e8": "write_thread_slow_yield_usec (u64)",
                "+0x1f0": "skip_stats_update_on_db_open, "
                         "skip_checking_sst_file_sizes_on_db_open "
                         "(2 bools, copied as one u32 with "
                         "wal_recovery_mode + allow_2pc)",
                "+0x1f2": "wal_recovery_mode (u8)",
                "+0x1f3": "allow_2pc (bool)",
                "+0x1f8": "row_cache (shared_ptr, shared)",
                "+0x208": "wal_filter (ptr, verbatim copy)",
                "+0x210": "fail_if_options_file_error, dump_malloc_stats, "
                         "avoid_flush_during_recovery, "
                         "avoid_flush_during_shutdown, allow_ingest_behind, "
                         "two_write_queues, manual_wal_flush "
                         "(7 bools, copied as one u64 with wal_compression)",
                "+0x217": "wal_compression (u8)",
                "+0x218": "atomic_flush, avoid_unnecessary_blocking_io "
                         "(2 bools, copied as one u16)",
                "+0x21a": "write_dbid_to_manifest (bool)",
                "+0x220": "log_readahead_size (u64)",
                "+0x228": "file_checksum_gen_factory (shared_ptr, shared)",
                "+0x238": "best_efforts_recovery (bool)",
                "+0x23c": "max_bgerror_resume_count (i32)",
                "+0x240": "bgerror_resume_retry_interval (u64)",
                "+0x248": "allow_data_in_errors (bool)",
                "+0x250": "db_host_id (string, deep copy, inlined "
                         "_M_construct pattern)",
                "+0x270": "checksum_handoff_file_types (u64)",
                "+0x278": "compaction_service (shared_ptr, shared)",
                "+0x288": "lowest_used_cache_tier (u8)",
                "+0x289": "enforce_single_del_contracts (bool)",
            },
            "db_path": {
                "+0x00": "path (std::string, deep-copied by the inlined "
                         "_M_construct pattern)",
                "+0x20": "target_size (u64, verbatim copy)",
                "size": "0x28 (40 bytes)",
            },
            "lsda_call_sites": {
                "FDE+0x12c..+0x131": "operator new, db_paths (0x60b33ac) -- "
                                    "pad 0x60b3b7b -> .cold 0x60b31d9 "
                                    "(chain only)",
                "FDE+0x1da..+0x1df": "_M_create, db_paths element "
                                    "(0x60b345a) -- pad 0x60b3b3f, action "
                                    "1 (catch) -> .cold 0x60b3154 "
                                    "(__cxa_begin_catch, dispose the "
                                    "constructed prefix walking FORWARD "
                                    "0x28 at a time, __cxa_rethrow) -- "
                                    "the rethrow call maps in the .cold "
                                    "LSDA to pad 0x60b324d (delete[] the "
                                    "db_paths buffer, then the chain)",
                "FDE+0x4a4..+0x4a9": "operator new, listeners "
                                    "(0x60b3724) -- pad 0x60b3b4b -> "
                                    ".cold 0x60b31b0 "
                                    "(write_buffer_manager ctrl, wal_dir "
                                    "dispose, db_log_dir dispose, "
                                    "db_paths dtor, then the chain)",
                "FDE+0x76a..+0x76f": "_M_create, wal_dir (0x60b39ea) -- "
                                    "pad 0x60b3b57 -> .cold 0x60b31c8 "
                                    "(db_log_dir dispose, db_paths "
                                    "dtor, then the chain)",
                "FDE+0x7b2..+0x7b7": "_M_create, db_log_dir (0x60b3a32) "
                                    "-- pad 0x60b3b63 -> .cold 0x60b31d0 "
                                    "(db_paths vector dtor, then the "
                                    "chain)",
                "FDE+0x80a..+0x80f": "_M_create, db_host_id (0x60b3a8a) "
                                    "-- pad 0x60b3b6f -> .cold 0x60b3182 "
                                    "(file_checksum_gen_factory ctrl, "
                                    "row_cache ctrl, listeners vector "
                                    "dtor 0x5d46140, write_buffer_manager "
                                    "ctrl, wal_dir dispose, db_log_dir "
                                    "dispose, db_paths dtor, then the "
                                    "chain)",
                "FDE+0x8a0..+0x8a5": "__throw_bad_array_new_length, "
                                    "db_paths (0x60b3b20) -- pad "
                                    "0x60b3b7b -> .cold 0x60b31d9 (chain "
                                    "only)",
                "FDE+0x8b5..+0x8ba": "__throw_bad_array_new_length, "
                                    "listeners (0x60b3b35) -- pad "
                                    "0x60b3b4b -> .cold 0x60b31b0",
                ".cold FDE+0xd0..+0xd5": "_Unwind_Resume (0x60b3224) -- "
                                        "NO pad (already inside the "
                                        "cleanup)",
                ".cold FDE+0xe5..+0xea": "__cxa_rethrow (0x60b3239) -- "
                                        "pad 0x60b324d (__cxa_end_catch, "
                                        "delete[] the db_paths buffer, "
                                        "then the chain at 0x60b31d9)",
            },
            "lsda": {
                "va": "0x422440",
                "bytes_hex": "ff9b390130ac0205fb1100da0305bf1101a40905"
                             "cb1100ea0e05d71100b20f05e311008a1005ef1100"
                             "a01105fb1100b51105cb1100",
                "action_table_hex": "0100",
                "note": "53 bytes: header ff 9b 39 01 30 + 8 call-site "
                        "entries, all action 0 except the db_paths "
                        "element-copy entry (action 1, a catch pad); "
                        "the 2-byte action table (01 00) follows at "
                        "0x422475. Landing pads are FDE-relative "
                        "offsets from 0x60b3280; each pad is an endbr64 "
                        "stub jumping into .cold.",
            },
            "cold_lsda": {
                "va": "0x42247c",
                "bytes_hex": "ff9b15010bd001050000e50105f90100",
                "note": "16 bytes: header ff 9b 15 01 0b + 2 call-site "
                        "entries (_Unwind_Resume -> no pad; "
                        "__cxa_rethrow -> pad 0x60b324d). Landing pads "
                        "are FDE-relative offsets from 0x60b3154.",
            },
            "landing_pads": {
                "0x60b3b3f": "stub -> .cold 0x60b3154 (db_paths element "
                            "copy catch pad: begin_catch, dispose the "
                            "constructed prefix walking forward 0x28 "
                            "at a time, rethrow)",
                "0x60b3b4b": "stub -> .cold 0x60b31b0 (listeners new / "
                            "length throw: write_buffer_manager ctrl, "
                            "wal_dir dispose, db_log_dir dispose, "
                            "db_paths dtor, then the chain)",
                "0x60b3b57": "stub -> .cold 0x60b31c8 (wal_dir: "
                            "db_log_dir dispose, db_paths dtor, then "
                            "the chain)",
                "0x60b3b63": "stub -> .cold 0x60b31d0 (db_log_dir: "
                            "db_paths vector dtor, then the chain)",
                "0x60b3b6f": "stub -> .cold 0x60b3182 (db_host_id: "
                            "file_checksum_gen_factory ctrl, row_cache "
                            "ctrl, listeners vector dtor, "
                            "write_buffer_manager ctrl, wal_dir "
                            "dispose, db_log_dir dispose, db_paths "
                            "dtor, then the chain)",
                "0x60b3b7b": "stub -> .cold 0x60b31d9 (db_paths new / "
                            "length throw: the chain only)",
                "0x60b324d": ".cold pad (rethrow continuation): "
                            "__cxa_end_catch, raw delete[] of the "
                            "db_paths buffer, then the chain at "
                            "0x60b31d9",
                "0x60b31d9": "the chain: statistics ctrl, info_log "
                            "ctrl, sst_file_manager ctrl, rate_limiter "
                            "ctrl (each _M_release if non-null), then "
                            "_Unwind_Resume",
            },
        },
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
