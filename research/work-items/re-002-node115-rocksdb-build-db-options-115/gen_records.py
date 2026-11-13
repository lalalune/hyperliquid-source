#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body and source hashes are recomputed from work/hl-node-115.bin
over the FDE range and checked against the vendor census record
(the source hash reproduces by zeroing the 19 census relocations,
kinds 2/4/42, no relaxation).
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
    ("0x60c2e20", "0x60c3477",
     "rocksdb::BuildDBOptions",
     "build-db-options-60c2e20", True),
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
    main_calls = [s for s in sites if s["target"] == "0x60c2e20"]
    functions["0x60c2e20"]["callers"] = [s["site"] for s in main_calls]
    functions["0x60c2e20"]["model"] = (
        "1623-byte DBOptions BuildDBOptions(const ImmutableDBOptions& "
        "immutable, const MutableDBOptions& mutable) (hidden sret in "
        "rdi, immutable in rsi, mutable in rdx). (1) Default "
        "construction (0x60c2e37): DBOptions::DBOptions() 0x60b2db0 "
        "runs on the output first; every field starts at its "
        "declared default. (2) The copy map (0x60c2e3c..0x60c33bf): "
        "91 field copies in the exact upstream order -- 74 from the "
        "immutable half, 17 from the mutable half (see layouts). "
        "Scalars copy with the width the type dictates; the three "
        "structs lay their fields out in different orders "
        "(max_write_batch_group_size_bytes is immutable +0xf8 but "
        "output +0x1d8; the mutable half packs 17 fields into "
        "0x6c bytes). (3) Shared pointers (7 fields): the pointer "
        "word copies inline and the control block goes through the "
        "shared_ptr copy routine -- inlined for five fields, "
        "out-of-line through __shared_count::operator= 0x60bcde0 "
        "for sst_file_manager (+0x20) and file_checksum_gen_factory "
        "(+0x228). If the new target differs from the old one the "
        "new use count goes up by one (plain addl when the "
        "single-thread flag byte at 0x64ed290 is set, lock addl "
        "otherwise) and the old target is released via "
        "_Sp_counted_base::_M_release 0x5d350c0 (destroyed at zero; "
        "the out-of-line spelling also checks the combined (use, "
        "weak) count 0x100000001 before disposing). Equal targets "
        "are a no-op; a null new target only releases the old one. "
        "On the normal path the release half is dead: the ctor "
        "nulls all seven slots. (4) Containers: db_paths is a "
        "std::vector<DbPath> copy (operator= 0x60c2790) from "
        "immutable +0x60 into output +0x70; listeners is a "
        "std::vector<std::shared_ptr<EventListener>> copy "
        "(operator= 0x60bd2d0) from immutable +0x140 into output "
        "+0x1a8; the three strings (db_log_dir, wal_dir, "
        "db_host_id) copy with std::string::_M_assign (PLT "
        "0x63f0f00). (5) Landing pad (0x60c346b..0x60c3477, inside "
        "the main FDE -- NO separate .cold FDE): on any throw the "
        "pad moves the exception to rbp, jumps to 0x60c2e04, "
        "destroys the partially built output with "
        "DBOptions::~DBOptions 0x5d354b0 and resumes unwinding "
        "with _Unwind_Resume. The output is never returned "
        "half-built. The two fields the function never writes -- "
        "write_dbid_to_manifest (+0x21a) and compaction_service "
        "(+0x278..+0x287) -- keep the ctor defaults (false and "
        "nullptr, verified in the ctor disassembly).")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-dbimpl-createwal-115 (open, PR "
            "#6222): reconstructs DBImpl::CreateWAL 0x5e5c270, which "
            "calls BuildDBOptions first (site 0x5e5c2f8) to build "
            "the DBOptions it passes to OptimizeForLogWrite; this "
            "packet supersedes that caller's oracle note with the "
            "full copy map.",
            "RE-002-node115-vendor-census: BuildDBOptions IS "
            "census-bound (member "
            "d7ece8bd5f9dc186-options_helper.o, symbol "
            "_ZN7rocksdb14BuildDBOptionsERKNS_18ImmutableDBOptionsE"
            "RKNS_16MutableDBOptionsE); body hash 8c918932f1d73255... "
            "and source hash 53ce0817d1e68f2f... reproduced exactly "
            "by zeroing its 19 census relocations (kinds 2/4/42, "
            "no relaxation). Its callees are census-bound too: "
            "DBOptions::DBOptions() 0x60b2db0, "
            "__shared_count::operator= 0x60bcde0, "
            "vector<DbPath>::operator= 0x60c2790, "
            "vector<shared_ptr<EventListener>>::operator= 0x60bd2d0, "
            "_Sp_counted_base::_M_release 0x5d350c0.",
            "facebook/rocksdb v8.1.1, read live this cycle (the "
            "repo has since moved to meta/rocksdb): "
            "options/options_helper.cc defines BuildDBOptions as "
            "91 assignments in the exact order the binary copies "
            "them (verified field by field -- see the README); "
            "include/rocksdb/options.h declares DBOptions (0x290 "
            "bytes, 93 data members); options/db_options.h "
            "declares ImmutableDBOptions (0x240 bytes, 80 members "
            "including the convenience tail fs/clock/stats/logger/"
            "compaction_service/enforce_single_del_contracts past "
            "lowest_used_cache_tier) and MutableDBOptions (0x6c "
            "bytes, 17 members). The two DBOptions members the "
            "function never assigns are write_dbid_to_manifest and "
            "compaction_service. In v8.1.1 max_log_file_size, "
            "log_file_time_to_roll, keep_log_file_num, "
            "recycle_log_file_num, max_manifest_file_size and "
            "persist_stats_to_disk come from the immutable half, "
            "not the mutable half.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "target, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "rocksdb::BuildDBOptions 0x60c2e20: exactly 12 direct "
                "calls, 0 tail jumps, 0 LEA refs. The callers are "
                "DBImpl::GetDBOptions 0x5d488e0 (site 0x5d48922), "
                "DBImpl::GetOptions 0x5d58720 (0x5d5878f), DBImpl::"
                "CreateColumnFamilyImpl 0x5d69a00 (0x5d69a88), "
                "DBImpl::WriteOptionsFile 0x5d713f0 (0x5d71b79), "
                "DBImpl::SetDBOptions 0x5d71fe0 (0x5d72361), DBImpl::"
                "SetOptions 0x5d72ed0 (0x5d73283), an unnamed FDE "
                "0x5d74aa0 (0x5d753be, not in the census), DBImpl::"
                "DBImpl 0x5d85480 (0x5d858aa), CompactionJob::"
                "ProcessKeyValueCompactionWithCompactionService "
                "0x5e41fa0 (0x5e427fb), DBImpl::"
                "GetLogSizeAndMaybeTruncate 0x5e5ad50 (0x5e5af6b), "
                "DBImpl::CreateWAL 0x5e5c270 (0x5e5c2f8, the #6222 "
                "packet) and DBOptionsConfigurable::"
                "ConfigureOptions 0x60a2470 (0x60a24f8) -- all "
                "census-bound symbols except the one unnamed FDE. "
                "Every DB open / options-query / options-change "
                "path rebuilds its DBOptions through this routine.",
                "BuildDBOptions has no .cold FDE: its landing pad "
                "sits at the tail of the main FDE (0x60c346b.."
                "0x60c3477: endbr64; mov %rax,%rbp; jmp 0x60c2e04) "
                "and the pad target at 0x60c2e04 destroys the "
                "partial output and resumes unwinding.",
                "BuildDBOptions calls its helpers through direct "
                "calls (DBOptions::DBOptions, __shared_count::"
                "operator=, the two vector operator=s, "
                "_Sp_counted_base::_M_release, std::string::"
                "_M_assign, DBOptions::~DBOptions on the landing "
                "pad, _Unwind_Resume) -- the targets are pinned by "
                "the disassembly, the PLT relocation map and the "
                "vendor census, not by the scan.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 immutable (random immutable half, mutable "
                     "fixed at declaration defaults -- every "
                     "assertion isolates an immutable-sourced field) "
                     "+ 600 mutable (random mutable half, immutable "
                     "fixed) + 600 shared_ptr (aliasing-heavy: few "
                     "targets shared across the seven shared_ptr "
                     "fields and the listeners vector, nulls mixed "
                     "in; use-count event sequences) + 600 bindings "
                     "(full random builds, byte-image checks, struct "
                     "sizes, FDE hash, caller sites, copy order, "
                     "un-copied fields)",
            "tests": "tests/test_build_db_options115.py",
            "tool": "tools/build_db_options115.py",
            "what_is_checked": [
                "immutable: each of the 74 immutable-sourced output "
                "fields equals its immutable input field (scalars "
                "by value, strings by content, vectors element by "
                "element, shared_ptr targets by identity with the "
                "use count after the copy); the 17 mutable-sourced "
                "fields stay at their declaration defaults",
                "mutable: each of the 17 mutable-sourced output "
                "fields equals its mutable input field; the 74 "
                "immutable-sourced fields stay at their declaration "
                "defaults",
                "shared_ptr: copy-assign acquires the new target "
                "(use count +1) and releases the old one (use count "
                "-1, destroyed at zero); equal targets are a no-op; "
                "a null new target only releases; aliasing across "
                "fields and listeners elements accumulates the "
                "count (one input reference per slot, one output "
                "reference per copy)",
                "bindings: the 0x290-byte output image carries "
                "every copied field at the binary's output offset "
                "with the right bytes (bools as single bytes, the "
                "1-byte enums, ints little-endian, SSO strings "
                "with the inline buffer, long strings and vectors "
                "with heap ids); the two unwritten fields keep the "
                "ctor defaults (write_dbid_to_manifest false, "
                "compaction_service null); struct sizes 0x290 / "
                "0x240 / 0x6c; the FDE body hash; the 12 caller "
                "sites; the 91-entry copy order",
            ],
        },
        "engine_callees": {
            "0x60b2db0": "rocksdb::DBOptions::DBOptions() "
                        "(census-bound, member "
                        "d7ece8bd5f9dc186-options.o): the default "
                        "constructor, called first on the output. "
                        "This model scripts it as an oracle; the "
                        "two unwritten fields keep the defaults "
                        "verified in its disassembly "
                        "(write_dbid_to_manifest false at +0x21a, "
                        "compaction_service null at +0x278..+0x287, "
                        "lowest_used_cache_tier 1 and "
                        "enforce_single_del_contracts true as one "
                        "0x101 store at +0x288). The full ctor is "
                        "the next work item, not this packet.",
            "0x60bcde0": "std::__shared_count::operator= "
                        "(census-bound, member "
                        "d7ece8bd5f9dc186-options_helper.o): the "
                        "shared_ptr control-block copy-assign, used "
                        "for sst_file_manager (out+0x20) and "
                        "file_checksum_gen_factory (out+0x228). If "
                        "the new control block differs from the old "
                        "one it addrefs the new block and releases "
                        "the old one (checking the combined (use, "
                        "weak) count 0x100000001 before disposing).",
            "0x60c2790": "std::vector<DbPath>::operator= "
                        "(census-bound, member "
                        "d7ece8bd5f9dc186-options_helper.o): copies "
                        "db_paths from immutable +0x60 into output "
                        "+0x70.",
            "0x60bd2d0": "std::vector<std::shared_ptr<EventListener>>"
                        "::operator= (census-bound, member "
                        "d7ece8bd5f9dc186-options_helper.o): copies "
                        "listeners from immutable +0x140 into output "
                        "+0x1a8, acquiring each element target.",
            "0x5d350c0": "std::_Sp_counted_base::_M_release() "
                        "(census-bound, member ec5269789d1af65a-"
                        "cache.o): the shared_ptr release, called "
                        "for the old target of each inlined "
                        "shared_ptr copy (five fields).",
            "0x63f0f00": "PLT std::string::_M_assign: the three "
                        "string copies (db_log_dir, wal_dir, "
                        "db_host_id).",
            "0x5d354b0": "rocksdb::DBOptions::~DBOptions(): called "
                        "only from the landing pad at 0x60c2e04 to "
                        "destroy a partially built output before "
                        "unwinding resumes.",
            "0x63f0a50": "PLT _Unwind_Resume: the landing pad's "
                        "exit after destroying the output.",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this "
                               "VM. The target binary is never executed. "
                               "The tool models the routine in Python; "
                               "DBOptions::DBOptions() is scripted as an "
                               "oracle (its two unwritten fields keep "
                               "the defaults verified in its "
                               "disassembly); heap addresses of strings, "
                               "vectors and shared_ptr control blocks "
                               "are modelled as deterministic ids, not "
                               "real pointers; vector/string capacities "
                               "after copy-assign are modelled as "
                               "exactly the source size (the libstdc++ "
                               "fresh-target behaviour) and recorded as "
                               "a model choice, not a binary-pinned "
                               "fact. make verify/test/catalogue-check "
                               "in a tooled environment is still owed "
                               "upstream.",
        "functions": functions,
        "layouts": {
            "db_options_0x290": {
                "+0x0000": "create_if_missing bool (imm +0x00)",
                "+0x0001": "create_missing_column_families bool "
                          "(imm +0x01)",
                "+0x0002": "error_if_exists bool (imm +0x02)",
                "+0x0003": "paranoid_checks bool (imm +0x03)",
                "+0x0004": "flush_verify_memtable_count bool (imm +0x04)",
                "+0x0005": "track_and_verify_wals_in_manifest bool "
                          "(imm +0x05)",
                "+0x0006": "verify_sst_unique_id_in_manifest bool "
                          "(imm +0x06)",
                "+0x0008": "env Env* (imm +0x08)",
                "+0x0010": "rate_limiter shared_ptr (imm +0x10, "
                          "ctrl +0x18)",
                "+0x0020": "sst_file_manager shared_ptr (imm +0x20, "
                          "ctrl +0x28, via __shared_count::operator=)",
                "+0x0030": "info_log shared_ptr (imm +0x30, ctrl +0x38)",
                "+0x0040": "info_log_level u8 (imm +0x40; 1-byte enum)",
                "+0x0044": "max_open_files i32 (MUT +0x40)",
                "+0x0048": "max_file_opening_threads i32 (imm +0x44)",
                "+0x0050": "max_total_wal_size u64 (MUT +0x20)",
                "+0x0058": "statistics shared_ptr (imm +0x48, ctrl +0x60)",
                "+0x0068": "use_fsync bool (imm +0x58)",
                "+0x0070": "db_paths vector<DbPath> (imm +0x60, "
                          "operator=)",
                "+0x0088": "db_log_dir string (imm +0x78, _M_assign)",
                "+0x00a8": "wal_dir string (imm +0x98, _M_assign)",
                "+0x00c8": "delete_obsolete_files_period_micros u64 "
                          "(MUT +0x28)",
                "+0x00d0": "max_background_jobs i32 (MUT +0x00)",
                "+0x00d4": "max_background_compactions i32 (MUT +0x04)",
                "+0x00d8": "max_subcompactions u32 (MUT +0x08)",
                "+0x00dc": "max_background_flushes i32 (MUT +0x68)",
                "+0x00e0": "max_log_file_size u64 (imm +0xb8)",
                "+0x00e8": "log_file_time_to_roll u64 (imm +0xc0)",
                "+0x00f0": "keep_log_file_num u64 (imm +0xc8)",
                "+0x00f8": "recycle_log_file_num u64 (imm +0xd0)",
                "+0x0100": "max_manifest_file_size u64 (imm +0xd8)",
                "+0x0108": "table_cache_numshardbits i32 (imm +0xe0)",
                "+0x0110": "WAL_ttl_seconds u64 (imm +0xe8)",
                "+0x0118": "WAL_size_limit_MB u64 (imm +0xf0)",
                "+0x0120": "manifest_preallocation_size u64 (imm +0x100)",
                "+0x0128": "allow_mmap_reads bool (imm +0x108)",
                "+0x0129": "allow_mmap_writes bool (imm +0x109)",
                "+0x012a": "use_direct_reads bool (imm +0x10a)",
                "+0x012b": "use_direct_io_for_flush_and_compaction bool "
                          "(imm +0x10b)",
                "+0x012c": "allow_fallocate bool (imm +0x10c)",
                "+0x012d": "is_fd_close_on_exec bool (imm +0x10d)",
                "+0x0130": "stats_dump_period_sec u32 (MUT +0x30)",
                "+0x0134": "stats_persist_period_sec u32 (MUT +0x34)",
                "+0x0138": "persist_stats_to_disk bool (imm +0x199)",
                "+0x0140": "stats_history_buffer_size u64 (MUT +0x38)",
                "+0x0148": "advise_random_on_open bool (imm +0x10e)",
                "+0x0150": "db_write_buffer_size u64 (imm +0x110)",
                "+0x0158": "write_buffer_manager shared_ptr (imm +0x118, "
                          "ctrl +0x120)",
                "+0x0168": "access_hint_on_compaction_start i32 "
                          "(imm +0x128)",
                "+0x0170": "compaction_readahead_size u64 (MUT +0x60)",
                "+0x0178": "random_access_max_buffer_size u64 "
                          "(imm +0x130)",
                "+0x0180": "writable_file_max_buffer_size u64 "
                          "(MUT +0x10)",
                "+0x0188": "use_adaptive_mutex bool (imm +0x138)",
                "+0x0190": "bytes_per_sync u64 (MUT +0x48)",
                "+0x0198": "wal_bytes_per_sync u64 (MUT +0x50)",
                "+0x01a0": "strict_bytes_per_sync bool (MUT +0x58)",
                "+0x01a8": "listeners vector<shared_ptr<EventListener>> "
                          "(imm +0x140, operator=)",
                "+0x01c0": "enable_thread_tracking bool (imm +0x158)",
                "+0x01c8": "delayed_write_rate u64 (MUT +0x18)",
                "+0x01d0": "enable_pipelined_write bool (imm +0x159)",
                "+0x01d1": "unordered_write bool (imm +0x15a)",
                "+0x01d2": "allow_concurrent_memtable_write bool "
                          "(imm +0x15b)",
                "+0x01d3": "enable_write_thread_adaptive_yield bool "
                          "(imm +0x15c)",
                "+0x01d8": "max_write_batch_group_size_bytes u64 "
                          "(imm +0xf8 -- reordered vs DBOptions)",
                "+0x01e0": "write_thread_max_yield_usec u64 (imm +0x160)",
                "+0x01e8": "write_thread_slow_yield_usec u64 (imm +0x168)",
                "+0x01f0": "skip_stats_update_on_db_open bool (imm +0x170)",
                "+0x01f1": "skip_checking_sst_file_sizes_on_db_open bool "
                          "(imm +0x171)",
                "+0x01f2": "wal_recovery_mode u8 (imm +0x172; 1-byte enum)",
                "+0x01f3": "allow_2pc bool (imm +0x173)",
                "+0x01f8": "row_cache shared_ptr (imm +0x178, ctrl +0x180)",
                "+0x0208": "wal_filter WalFilter* (imm +0x188)",
                "+0x0210": "fail_if_options_file_error bool (imm +0x190)",
                "+0x0211": "dump_malloc_stats bool (imm +0x191)",
                "+0x0212": "avoid_flush_during_recovery bool (imm +0x192)",
                "+0x0213": "avoid_flush_during_shutdown bool (MUT +0x0c)",
                "+0x0214": "allow_ingest_behind bool (imm +0x193)",
                "+0x0215": "two_write_queues bool (imm +0x194)",
                "+0x0216": "manual_wal_flush bool (imm +0x195)",
                "+0x0217": "wal_compression u8 (imm +0x196; 1-byte enum)",
                "+0x0218": "atomic_flush bool (imm +0x197)",
                "+0x0219": "avoid_unnecessary_blocking_io bool "
                          "(imm +0x198)",
                "+0x021a": "write_dbid_to_manifest bool -- NOT WRITTEN, "
                          "ctor default false",
                "+0x0220": "log_readahead_size u64 (imm +0x1a0)",
                "+0x0228": "file_checksum_gen_factory shared_ptr "
                          "(imm +0x1a8, ctrl +0x1b0, via "
                          "__shared_count::operator=)",
                "+0x0238": "best_efforts_recovery bool (imm +0x1b8)",
                "+0x023c": "max_bgerror_resume_count i32 (imm +0x1bc)",
                "+0x0240": "bgerror_resume_retry_interval u64 (imm +0x1c0)",
                "+0x0248": "allow_data_in_errors bool (imm +0x1c8)",
                "+0x0250": "db_host_id string (imm +0x1d0, _M_assign)",
                "+0x0270": "checksum_handoff_file_types u64 (imm +0x1f0)",
                "+0x0278": "compaction_service shared_ptr -- NOT WRITTEN, "
                          "ctor default null (16 zeroed bytes)",
                "+0x0288": "lowest_used_cache_tier u8 (imm +0x1f8; "
                          "1-byte enum)",
                "+0x0289": "enforce_single_del_contracts bool "
                          "(imm +0x238)",
            },
            "immutable_0x240": {
                "size": "0x240 bytes; fields +0x00..+0x1ff hold the "
                        "74 immutable-sourced fields (see the "
                        "db_options_0x290 table for the source "
                        "offsets); past lowest_used_cache_tier "
                        "(+0x1f8) the convenience tail holds fs "
                        "shared_ptr +0x200, clock +0x210, stats "
                        "+0x218, logger +0x220, compaction_service "
                        "shared_ptr +0x228 and "
                        "enforce_single_del_contracts bool +0x238 -- "
                        "none of them are part of DBOptions, and "
                        "only enforce_single_del_contracts is copied "
                        "out (to +0x289).",
            },
            "mutable_0x6c": {
                "+0x00": "max_background_jobs i32 -> out +0xd0",
                "+0x04": "max_background_compactions i32 -> out +0xd4",
                "+0x08": "max_subcompactions u32 -> out +0xd8",
                "+0x0c": "avoid_flush_during_shutdown bool -> out +0x213",
                "+0x10": "writable_file_max_buffer_size u64 -> "
                         "out +0x180",
                "+0x18": "delayed_write_rate u64 -> out +0x1c8",
                "+0x20": "max_total_wal_size u64 -> out +0x50",
                "+0x28": "delete_obsolete_files_period_micros u64 -> "
                         "out +0xc8",
                "+0x30": "stats_dump_period_sec u32 -> out +0x130",
                "+0x34": "stats_persist_period_sec u32 -> out +0x134",
                "+0x38": "stats_history_buffer_size u64 -> out +0x140",
                "+0x40": "max_open_files i32 -> out +0x44",
                "+0x48": "bytes_per_sync u64 -> out +0x190",
                "+0x50": "wal_bytes_per_sync u64 -> out +0x198",
                "+0x58": "strict_bytes_per_sync bool -> out +0x1a0",
                "+0x60": "compaction_readahead_size u64 -> out +0x170",
                "+0x68": "max_background_flushes i32 -> out +0xdc",
            },
        },
        "observations": [
            "The binary copies the 91 fields in exactly the upstream "
            "assignment order -- the copy order IS the source order, "
            "so the field-name mapping is pinned twice over (by the "
            "disassembly offsets and by the source listing).",
            "The three structs lay their fields out in different "
            "orders: max_write_batch_group_size_bytes is immutable "
            "+0xf8 but output +0x1d8, and persist_stats_to_disk is "
            "immutable +0x199 (after the bool run) but output "
            "+0x138. A model that assumed declaration order for the "
            "immutable half would place both wrong.",
            "The shared_ptr copies come in two spellings -- inlined "
            "for five fields, out-of-line __shared_count::operator= "
            "for sst_file_manager and file_checksum_gen_factory -- "
            "with identical observable semantics; the compiler "
            "chose the call for the two fields whose control-block "
            "store follows a pointer-word store in the same basic "
            "block.",
            "The release half of every shared_ptr copy is dead on "
            "the normal path: DBOptions::DBOptions() nulls all "
            "seven slots, so there is never an old target to "
            "release. It exists only for the (unreachable from "
            "this routine) case of building into a non-fresh "
            "output.",
            "The landing pad destroys the partially built output "
            "and resumes unwinding -- the routine never returns a "
            "half-built DBOptions, even when a string or vector "
            "copy throws midway.",
            "The single-thread flag byte at 0x64ed290 only chooses "
            "between a plain and a lock-prefixed use-count "
            "increment; it has no observable effect on the model, "
            "which records the increment either way.",
            "No /home/ paths appear in the packet excerpts: the "
            "objdump excerpt uses the repo-relative binary path "
            "work/hl-node-115.bin (the #5857 defect class, avoided).",
        ],
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
    print("wrote records.json")


if __name__ == "__main__":
    main()
