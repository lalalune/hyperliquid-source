#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

The body hashes are recomputed from work/hl-node-115.bin over the
FDE ranges. Both FDEs are vendor-census-bound (member
4d429ab1cb2d8f8b-db_impl.o, librocksdb-sys 0.11.0+8.1.1); their
source hashes reproduce exactly by zeroing the census
relocations (main 121, cold 20, kinds 2/4, no relaxation). The
main FDE has a .cold FDE with a 22-entry LSDA (all cleanup,
entry [0] has no landing pad); the .cold FDE has a 1-entry LSDA.
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
    ("0x5d71fe0", "0x5d72e50",
     "rocksdb::DBImpl::SetDBOptions",
     "set-db-options-5d71fe0", True),
    ("0x5d71eea", "0x5d71fe0",
     "rocksdb::DBImpl::SetDBOptions.cold",
     "set-db-options-5d71eea-cold", True),
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
        source_hash = hashlib.sha256(bytes(zeroed)).hexdigest()
        assert source_hash == rec["source_body_sha256"], name
        relocs = ";".join(
            "%d:kind%d" % (r["offset"], r["kind"])
            for r in rec["relocations"])
        symbol = rec["symbol"]
        raw_equal = str(rec["raw_equal"])
        row = {
            "name": name, "start": start_s, "end": end_s,
            "size": str(end - start), "body_sha256": body_hash,
            "source_sha256": source_hash,
            "raw_equal": raw_equal,
            "relocations": relocs,
            "census_id": "node115-vendor-%s" % start_s[2:],
            "symbol": symbol,
            "excerpt": slug + ".objdump.txt", "hex": slug + ".hex",
        }
        functions[start_s] = {
            "body_sha256": body_hash,
            "source_sha256": source_hash,
            "relocations": relocs,
            "census_id": row["census_id"],
            "mangled": symbol,
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
    main_calls = [s for s in sites if s["target"] == "0x5d71fe0"]
    functions["0x5d71fe0"]["callers"] = [s["site"] for s in main_calls]
    functions["0x5d71fe0"]["model"] = (
        "3696-byte setter "
        "SetDBOptions(const unordered_map<string, string>&) "
        "(result by value, sret out in rdi = r12; this in rsi = "
        "rbx; options_map in rdx; stack canary used, stored "
        "0xa48(%rsp), checked at the epilogue 0x5d720a1 and in the "
        ".cold chain at 0x5d71f1c before _Unwind_Resume). Empty "
        "input: log WARN and return InvalidArgument 'empty input' "
        "with no lock and no WriteContext. Otherwise lock the "
        "mutex, parse with GetMutableDBOptionsFromStrings "
        "(0x60a1d60, oracle; a parse failure restores the base "
        "options), default bytes_per_sync to 1 MiB, short-circuit "
        "OK when nothing changed, build a new DBOptions "
        "(BuildDBOptions 0x60c2e20, oracle), validate it "
        "(ValidateOptions 1-arg 0x5e59cd0, oracle, open PR "
        "#6379) and every live column family "
        "(ColumnFamilyData::ValidateOptions 0x5d8e3b0, oracle, "
        "open PR #6449; dropped CFs skipped, first failure "
        "wins), grow the background thread pools when the new "
        "BGJobLimits increase (IncBackgroundThreadsIfNeeded, "
        "HIGH then LOW, then MaybeScheduleFlushOrCompaction), "
        "unlock, re-register the periodic dump/persist-stats "
        "tasks (Register returns the status; a dump-register "
        "failure skips the persist task), store the new "
        "max_total_wal_size when it changed, relock, return the "
        "first failure status, else apply the new mutable "
        "options (write_controller rate, table_cache capacity "
        "0x400000 when max_open_files == -1, else "
        "max_open_files - 10), rebuild the compaction "
        "FileOptions (EnvOptions ctor from the new DBOptions, "
        "then the base FileSystem "
        "OptimizeForCompactionTableWrite/Read hooks), switch "
        "the WAL when total_log_size exceeds the max or "
        "wal_bytes_per_sync changed (a SwitchWAL failure is "
        "only logged, never returned), persist the options "
        "file, log the inputs and the outcome, and return the "
        "parse/validation/scheduler status, or IOError "
        "'SetDBOptions() succeeded, but unable to persist "
        "options: ...' when the options file could not be "
        "persisted and fail_if_options_file_error is set. "
        "The .cold FDE (246 B) runs the destructor chain in "
        "order (string _M_dispose, WriteContext dtor, "
        "ColumnFamilyOptions/DBOptions dtors, FileOptions "
        "property_bag clear/dispose, FileSystemPtr release, "
        "Writer dtor, Mutex::Unlock) and then checks the canary "
        "before resuming -- so a throw with a bad canary "
        "becomes StackCheckFailed after cleanup, unlike the "
        "no-LSDA packets.")
    functions["0x5d71eea"]["model"] = (
        "246-byte .cold FDE for SetDBOptions: the landing-pad "
        "continuations for the 15 main-FDE stubs (0x5d72d9c.."
        "0x5d72e44, each endbr64 + mov %rax,%rbx + jmp rel32 "
        "into this FDE) plus the 1-entry LSDA at 0x409343. It "
        "runs the cleanup chain in order and checks the stack "
        "canary at 0x5d71f1c before _Unwind_Resume (0x63f0a50). "
        "A throw with a bad canary becomes StackCheckFailed "
        "after cleanup.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-dbimpl-validate-options-115 "
            "(open, PR #6379): reconstructs DBImpl::"
            "ValidateOptions (1-arg) 0x5e59cd0, which this "
            "setter calls once (site 0x5d7256d) on the rebuilt "
            "DBOptions. The #6379 packet's reconstruction is "
            "used here as the validation oracle.",
            "RE-002-node115-rocksdb-column-family-data-validate-"
            "options-115 (open, PR #6449): reconstructs "
            "ColumnFamilyData::ValidateOptions 0x5d8e3b0, which "
            "this setter calls once per live column family "
            "(site 0x5d725f6). The #6449 packet's reconstruction "
            "is used here as the per-CF validation oracle.",
            "RE-002-node115-vendor-census: both FDEs are "
            "census-bound (member 4d429ab1cb2d8f8b-db_impl.o, "
            "librocksdb-sys 0.11.0+8.1.1). Main body 4e93a3e0... "
            "/ source 74c9d375... (121 relocations, kinds 2/4, "
            "no relaxation); cold body 1e1c1fff... / source "
            "94db39e5... (20 relocations, kinds 2/4, no "
            "relaxation).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "db/db_impl.cc:1209-1376 defines SetDBOptions "
            "exactly as the binary behaves -- the empty-input "
            "guard (:1212), the bytes_per_sync 1 MiB default "
            "(:1224), the unchanged short-circuit (:1231-1237), "
            "BuildDBOptions + the 1-arg ValidateOptions + the "
            "per-CF loop skipping dropped CFs (:1242-1258), the "
            "BGJobLimits growth with IncBackgroundThreadsIfNeeded "
            "HIGH/LOW and MaybeScheduleFlushOrCompaction "
            "(:1261-1291), the unlock / periodic-task register / "
            "max_total_wal_size store / relock sequence "
            "(:1293-1321), the apply step (write_controller, "
            "table_cache kInfiniteCapacity, FileOptions + the "
            "two OptimizeForCompactionTable hooks, "
            "ChangeFileOptions) (:1323-1336), the WAL switch "
            "gate with the warn-only failure (:1337-1347), "
            "WriteOptionsFile (:1348), and the log-inputs / "
            "succeeded / persist-IOError / failed / LogFlush "
            "tail (:1352-1376). All ten log/message strings "
            "match the binary's .rodata byte-for-byte, with "
            "their source line numbers.",
            "DBImpl/DBOptions layout: the vendored build's "
            "layout differs from a stock v8.1.1 compile after "
            "mutable_db_options_ (mutex_ +0x700 vs +0x740, "
            "table_cache_ +0x750 vs +0x7d0, "
            "file_options_for_compaction_ +0x8d0 vs +0x950, "
            "write_controller_ +0x1120 vs +0x11b0, "
            "total_log_size_ +0xc28 vs +0xcb8, "
            "max_total_wal_size_ +0x1860 vs +0x1978, "
            "periodic_task_scheduler_ +0x1748 vs +0x1858) and "
            "inside DBOptions (fail_if_options_file_error at "
            "+0x190 vs +0x210). The model follows the binary "
            "offsets; the stock-header offsets are recorded as "
            "the observation, not the ground truth. Early "
            "members match exactly (immutable_db_options_ "
            "+0x330, mutable_db_options_ +0x5a0, versions_ "
            "+0x68, env_ +0x318), as do MutableDBOptions "
            "(0x70 B), ColumnFamilyOptions (+0xe8/+0x160/"
            "+0x2b8), ColumnFamilyData (dropped_ +0x3d, next_ "
            "+0x938), ColumnFamilySet (dummy_cfd_ +0x110) and "
            "VersionSet (column_family_set_ +0x40), all "
            "verified by compiling offsetof() against the real "
            "v8.1.1 headers (g++).",
            "Binary-vs-source observations (recorded, not "
            "hidden): 0x60d52f0 is port::Mutex::Unlock, not "
            "Lock: the census lists 9 identical candidate "
            "symbols for that 149-byte body (Lock/Unlock/"
            "CondVar::Signal/...); the disassembly calls "
            "pthread_mutex_unlock (PLT 0x63f0b70). The Lock copy "
            "is 0x60d5230, reached through the "
            "InstrumentedMutexLock wrapper 0x606ca40 (not in "
            "the vendor census). The FileOptions temp is built "
            "by EnvOptions::EnvOptions(const DBOptions&) "
            "(AssignEnvOptions + the base no-op "
            "SanitizeEnvOptions) with IOOptions defaults, "
            "temperature kUnknown and handoff checksum kCRC32c; "
            "the base FileSystem OptimizeForCompactionTableWrite "
            "sets use_direct_writes from "
            "use_direct_io_for_flush_and_compaction and "
            "OptimizeForCompactionTableRead sets use_direct_reads "
            "from use_direct_reads (PosixFileSystem does not "
            "override either). GetBGJobLimits is the static "
            "formula (flushes==-1 and compactions==-1: quarter "
            "of max_background_jobs to flushes; else max(1, "
            "flushes/compactions); parallelize=true here so the "
            "throttle arm never fires). "
            "GetMutableDBOptionsFromStrings restores the base "
            "options on a parse failure (its contract, "
            "options/db_options.cc:1049); the model takes the "
            "parse outcome as an oracle input. The per-CF loop "
            "walks the ColumnFamilySet circular list via "
            "dummy_cfd_->next_ (+0x938) and skips dropped CFs "
            "(byte +0x3d); a CF's options temp is destroyed "
            "after each iteration, and on the first failure the "
            "loop breaks through the 0x5d72d8d stub "
            "(ColumnFamilyOptions dtor, then the error tail).",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "target, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "DBImpl::SetDBOptions 0x5d71fe0: exactly 0 direct "
                "calls, 0 tail jumps, 0 LEA refs -- it is a "
                "virtual API, not a direct callee. DB::"
                "SetDBOptions is reached through the DB vtable "
                "slot 0x248: StackableDB::SetDBOptions 0x5d30750 "
                "(census-bound, c.o) calls the slot at 0x5d3081b "
                "('call *0x248(%rax)', verified live from the "
                "disassembly) after a devirtualization chain. "
                "The empty census is the expected result.",
                "Main FDE record in .eh_frame (section offset "
                "0x7346d0, length 0x4c, initial_location "
                "0x5d71fe0, range 0xe70, aug_len 4, LSDA at "
                "0x4092b8, 22 call-site entries, all cleanup, "
                "entry [0] has no landing pad). Cold FDE record "
                "(section offset 0x734720, length 0x20, range "
                "0xf6, aug_len 4, LSDA at 0x409343, 1 entry, no "
                "landing pad).",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 checks (22 modes: empty, parse-fail, "
                     "unchanged, bytes-per-sync-default, "
                     "validate1-fail, cf-fail-first, "
                     "cf-fail-second, cf-dropped-skipped, "
                     "bg-flush-up, bg-compaction-up, bg-both-up, "
                     "bg-none, scheduler-dump-0, "
                     "scheduler-dump-register-fail, "
                     "scheduler-persist-0, "
                     "scheduler-persist-register-fail, "
                     "wal-switch-total, wal-switch-changed, "
                     "wal-switch-fail, persist-fail-ignore, "
                     "persist-fail-error, mixed) + 600 status (100 "
                     "each: OK image, empty-input error, "
                     "persist-IOError with ': ' join, ctor msg2 "
                     "join, arbitrary code/subcode/severity/state "
                     "images, BadAlloc in the empty-input Status "
                     "ctor with no landing pad) + 600 throw (one "
                     "armed fail_at per case across all 40 "
                     "THROW_SITES, in 5 modes: throw alone, "
                     "throw + bad canary, BadAlloc + bad canary, "
                     "canary failure on a normal return, "
                     "alloc_ok=False with no fail_at) + 600 "
                     "bindings (caller-site independence across "
                     "the vtable slot and the empty direct-call "
                     "census, both FDE hashes as expected values)",
            "tests": "tests/test_set_db_options115.py",
            "tool": "tools/set_db_options115.py",
            "what_is_checked": [
                "checks: the empty-input guard returns "
                "InvalidArgument 'empty input' before any lock; a "
                "parse failure returns the parse status and "
                "restores the base options; unchanged options "
                "short-circuit OK; bytes_per_sync 0 defaults to "
                "1 MiB; a validate1 failure and a per-CF failure "
                "(first and second CF, dropped CFs skipped) each "
                "return their status; pool growth fires only when "
                "the new limits increase (flush/compactions/both/"
                "none); the dump/persist periodic tasks are "
                "unregistered at period 0 and a dump-register "
                "failure skips the persist task; the WAL switches "
                "when total_log_size exceeds the max or "
                "wal_bytes_per_sync changed, and a SwitchWAL "
                "failure is logged only; a persist failure is "
                "ignored when fail_if is false and becomes "
                "IOError when fail_if is true",
                "status: the Status byte layout the ctor proves "
                "(code u8 +0x0, subcode u8 +0x1, severity u8 "
                "+0x2, padding +0x3..+0x7 zero with +0x6..+0x7 "
                "unwritten, state_ +0x8); the state_ buffer is "
                "msg + NUL with alloc len+1; the ctor's ': ' join "
                "when msg2 is non-empty (the persist IOError "
                "message); both messages byte-exact",
                "throw: each throwing call is recorded with its "
                "landing-pad stub and its .cold cleanup chain; a "
                "throw through a pad with a bad canary becomes "
                "StackCheckFailed after cleanup; a throw with no "
                "pad (the empty-input Log and the Status ctor, "
                "and LogFlush) propagates with no cleanup and no "
                "canary check, so BadAlloc + a bad canary still "
                "propagates as BadAlloc; a canary failure on a "
                "normal return raises StackCheckFailed at the "
                "epilogue; alloc_ok=False fires only on an error "
                "path that runs the ctor",
                "bindings: the result depends only on the "
                "options, never on the caller site; both FDE "
                "body hashes, both source hashes (121 + 20 "
                "relocations zeroed) and the engine-call counts "
                "match the binary",
            ],
        },
        "engine_callees": {
            "0x61cf670": "rocksdb::Status::Status(Code, SubCode, "
                         "const Slice&, const Slice&, Severity) "
                         "(census-bound, status.o): the five-argument "
                         "Status ctor, called twice (0x5d7208b empty-"
                         "input error, 0x5d724a2 persist IOError). "
                         "Its observable behavior IS pinned from its "
                         "disassembly: code u8 +0x0, subcode u8 +0x1, "
                         "severity u8 +0x2, zeroes +0x3..+0x5, state_ "
                         "= new char[size+1] holding msg + (': ' + "
                         "msg2 if len2) + NUL. Its trailing delete[] "
                         "of the old state_ is DEAD (state_ is "
                         "zeroed at 0x61cf6b0 before the read at "
                         "0x61cf6e4).",
            "0x61cfed0": "rocksdb::Status::ToString (census-bound, "
                         "status.o): called 3x (the SwitchWAL warn "
                         "log, the persist-IOError message, the "
                         "persist warn log). Its rendering IS pinned "
                         "from its own disassembly: a jump table at "
                         "0x97e958 over the code byte loads a prefix "
                         "string per code -- 'NotFound: ', "
                         "'Corruption: ', 'Not implemented: ', "
                         "'Invalid argument: ', 'IO error: ', 'Merge "
                         "in progress: ', 'Result incomplete: ', "
                         "'Shutdown in progress: ', 'Operation timed "
                         "out: ', 'Operation aborted: ', 'Resource "
                         "busy: ', 'Operation expired: ', 'Operation "
                         "failed. Try again.: ', 'Compaction too "
                         "large: ', 'Column family dropped: ' (code "
                         "0 is built inline as 'OK'; codes > 15 "
                         "render as 'Unknown code(%d): '). A "
                         "non-zero subcode appends its string from "
                         "the table at 0x64d7b00 (e.g. subcode 1 "
                         "'Timeout Acquiring Mutex', 4 'No space left "
                         "on device', 9 'No such file or directory'; "
                         "10 entries), then ': ' + state_. With "
                         "subcode 0 the state_ follows the prefix "
                         "directly. So the persist-IOError message "
                         "is 'SetDBOptions() succeeded, but unable "
                         "to persist options: IO error: <state>', "
                         "not 'kIOError: <state>' -- the enum names "
                         "with the 'k' prefix never appear in "
                         "ToString output.",
            "0x60a1d60": "rocksdb::GetMutableDBOptionsFromStrings "
                         "(census-bound, db_options.o): the parse, "
                         "called once (0x5d72192). Taken as an "
                         "oracle: it supplies the parsed new options "
                         "and restores the base options on a parse "
                         "failure.",
            "0x60c2e20": "rocksdb::BuildDBOptions (census-bound, "
                         "options_helper.o): called once (0x5d72361). "
                         "Taken as an oracle.",
            "0x5e59cd0": "rocksdb::DBImpl::ValidateOptions "
                         "(1-arg, census-bound, db_impl_open.o, open "
                         "PR #6379): called once (0x5d7256d) on the "
                         "rebuilt DBOptions. Taken as an oracle.",
            "0x5d8e3b0": "rocksdb::ColumnFamilyData::"
                         "ValidateOptions (census-bound, "
                         "column_family.o, open PR #6449): called "
                         "once per live CF (0x5d725f6). Taken as an "
                         "oracle.",
            "0x5d8bce0": "rocksdb::ColumnFamilyData::"
                         "GetLatestCFOptions (census-bound, "
                         "column_family.o): called once per live CF "
                         "(0x5d725e4).",
            "0x5dd5f00": "rocksdb::DBImpl::GetBGJobLimits "
                         "(census-bound, db_impl_compaction_flush.o): "
                         "called twice (0x5d7265a current, and once "
                         "for the new limits). The static formula: "
                         "flushes==-1 and compactions==-1 gives a "
                         "quarter of max_background_jobs to flushes; "
                         "else max(1, flushes/compactions); "
                         "parallelize=true here so the throttle arm "
                         "never fires.",
            "0x5e8c5e0": "rocksdb::DBImpl::SwitchWAL "
                         "(census-bound, db_impl_write.o): called "
                         "once (0x5d72c52). A failure is only logged, "
                         "never returned.",
            "0x5d713f0": "rocksdb::DBImpl::WriteOptionsFile "
                         "(census-bound, db_impl.o): called once "
                         "(0x5d72c83). Its status is kept in "
                         "persist_options_status and only surfaces "
                         "as IOError when fail_if_options_file_error "
                         "is set.",
            "0x60d52f0": "PLT pthread_mutex_unlock via the "
                         "149-byte body at 0x60d52f0: the census "
                         "lists 9 identical candidate symbols for "
                         "that body (Lock/Unlock/CondVar::Signal/"
                         "...); the disassembly calls "
                         "pthread_mutex_unlock (PLT 0x63f0b70), so "
                         "this copy IS Mutex::Unlock. Called 3x in "
                         "the main FDE (the scheduler unlock, the "
                         "relock path's unlock, the epilogue "
                         "unlock) and 1x in the .cold chain. The "
                         "Lock copy is 0x60d5230, reached through "
                         "the InstrumentedMutexLock wrapper "
                         "0x606ca40 (not in the vendor census).",
            "0x63f0d70": "PLT __stack_chk_fail: the canary failure "
                         "at the epilogue (0x5d720a1) and in the "
                         ".cold chain (0x5d71f1c).",
            "0x63f0a50": "PLT _Unwind_Resume: the .cold chain ends "
                         "here (0x5d71f1c path) after the canary "
                         "check.",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this VM. "
            "The target binary is never executed. The tool models the "
            "setter in Python from its whole-FDE disassembly; the "
            "Status ctor's observable behavior is pinned from its own "
            "disassembly. Status state_ buffers are deterministic heap "
            "ids, not real pointers; the subcode padding bytes "
            "(+0x6..+0x7) the binary never writes are modelled as "
            "zero. The live check (--live) reads the binary: both "
            "FDE body hashes, both source hashes, both FDE records "
            "(lengths 0x4c/0x20, ranges 0xe70/0xf6, aug_len 4, LSDA "
            "pointers 0x4092b8/0x409343), the LSDA call-site tables "
            "(22 + 1 entries, all cleanup), the 15 landing-pad stub "
            "mappings, the engine-call counts, the field cmp "
            "instructions, the message bytes and the empty caller "
            "census plus the vtable slot. make "
            "verify/test/catalogue-check in a tooled environment is "
            "still owed upstream.",
        "functions": functions,
        "layouts": {
            "status": {
                "+0x00": "code (u8; the Code enum; 0 = kOk, 3 = "
                         "kNotSupported, 4 = kInvalidArgument, 5 = "
                         "kIOError here). Written by the ctor "
                         "(mov %sil) and by the OK path (movl $0x0 "
                         "covers +0x0..+0x3).",
                "+0x01": "subcode (u8). Written by the ctor "
                         "(mov %dl); 0 in every result this FDE "
                         "produces.",
                "+0x02": "severity (u8). Written by the ctor "
                         "(mov %r9b); 0 in every result this FDE "
                         "produces.",
                "+0x03": "padding (5 bytes, +0x3..+0x7). The ctor "
                         "writes +0x3..+0x5 zero; the OK path writes "
                         "+0x3..+0x5 zero; +0x6..+0x7 are NEVER "
                         "written by any path in this FDE -- modelled "
                         "as zero, recorded as unwritten.",
                "+0x08": "state_ (char*, 8 bytes). nullptr = no "
                         "message; otherwise a heap buffer of "
                         "len(msg)+1 bytes holding msg + NUL (or "
                         "msg + ': ' + msg2 + NUL when msg2 is "
                         "non-empty, as in the persist IOError), "
                         "freed by the caller's move/delete[], never "
                         "in this FDE.",
                "size": "0x10 (16 bytes)",
            },
            "dbimpl_fields_read": {
                "+0x68": "versions_ (VersionSet*).",
                "+0x318": "env_ (Env*).",
                "+0x330": "immutable_db_options_ (ImmutableDBOptions).",
                "+0x4c0": "fail_if_options_file_error, read through "
                         "immutable_db_options_ (cmpb $0x0,0x4c0"
                         "(%rbx) -- the vendored DBOptions layout "
                         "puts it at +0x190 inside DBOptions, vs "
                         "+0x210 in a stock v8.1.1 compile).",
                "+0x5a0": "mutable_db_options_ (MutableDBOptions, "
                         "0x70 B).",
                "+0x700": "mutex_ (port::Mutex).",
                "+0x750": "table_cache_ (shared_ptr<TableCache>).",
                "+0x8d0": "file_options_for_compaction_ "
                         "(FileOptions).",
                "+0xc28": "total_log_size_ (uint64_t).",
                "+0x1120": "write_controller_ (WriteController).",
                "+0x1748": "periodic_task_scheduler_ "
                         "(PeriodicTaskScheduler).",
                "+0x1780": "periodic_task_functions_ (the task map, "
                         "read at +0x1780 for the dump/persist "
                         "function pointers).",
                "+0x1860": "max_total_wal_size_ (atomic uint64_t).",
                "+0xd40": "write_thread_ (WriteThread).",
            },
            "mutable_db_options_fields": {
                "size": "0x70 (112 bytes)",
                "fields": "max_background_jobs, "
                         "max_background_compactions, "
                         "max_subcompactions, "
                         "avoid_flush_during_shutdown, "
                         "writable_file_max_buffer_size, "
                         "delayed_write_rate, max_total_wal_size, "
                         "delete_obsolete_files_period_micros, "
                         "stats_dump_period_sec, "
                         "stats_persist_period_sec, "
                         "stats_history_buffer_size, max_open_files, "
                         "bytes_per_sync, wal_bytes_per_sync, "
                         "strict_bytes_per_sync, "
                         "compaction_readahead_size, "
                         "max_background_flushes.",
            },
            "lsda": {
                "main": "LSDA at 0x4092b8 (134 bytes): 22 call-site "
                        "entries, all cleanup (action 0). Entry [0] "
                        "(the empty-input Log + Status ctor) has NO "
                        "landing pad, so a throw there propagates "
                        "with no cleanup and no canary check. The "
                        "other 21 entries map to 15 distinct "
                        "landing-pad stubs at 0x5d72d9c..0x5d72e44, "
                        "each endbr64 + mov %rax,%rbx + jmp rel32 "
                        "into the .cold FDE.",
                "cold": "LSDA at 0x409343: 1 call-site entry "
                        "(38,81,0,0) for the _Unwind_Resume call -- "
                        "no landing pad of its own.",
            },
            "landing_pads": {
                "0x5d72d9c": "-> cold 0x5d71efe: "
                            "SuperVersionContext ctor throw.",
                "0x5d72da8": "-> cold 0x5d71ef4: mutex-lock / log / "
                            "dump / ToString / log-failed throws.",
                "0x5d72db4": "-> cold 0x5d71f4b: parse / log-not-"
                            "changed / build throws.",
                "0x5d72dc0": "-> cold 0x5d71f37: validate-cf throw.",
                "0x5d72dcc": "-> cold 0x5d71eea: log-persist-warn "
                            "throw.",
                "0x5d72dd8": "-> cold 0x5d71eea: persist-IOError "
                            "Status ctor throw.",
                "0x5d72de4": "-> cold 0x5d71f41: validate1 / "
                            "get-latest-cf-options / bg-limits / "
                            "inc-threads / maybe-schedule / "
                            "unregister / register / relock / "
                            "file-options-ctor throws.",
                "0x5d72df0": "-> cold 0x5d71f76: enter-unbatched / "
                            "switch-wal / write-options-file / "
                            "exit-unbatched throws.",
                "0x5d72dfc": "-> cold 0x5d71f80: hashtable-assign-"
                            "read throw.",
                "0x5d72e08": "-> cold 0x5d71fa4: hashtable-assign-"
                            "read2 throw.",
                "0x5d72e14": "-> cold 0x5d71fb4: optimize-read "
                            "throw.",
                "0x5d72e20": "-> cold 0x5d71f90: optimize-write "
                            "throw.",
                "0x5d72e2c": "-> cold 0x5d71f5c: log-switchwal-fail "
                            "throw.",
                "0x5d72e38": "-> cold 0x5d71f64: tostring-switchwal "
                            "throw.",
                "0x5d72e44": "-> cold 0x5d71fcb: hashtable-assign-"
                            "write throw.",
            },
            "error_blocks": {
                "0x5d72033": "empty-input Log call (no landing pad: "
                            "a throw propagates with no cleanup).",
                "0x5d7208b": "empty-input Status ctor (no landing "
                            "pad): InvalidArgument 'empty input' "
                            "into out, then the early return (no "
                            "epilogue cleanup, only the canary "
                            "check at 0x5d720a1).",
                "0x5d724a2": "persist-IOError Status ctor (pad "
                            "0x5d72dd8 -> cold 0x5d71eea): IOError "
                            "'SetDBOptions() succeeded, but unable "
                            "to persist options: <persist status>' "
                            "into s, then the log-persist-warn path.",
                "0x5d72238..0x5d72337": "common epilogue: "
                            "WriteContext::Clean + delete memtables, "
                            "SuperVersionContext dtor, delete[] "
                            "persist_options_status.state_ (null "
                            "unless WriteOptionsFile failed) and "
                            "delete[] s.state_ (null after the move "
                            "into out), then the canary check at "
                            "0x5d720a1.",
            },
        },
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
