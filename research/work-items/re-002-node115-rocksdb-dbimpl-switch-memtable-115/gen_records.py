#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

The body hashes are recomputed from work/hl-node-115.bin over the
FDE ranges. Both FDEs are vendor-census-bound (member
4d429ab1cb2d8f8b-db_impl_write.o, librocksdb-sys 0.11.0+8.1.1);
their source hashes reproduce exactly by zeroing the census
relocations (main 110, cold 13, kinds 2/4/42, no relaxation).
The main FDE has a .cold FDE with a 21-entry LSDA (all cleanup,
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
    ("0x5e8a890", "0x5e8c518",
     "rocksdb::DBImpl::SwitchMemtable",
     "switch-memtable-5e8a890", True),
    ("0x5e8a7ae", "0x5e8a882",
     "rocksdb::DBImpl::SwitchMemtable.cold",
     "switch-memtable-5e8a7ae-cold", True),
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
    main_calls = [s for s in sites if s["target"] == "0x5e8a890"]
    functions["0x5e8a890"]["callers"] = [s["site"] for s in main_calls]
    functions["0x5e8a890"]["model"] = (
        "7304-byte memtable switch "
        "SwitchMemtable(ColumnFamilyData*, WriteContext*) "
        "(Status by value, sret out in rdi = r15; this in rsi = "
        "r14; cfd in rdx = rbx; context in rcx; stack canary used, "
        "stored -0x38(%rbp), checked at the epilogue 0x5e8acde and "
        "in the .cold chain at 0x5e8a814 before _Unwind_Resume). "
        "mutex_.AssertHeld() (the empty 0x60d5390), then "
        "WriteRecoverableState (0x5e8a4e0, oracle); a failure "
        "returns that status directly through the epilogue (no "
        "SetBGError). creating_new_log = !log_empty_, read under "
        "log_write_mutex_ when two_write_queues_ is set; the "
        "front of log_recycle_files_ is reused when creating and "
        "recycle_log_file_num is set; new_log_number = "
        "versions_->NewFileNumber() (atomic fetch-add on "
        "versions_+0xd8) when creating, else logfile_number_. "
        "The MutableCFOptions copy (deep copy, three vectors "
        "reallocated), MemTableInfo from cfd->mem(), "
        "NumNotFlushed, GetWalPreallocateBlockSize "
        "(0x5e87d60, pinned from its own disassembly: "
        "write_buffer_size/10 + write_buffer_size, min with "
        "max_total_wal_size when non-zero, min with "
        "db_write_buffer_size when non-zero, max with "
        "write_buffer_manager->buffer_size_ when the manager is "
        "non-null and its size is non-zero), mutex_.Unlock(), "
        "CreateWAL (0x5e5c270, oracle) when creating (s = io_s "
        "when s was OK), ConstructNewMemtable (0x5d8ca00, oracle) "
        "and NewSuperVersion when s is OK, the INFO log line "
        "(0x95b0b0, '[%s:2146] ... New memtable created with log "
        "file: #%lu. Immutable memtables: %d.'), "
        "ConstructFragmentedRangeTombstones on the old mem, "
        "mutex_.Lock(), pop_front of the recycled number, then "
        "the error path whenever s is not OK (delete new_mem and "
        "new_log, reset the superversion, SetBGError(io_s or s, "
        "kMemTable) at 0x5ead310, return GetBGError()). When "
        "creating, lock log_write_mutex_ and WriteBuffer the "
        "last log (0x5e86040 copy-assign s = io_s; a failure "
        "logs the WARN line at 0x962cf0, '[%s:2178] ... Failed to "
        "switch from #%lu to #%lu  WAL file', with TWO spaces "
        "before WAL); when s is OK, record the new log file "
        "(logfile_number_ = new_log_number, log_empty_ = true, "
        "log_dir_synced_ = false, logs_.emplace_back, "
        "alive_log_files_.push_back) -- the record step runs "
        "even when logs_ was empty. When "
        "track_and_verify_wals_in_manifest is on and 2PC is off "
        "and a new log is being created, "
        "PreComputeMinLogNumberWithUnflushedData(logfile_number_) "
        "runs (each CF contributes its log_number_, an empty CF "
        "contributes the new logfile_number_, dropped CFs never "
        "lower the minimum, UINT64_MAX default) and is compared "
        "with the WalSet minimum; when larger, the empty CFs are "
        "collected (autovector, 8 inline slots) and a VersionEdit "
        "deleting WALs before it is applied to the default CF "
        "(LogAndApply 0x5d68760, oracle; a failure with an "
        "IOError versions status becomes SetBGError(io_status, "
        "kManifestWrite) and its status is returned, a failure "
        "otherwise returns the LogAndApply status directly), "
        "then each collected empty CF is re-checked and updated "
        "(SetLogNumber + SetCreationSeq). Otherwise every empty "
        "CF is updated in the plain loop: SetLogNumber only when "
        "creating, SetCreationSeq unconditionally. The tail "
        "installs the new memtable (SetNextLogNumber on the old "
        "mem, imm()->Add, new_mem->Ref(), SetMemtable assigning "
        "last_memtable_id_.fetch_add(1)+1, "
        "InstallSuperVersionAndScheduleWork 0x5de3060, "
        "NotifyOnMemTableSealed 0x5e87e10) and "
        "io_s.PermitUncheckedError().")
    functions["0x5e8a7ae"]["model"] = (
        "212-byte .cold FDE for SwitchMemtable: the landing-pad "
        "continuations for the 9 main-FDE stubs (0x5e8c4ac.."
        "0x5e8c50c, each endbr64 + mov %rax,%rbx + jmp rel32 "
        "into this FDE) plus the 1-entry LSDA at 0x41124a. It "
        "runs the cleanup chain in order and checks the stack "
        "canary at 0x5e8a814 before _Unwind_Resume (0x63f0a50). "
        "A throw with a bad canary becomes StackCheckFailed "
        "after cleanup. The chains are a partial-destruction "
        "ladder for the MutableCFOptions copy (shared_ptr only, "
        "+0xc0 vector, +0x1c8 vector, or the completed copy "
        "dtor), except the WriteBuffer pads (0x5e8c50c), which "
        "unlock log_write_mutex_ first, and the LogAndApply pads "
        "(0x5e8c4dc), which destroy the VersionEdit and the "
        "empty_cfs autovector first.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-vendor-census: both FDEs are "
            "census-bound (member 4d429ab1cb2d8f8b-db_impl_write.o, "
            "librocksdb-sys 0.11.0+8.1.1). Main body 7e3e454f... "
            "/ source 647a18ff... (110 relocations, kinds 2/4/42, "
            "no relaxation); cold body 00213ad0... / source "
            "160ff752... (13 relocations, kind 4, no "
            "relaxation).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "db/db_impl/db_impl_write.cc:2087-2290 defines "
            "SwitchMemtable exactly as the binary behaves -- the "
            "recoverable-state early return (:2095-2098), the "
            "two_write_queues_ log_write_mutex_ read (:2103-"
            "2109), the recycle front (:2111-2114), NewFileNumber "
            "(:2115-2117), the MutableCFOptions copy and "
            "MemTableInfo (:2118-2130), NumNotFlushed and "
            "GetWalPreallocateBlockSize (:2131-2134), the "
            "mutex_.Unlock and CreateWAL (:2135-2142), "
            "ConstructNewMemtable + NewSuperVersion (:2143-2147), "
            "the INFO log (:2148-2152, at source line 2147 vs "
            "2146 in the binary's format string -- a one-line "
            "skew in the vendored file), "
            "ConstructFragmentedRangeTombstones (:2155), the "
            "relock and recycle pop_front (:2157-2166), the "
            "WriteBuffer block with the warn line (:2167-2197, "
            "the warn format at source line 2179 vs 2178 in the "
            "binary, and with TWO spaces before WAL, as in the "
            "binary), the error path (:2199-2219), the "
            "track_and_verify branch with "
            "PreComputeMinLogNumberWithUnflushedData and "
            "LogAndApplyToDefaultColumnFamily (:2221-2272), the "
            "plain empty-CF loop (:2273-2285, SetCreationSeq "
            "unconditional), and the install tail (:2287-2290). "
            "db/version_set.h PreComputeMinLogNumberWithUnflushed-"
            "Data(uint64_t) defines the minimum exactly as the "
            "binary computes it: num = cfd->IsEmpty() ? "
            "new_log_number_for_empty_cf : cfd->GetLogNumber(); "
            "min over non-dropped CFs, UINT64_MAX default. "
            "db_impl_write.cc:1596-1670 defines SwitchWAL, which "
            "calls SwitchMemtable once per column family -- the "
            "sixth caller site (0x5e8c901).",
            "Binary-vs-source observations (recorded, not "
            "hidden): 0x60d52f0 is port::Mutex::Unlock, not "
            "Lock: the census lists 9 identical candidate "
            "symbols for that 149-byte body (Lock/Unlock/"
            "CondVar::Signal/...); the disassembly calls "
            "pthread_mutex_unlock (PLT 0x63f0b70). The Lock copy "
            "is 0x60d5230, reached through the "
            "InstrumentedMutexLock wrapper 0x606ca40 (not in "
            "the vendor census). 0x5d5b080 is a std::vector "
            "buffer free (the _M_deallocate of a vector "
            "destructor), NOT a std::string destructor: the "
            "string dtor shape (SSO check, capacity+1) is "
            "different, as a g++ -O2 control compile shows; it "
            "frees the empty_cfs overflow vector buffer. The "
            "sibling SetDBOptions packet's 'string dtor' label "
            "for this address is a misread; this packet does "
            "not repeat it. GetWalPreallocateBlockSize has a "
            "third term the v8.1.1 tag source lacks: max with "
            "write_buffer_manager->buffer_size_ when the manager "
            "is non-null and its size is non-zero (the manager "
            "is final, so *(ptr) IS buffer_size_). 0x5e85ea0 is "
            "the Status move-assign (copies the bytes, zeroes "
            "the source; not in the vendor census). 0x5d8ce80 "
            "is a 6-byte getter returning *(ColumnFamilySet+"
            "0x118) -- the default ColumnFamilyData* passed as "
            "the first LogAndApply argument (not in the vendor "
            "census). 0x5d67c10 is the empty_cfs autovector "
            "overflow-buffer growth (std::vector push_back "
            "reallocation; not in the vendor census). 0x5f12a10 "
            "is imm()->NumNotFlushed() (mov 0x8(%rdi),%rax; mov "
            "0x10(%rax),%eax; ret). The binary checks the stack "
            "canary at ten return points (one store + ten sub "
            "%fs:0x28,%rax), not only at the epilogue. "
            "logfile_number_ is already the NEW log number when "
            "the min-WAL loop runs, so an empty CF contributes "
            "the new number. The 16-bit store of 0x100 at "
            "DBImpl+0xab8 sets log_dir_synced_ = 0 and "
            "log_empty_ = 1 in one instruction.",
            "Corrections made in-cycle while verifying this "
            "packet against the binary and the v8.1.1 source "
            "(the draft model had these wrong; the packet as "
            "submitted has them right): (1) the min-WAL "
            "computation took the minimum over EMPTY CFs' log "
            "numbers -- the binary and version_set.h take the "
            "minimum over (empty ? new logfile_number_ : "
            "cf->log_number_) for non-dropped CFs; (2) the "
            "plain-loop SetCreationSeq was gated on "
            "creating_new_log -- the binary (0x5e8b35f) and the "
            "source set it unconditionally for empty CFs; (3) "
            "the WriteBuffer-block record step (logfile_number_ "
            "= new, log_empty_ = true, logs_.emplace_back, "
            "alive_log_files_.push_back) was nested inside the "
            "!logs_.empty() check -- the binary (0x5e8b642 "
            "jumps to the s check at 0x5e8b734 when logs_ is "
            "empty) and the source run it whenever s is OK; "
            "(4) the caller census listed five sites and "
            "claimed the 0x5e8c901 pattern was rejected -- the "
            "whole-.text scan finds six validated sites, the "
            "sixth being DBImpl::SwitchWAL, confirmed by the "
            "v8.1.1 SwitchWAL source; (5) the log-warn format "
            "string has TWO spaces before WAL (60 bytes, not "
            "one space); (6) the deque-length-error string is "
            "47 bytes, not 49.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "target, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "DBImpl::SwitchMemtable 0x5e8a890: exactly 6 direct "
                "calls, 0 tail jumps, 0 LEA refs -- two in "
                "DBImpl::FlushMemtable (0x5ddfb4a, 0x5de0835), one "
                "in DBImpl::AtomicFlushMemTables (0x5de189a), one "
                "in DBImpl::SwitchWAL (0x5e8c901, FDE 0x5e8c5e0.."
                "0x5e8d007, census-bound), one in DBImpl::"
                "HandleWriteBufferManagerFlush (0x5e8d404) and one "
                "in DBImpl::ScheduleFlushes (0x5e8dd1c). The raw "
                "scan finds exactly these six candidates, all "
                "validated. The upstream source calls "
                "SwitchMemtable from WriteImpl variants "
                "(db_impl_write.cc:1666, 1757, 2035); the "
                "binary's callers differ -- recorded as observed. "
                "SwitchWAL itself calls SwitchMemtable once per "
                "column family (db_impl_write.cc:1660).",
                "Main FDE record in .eh_frame (section offset "
                "0x73fe08, length 0x4c, initial_location "
                "0x5e8a890, range 0x1c88, aug_len 4, LSDA at "
                "0x4111c4, 21 call-site entries, all cleanup, "
                "entry [0] has no landing pad). Cold FDE record "
                "(section offset 0x73fe58, length 0x20, range "
                "0xd4, aug_len 4, LSDA at 0x41124a, 1 entry, no "
                "landing pad).",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 checks (25 modes: recoverable-fail, "
                     "no-create, create-ok, create-fail, "
                     "two-write-queues, two-write-queues-no-create, "
                     "recycle-hit, recycle-empty, recycle-num-zero, "
                     "write-buffer-fail, write-buffer-ok, "
                     "logs-empty, recovery-in-progress, "
                     "track-min-apply, track-min-no-apply, "
                     "track-allow-2pc, track-no-create, "
                     "log-and-apply-fail-ioerror, "
                     "log-and-apply-fail-other, dropped-cf-excluded, "
                     "plain-loop-multi, preallocate-max-total, "
                     "preallocate-db-wbs, preallocate-wbm, mixed) + "
                     "600 status (6 kinds: ok, error, image, "
                     "tostring, copy-assign, alloc-fail) + 600 throw "
                     "(one armed fail_at per case across all 32 "
                     "THROW_SITES, in 5 modes: throw, "
                     "throw-bad-canary, badalloc-bad-canary, "
                     "canary-return, alloc-false) + 600 bindings "
                     "(caller-site independence across the 6 caller "
                     "sites, both FDE hashes as expected values)",
            "tests": "tests/test_switch_memtable115.py",
            "tool": "tools/switch_memtable115.py",
            "what_is_checked": [
                "checks: a recoverable-state failure returns that "
                "status directly; no-create returns OK with no new "
                "log and the plain loop still sets the creation "
                "sequence; create-ok records the new log file "
                "(logfile_number_, log_empty_, logs_, "
                "alive_log_files_); create-fail goes to the error "
                "path (SetBGError(io_s), GetBGError); "
                "two_write_queues_ takes the log_write_mutex_ "
                "around the log_empty_ read; a recycle hit reuses "
                "and pops the front number, an empty recycle deque "
                "and recycle_log_file_num 0 take a fresh number; a "
                "WriteBuffer failure logs the warn line (with two "
                "spaces before WAL) and goes to the error path; a "
                "WriteBuffer success records the log even when "
                "logs_ was empty; recovery-in-progress resets the "
                "seen_error flag; track-min-apply runs LogAndApply "
                "when the min WAL exceeds the WalSet minimum "
                "(empty CFs contribute the new log number, "
                "non-empty CFs their own, dropped CFs excluded) "
                "and updates the empty CFs; track-min-no-apply "
                "takes the plain loop; allow_2pc and no-create "
                "skip the track branch; a LogAndApply failure with "
                "an IOError versions status becomes SetBGError "
                "(kManifestWrite), otherwise the LogAndApply "
                "status is returned; the plain loop sets the "
                "creation sequence unconditionally; the "
                "preallocate size follows the three-term formula "
                "(write_buffer_size/10 + write_buffer_size, min "
                "with max_total_wal_size, min with "
                "db_write_buffer_size, max with the write-buffer "
                "manager size)",
                "status: the Status byte layout the ctor proves "
                "(code u8 +0x0, subcode u8 +0x1, severity u8 "
                "+0x2, padding +0x3..+0x7 zero with +0x6..+0x7 "
                "unwritten, state_ +0x8); the state_ buffer is "
                "msg + NUL with alloc len+1; the ctor's ': ' join "
                "when msg2 is non-empty; ToString renders the "
                "human phrases ('IO error: ', 'Invalid argument: "
                "', ...) from the jump table, never the 'k' enum "
                "names; codes > 15 render as 'Unknown code(%d): "
                "'; copy-assign steals a fresh copy of the state_ "
                "buffer; an alloc failure in the copy ctor raises "
                "BadAlloc with the half-built status attached",
                "throw: each throwing call is recorded with its "
                "landing-pad stub and its .cold cleanup chain "
                "(the MutableCFOptions partial-destruction ladder, "
                "the log_write_mutex_ unlock first for the "
                "WriteBuffer pads, the VersionEdit + empty_cfs "
                "destruction for the LogAndApply pads); a throw "
                "through a pad with a bad canary becomes "
                "StackCheckFailed after cleanup; the AssertHeld "
                "throw has no pad and propagates with no cleanup "
                "and no canary check; a canary failure on a "
                "normal return raises StackCheckFailed at the "
                "epilogue; alloc_ok=False fires only on an "
                "allocating site",
                "bindings: the result depends only on the inputs, "
                "never on the caller site; both FDE body hashes, "
                "both source hashes (110 + 13 relocations zeroed) "
                "and the engine-call counts match the binary",
            ],
        },
        "engine_callees": {
            "0x61cf670": "rocksdb::Status::Status(Code, SubCode, "
                         "const Slice&, const Slice&, Severity) "
                         "(census-bound, status.o): the five-argument "
                         "Status ctor. Its observable behavior IS "
                         "pinned from its disassembly: code u8 +0x0, "
                         "subcode u8 +0x1, severity u8 +0x2, zeroes "
                         "+0x3..+0x5, state_ = new char[size+1] "
                         "holding msg + (': ' + msg2 if len2) + NUL. "
                         "Its trailing delete[] of the old state_ is "
                         "DEAD (state_ is zeroed at 0x61cf6b0 before "
                         "the read at 0x61cf6e4).",
            "0x61cfed0": "rocksdb::Status::ToString (census-bound, "
                         "status.o): the jump table at 0x97e958 over "
                         "the code byte loads a prefix string per "
                         "code -- 'NotFound: ', 'Corruption: ', 'Not "
                         "implemented: ', 'Invalid argument: ', 'IO "
                         "error: ', 'Merge in progress: ', 'Result "
                         "incomplete: ', 'Shutdown in progress: ', "
                         "'Operation timed out: ', 'Operation "
                         "aborted: ', 'Resource busy: ', 'Operation "
                         "expired: ', 'Operation failed. Try again.: "
                         "', 'Compaction too large: ', 'Column "
                         "family dropped: ' (code 0 is built inline "
                         "as 'OK'; codes > 15 render as 'Unknown "
                         "code(%d): '). A non-zero subcode appends "
                         "its string from the table at 0x64d7b00, "
                         "then ': ' + state_.",
            "0x5e86040": "rocksdb::Status::operator=(const Status&) "
                         "(census-bound, status.o): the copy-assign, "
                         "called 3x (s = io_s after CreateWAL at "
                         "0x5e8b7a1, s = io_s after WriteBuffer at "
                         "0x5e8b83e, s = SetBGError(...) after a "
                         "LogAndApply IOError at 0x5e8bf32). Deletes "
                         "the old state_, copies code/subcode/"
                         "severity, steals a fresh copy of the "
                         "state_ buffer.",
            "0x5e85ea0": "rocksdb::Status::operator=(Status&&) (NOT "
                         "in the vendor census): the move-assign, "
                         "called 2x (after the error-path "
                         "GetBGError copy at 0x5e8b482 and after "
                         "LogAndApply at 0x5e8bc64). Copies the 16 "
                         "bytes and zeroes the source, as its own "
                         "disassembly shows.",
            "0x5e8a4e0": "rocksdb::DBImpl::WriteRecoverableState "
                         "(census-bound, db_impl_write.o): called "
                         "once (0x5e8a90b). Taken as an oracle.",
            "0x5e5c270": "rocksdb::DBImpl::CreateWAL "
                         "(census-bound, db_impl_write.o): called "
                         "once (0x5e8a9c6) when creating a new log. "
                         "Taken as an oracle.",
            "0x5d8ca00": "rocksdb::ColumnFamilyData::"
                         "ConstructNewMemtable (census-bound, "
                         "column_family.o): called once (0x5e8b246) "
                         "when s is OK. Taken as an oracle.",
            "0x5e87d60": "rocksdb::DBImpl::"
                         "GetWalPreallocateBlockSize (census-bound, "
                         "db_impl_write.o): called once (0x5e8b1f8). "
                         "Its formula IS pinned from its own "
                         "disassembly (see the model).",
            "0x5e87e10": "rocksdb::DBImpl::NotifyOnMemTableSealed "
                         "(census-bound, db_impl_write.o): called "
                         "once (0x5e8abf7) in the install tail.",
            "0x5de3060": "rocksdb::DBImpl::"
                         "InstallSuperVersionAndScheduleWork "
                         "(census-bound, db_impl_compaction_flush.o): "
                         "called once (0x5e8abe5) in the install "
                         "tail.",
            "0x5d68760": "rocksdb::VersionSet::LogAndApply "
                         "(census-bound, version_set.o): called once "
                         "(0x5e8bc55) in the track_and_verify branch. "
                         "Taken as an oracle.",
            "0x5ead310": "rocksdb::ErrorHandler::SetBGError "
                         "(census-bound, error_handler.o): called "
                         "3x (the error path at 0x5e8b453 and "
                         "0x5e8b5fd, the manifest path at 0x5e8bf27), "
                         "always with reason 3 (kMemTable) on the "
                         "memtable path.",
            "0x5d8d820": "rocksdb::SuperVersion::~SuperVersion "
                         "(census-bound, column_family.o): the "
                         "superversion reset in the error path "
                         "(0x5e8b413) and the context dtor.",
            "0x5f10d40": "rocksdb::MemTable::~MemTable "
                         "(census-bound, memtable.o): the new_mem "
                         "delete in the error path (0x5e8b3bf) with "
                         "_ZdlPvm 0xd20.",
            "0x5f04800": "rocksdb::log::Writer::~Writer "
                         "(census-bound, log_writer.o): the new_log "
                         "delete in the error path (0x5e8b3e0) with "
                         "_ZdlPvm 0x58.",
            "0x5d8ce80": "A 6-byte getter returning "
                         "*(ColumnFamilySet+0x118) -- the default "
                         "ColumnFamilyData* passed as the first "
                         "LogAndApply argument (called once, "
                         "0x5e8bc17; NOT in the vendor census).",
            "0x5d67c10": "The empty_cfs autovector overflow-buffer "
                         "growth (std::vector push_back "
                         "reallocation; called once, 0x5e8c16a; NOT "
                         "in the vendor census).",
            "0x5f12a10": "imm()->NumNotFlushed() (called 5x): mov "
                         "0x8(%rdi),%rax; mov 0x10(%rax),%eax; ret.",
            "0x60d5390": "port::Mutex::AssertHeld (census-bound, "
                         "port.o): the empty body (endbr64; ret), "
                         "called once (0x5e8a8df). A throw here has "
                         "no landing pad.",
            "0x60d52f0": "PLT pthread_mutex_unlock via the "
                         "149-byte body at 0x60d52f0: the census "
                         "lists 9 identical candidate symbols for "
                         "that body; the disassembly calls "
                         "pthread_mutex_unlock (PLT 0x63f0b70), so "
                         "this copy IS Mutex::Unlock. Called 3x in "
                         "the main FDE and 1x in the .cold chain. "
                         "The Lock copy is 0x60d5230, reached "
                         "through the InstrumentedMutexLock wrapper "
                         "0x606ca40 (not in the vendor census).",
            "0x63f0d70": "PLT __stack_chk_fail: the canary failure "
                         "at the epilogue (0x5e8acde) and in the "
                         ".cold chain (0x5e8a814).",
            "0x63f0a50": "PLT _Unwind_Resume: the .cold chain ends "
                         "here (0x5e8a814 path) after the canary "
                         "check.",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this VM. "
            "The target binary is never executed. The tool models the "
            "switch in Python from its whole-FDE disassembly; the "
            "Status ctor, ToString, move-assign and "
            "GetWalPreallocateBlockSize behaviors are pinned from "
            "their own disassemblies. Status state_ buffers are "
            "deterministic heap ids, not real pointers; the subcode "
            "padding bytes (+0x6..+0x7) the binary never writes are "
            "modelled as zero. The live check (--live) reads the "
            "binary: both FDE body hashes, both source hashes, both "
            "FDE records (lengths 0x4c/0x20, ranges 0x1c88/0xd4, "
            "aug_len 4, LSDA pointers 0x4111c4/0x41124a), the LSDA "
            "call-site tables (21 + 1 entries, all cleanup), the 9 "
            "landing-pad stub mappings, the engine-call counts, the "
            "field cmp instructions, the message bytes and the "
            "6-site caller census. make verify/test/catalogue-check "
            "in a tooled environment is still owed upstream.",
        "functions": functions,
        "layouts": {
            "status": {
                "+0x00": "code (u8; the Code enum; 0 = kOk, 3 = "
                         "kNotSupported, 4 = kInvalidArgument, 5 = "
                         "kIOError here). Written by the ctor "
                         "(mov %sil) and by the OK path.",
                "+0x01": "subcode (u8). Written by the ctor "
                         "(mov %dl); 0 in every result this FDE "
                         "produces.",
                "+0x02": "severity (u8). Written by the ctor "
                         "(mov %r9b); 0 in every result this FDE "
                         "produces.",
                "+0x03": "padding (5 bytes, +0x3..+0x7). The ctor "
                         "writes +0x3..+0x5 zero; +0x6..+0x7 are "
                         "NEVER written by any path in this FDE -- "
                         "modelled as zero, recorded as unwritten.",
                "+0x08": "state_ (char*, 8 bytes). nullptr = no "
                         "message; otherwise a heap buffer of "
                         "len(msg)+1 bytes holding msg + NUL (or "
                         "msg + ': ' + msg2 + NUL when msg2 is "
                         "non-empty), freed by the caller's "
                         "move/delete[], never in this FDE.",
                "size": "0x10 (16 bytes)",
            },
            "dbimpl_fields_read": {
                "+0x68": "versions_ (VersionSet*). NewFileNumber "
                         "is the atomic fetch-add at versions_+0xd8; "
                         "LastSequence is at versions_+0x108; the "
                         "WalSet minimum is at versions_+0x38; "
                         "column_family_set_ is at versions_+0x40; "
                         "io_status is at versions_+0x280.",
                "+0x330": "immutable_db_options_ "
                         "(ImmutableDBOptions): recycle_log_file_num "
                         "+0x400, db_write_buffer_size +0x440, "
                         "write_buffer_manager +0x448, "
                         "track_and_verify_wals_in_manifest +0x335, "
                         "allow_2pc +0x4a3, info_log +0x360.",
                "+0x5c0": "mutable_db_options_.max_total_wal_size "
                         "(read by GetWalPreallocateBlockSize).",
                "+0x700": "mutex_ (port::Mutex). AssertHeld at "
                         "entry; Unlock before the WAL/memtable "
                         "creation; Lock after the log line.",
                "+0x760": "error_handler_ (ErrorHandler). "
                         "bg_error_ is at +0x10; the "
                         "recovery-in-progress flag is at DBImpl+"
                         "0x809.",
                "+0x9c8": "log_write_mutex_ (port::Mutex).",
                "+0xa60": "logfile_number_ (uint64_t).",
                "+0xa78": "log_recycle_files_ (deque<uint64_t>).",
                "+0xab8": "log_dir_synced_ (bool; set together "
                         "with log_empty_ by one 16-bit store of "
                         "0x100).",
                "+0xab9": "log_empty_ (bool).",
                "+0xb00": "alive_log_files_ (vector of "
                         "LogFileNumberSize).",
                "+0xb20": "logs_ (deque of (log_number, writer)).",
                "+0xd08": "directories_ (Directories).",
                "+0x17b0": "two_write_queues_ (bool).",
            },
            "column_family_data_fields": {
                "+0x3d": "dropped_ (bool, the min-WAL loop's "
                         "exclusion test).",
                "+0x6c0": "mutable_cf_options_ "
                         "(MutableCFOptions, copied).",
                "+0x8e8": "mem_ (MemTable*).",
                "+0x8f0": "imm_ (ImmutableMemTableList).",
                "+0x938": "next_ (ColumnFamilyData*, the "
                         "ColumnFamilySet chain).",
                "+0x948": "log_number_ (uint64_t).",
                "+0x980": "last_memtable_id_ (atomic uint64_t; "
                         "SetMemtable assigns fetch_add(1)+1).",
            },
            "memtable_fields": {
                "+0x70": "refs_ (atomic int32; new_mem->Ref() at "
                         "the tail).",
                "+0xa70": "num_entries.",
                "+0xa78": "num_deletes.",
                "+0xc18": "first_seqno (SequenceNumber).",
                "+0xc20": "earliest_seqno.",
                "+0xc28": "creation_seq.",
                "+0xc30": "next_log_number.",
                "+0xcc0": "id.",
                "size": "0xd20 (3360 bytes)",
            },
            "lsda": {
                "main": "LSDA at 0x4111c4 (129-byte call-site "
                        "table): 21 call-site entries, all cleanup "
                        "(action 0). Entry [0] (the AssertHeld "
                        "no-op call at +79) has NO landing pad, so "
                        "a throw there propagates with no cleanup "
                        "and no canary check. The other 20 entries "
                        "map to 9 distinct landing-pad stubs at "
                        "0x5e8c4ac..0x5e8c50c, each endbr64 + mov "
                        "%rax,%rbx + jmp rel32 into the .cold FDE.",
                "cold": "LSDA at 0x41124a (4-byte call-site "
                        "table): 1 call-site entry (120,5,0,0) for "
                        "the _Unwind_Resume call -- no landing pad "
                        "of its own.",
            },
            "landing_pads": {
                "0x5e8c4ac": "-> cold 0x5e8a7f5: "
                            "log_write_mutex_ lock/unlock throws "
                            "(the two_write_queues_ reads) -- no "
                            "copy cleanup yet, only the epilogue "
                            "tail.",
                "0x5e8c4b8": "-> cold 0x5e8a83a: the completed "
                            "MutableCFOptions copy chain (dispose "
                            "memtable_info.cf_name, run the copy "
                            "dtor, delete[] io_s.state_ if set).",
                "0x5e8c4c4": "-> cold 0x5e8a85c: the autovector "
                            "chain (clear empty_cfs, free the "
                            "overflow buffer, then the completed-"
                            "copy chain).",
                "0x5e8c4d0": "-> cold 0x5e8a7ae: the copy-alloc-3 "
                            "chain (free compression_per_level and "
                            "max_bytes_for_level_multiplier_additional "
                            "buffers, release prefix_extractor).",
                "0x5e8c4dc": "-> cold 0x5e8a850: the LogAndApply "
                            "chain (destroy the VersionEdit, clear "
                            "empty_cfs, free the overflow buffer, "
                            "then the completed-copy chain).",
                "0x5e8c4e8": "-> cold 0x5e8a7c9: the copy-alloc-2 "
                            "chain (free max_bytes_for_level_"
                            "multiplier_additional buffer, release "
                            "prefix_extractor).",
                "0x5e8c4f4": "-> cold 0x5e8a803: the "
                            "WriteRecoverableState chain (delete[] "
                            "io_s.state_ if set, then the canary "
                            "check and _Unwind_Resume).",
                "0x5e8c500": "-> cold 0x5e8a7e4: the copy-alloc-1 "
                            "chain (release prefix_extractor only).",
                "0x5e8c50c": "-> cold 0x5e8a82b: the WriteBuffer "
                            "chain (unlock log_write_mutex_ first, "
                            "then the completed-copy chain).",
            },
            "error_blocks": {
                "0x5e8a914": "WriteRecoverableState failure: jumps "
                            "straight to the epilogue at 0x5e8acc0 "
                            "and returns the status -- no "
                            "SetBGError, no error path.",
                "0x5e8b3b0": "The error path: delete new_mem "
                            "(MemTable dtor + _ZdlPvm 0xd20) and "
                            "new_log (log::Writer dtor + _ZdlPvm "
                            "0x58) when non-null, reset the "
                            "superversion (SuperVersion dtor + "
                            "_ZdlPvm 0x290), SetBGError(io_s when it "
                            "failed, else s, kMemTable) at 0x5e8b453 "
                            "or 0x5e8b5fd, then return GetBGError() "
                            "(inlined: a copy of bg_error_ at "
                            "error_handler_+0x10). Reached whenever "
                            "s is not OK after the relock or after "
                            "the WriteBuffer block. The source "
                            "asserts creating_new_log here.",
                "0x5e8bfe6": "The LogAndApply failure return: "
                            "destroy the VersionEdit, the empty_cfs "
                            "autovector and its overflow buffer, "
                            "then the epilogue -- reached when "
                            "LogAndApply fails (after the optional "
                            "SetBGError(manifest) step).",
            },
        },
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
