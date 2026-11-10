# RE-002 · Node #115 RocksDB DBImpl::SwitchMemtable

Component: storage / WAL / memtable. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 rotate the active memtable -- what does
`rocksdb::DBImpl::SwitchMemtable(ColumnFamilyData*, WriteContext*)`
do with the WAL, the recycle deque, the write-buffer manager and the
empty column families, and who calls it? Both functions are
census-bound (body hash matches the vendor census
`target_body_sha256` exactly; source hash reproduced by zeroing the
recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::DBImpl::SwitchMemtable` | 0x5e8a890..0x5e8c518 | 7304 | `7e3e454f2700b6e9454be33342d3ccdbb063c2c5d3f98a9…` |
| `rocksdb::DBImpl::SwitchMemtable.cold` | 0x5e8a7ae..0x5e8a882 | 212 | `00213ad0c4d7f2e46b6f72d9b9c9da82d921bb0a1b3e6…` |

The full hashes are in `functions.tsv` and `records.json`.

## Answer (pinned)

**Signature.** `Status SwitchMemtable(ColumnFamilyData*, WriteContext*)`
returns by value, so `rdi` is the hidden 16-byte sret out-pointer
(`r15`), `rsi` is `this` (`r14`), `rdx` is `cfd` (`rbx`), `rcx` is
the `WriteContext*`. The stack canary is stored at `-0x38(%rbp)` and
checked at the epilogue (0x5e8acde) and in the `.cold` chain
(0x5e8a814) before `_Unwind_Resume`.

**Entry.** `mutex_.AssertHeld()` (the empty 0x60d5390; a throw here has
no landing pad), then `WriteRecoverableState` (0x5e8a4e0, oracle). A
failure there returns that status directly through the epilogue --
no `SetBGError`, no error path.

**New-log decision.** `creating_new_log = !log_empty_`, read under
`log_write_mutex_` when `two_write_queues_` is set. When creating and
`recycle_log_file_num` is set, the front of `log_recycle_files_` is
reused; otherwise `new_log_number = versions_->NewFileNumber()`
(atomic fetch-add on `versions_+0xd8`). When not creating, the new
log number is the current `logfile_number_`.

**Build.** The `MutableCFOptions` copy (deep copy, three vectors
reallocated), `MemTableInfo` from `cfd->mem()`, `NumNotFlushed`,
`GetWalPreallocateBlockSize` (0x5e87d60, pinned from its own
disassembly: `write_buffer_size/10 + write_buffer_size`, min with
`max_total_wal_size` when non-zero, min with `db_write_buffer_size`
when non-zero, max with `write_buffer_manager->buffer_size_` when the
manager is non-null and its size is non-zero), `mutex_.Unlock()`,
`CreateWAL` (0x5e5c270, oracle) when creating (`s = io_s` when `s`
was OK), `ConstructNewMemtable` (0x5d8ca00, oracle) and
`NewSuperVersion` when `s` is OK, the INFO log line (0x95b0b0,
`[%s:2146] [%s] New memtable created with log file: #%lu. Immutable
memtables: %d.`), `ConstructFragmentedRangeTombstones` on the old
mem, `mutex_.Lock()`, `pop_front` of the recycled number.

**Error path.** Reached whenever `s` is not OK after the relock or
after the WriteBuffer block (0x5e8b3b0): delete `new_mem` (MemTable
dtor + `_ZdlPvm` 0xd20) and `new_log` (log::Writer dtor +
`_ZdlPvm` 0x58) when non-null, reset the superversion (SuperVersion
dtor + `_ZdlPvm` 0x290), `SetBGError(io_s` when it failed, else `s`,
`kMemTable)` at 0x5ead310, return `GetBGError()` (inlined: a copy of
`bg_error_` at `error_handler_+0x10`).

**WriteBuffer block.** When creating, lock `log_write_mutex_` and
WriteBuffer the last log (0x5e86040 copy-assign `s = io_s`); a
failure logs the WARN line at 0x962cf0, `[%s:2178] [%s] Failed to
switch from #%lu to #%lu  WAL file`, with TWO spaces before WAL. When
`s` is OK, record the new log file (`logfile_number_ =
new_log_number`, `log_empty_ = true`, `log_dir_synced_ = false`,
`logs_.emplace_back`, `alive_log_files_.push_back`) -- the record step
runs even when `logs_` was empty (the binary jumps straight to the
`s` check when `logs_` is empty). `log_dir_synced_ = 0` and
`log_empty_ = 1` are set by one 16-bit store of `0x100` at
`DBImpl+0xab8`.

**Empty-CF handling.** When `track_and_verify_wals_in_manifest` is
on and 2PC is off and a new log is being created,
`PreComputeMinLogNumberWithUnflushedData(logfile_number_)` runs: each
CF contributes its `log_number_`, an empty CF contributes the new
`logfile_number_`, dropped CFs never lower the minimum, UINT64_MAX
default (upstream `db/version_set.h`). When the minimum exceeds the
WalSet minimum, the empty CFs are collected (autovector, 8 inline
slots) and a `VersionEdit` deleting WALs before it is applied to the
default CF (`LogAndApply` 0x5d68760, oracle; a failure with an IOError
versions status becomes `SetBGError(io_status, kManifestWrite)` and
its status is returned, a failure otherwise returns the LogAndApply
status directly), then each collected empty CF is re-checked and
updated (`SetLogNumber` + `SetCreationSeq`). Otherwise every empty CF
is updated in the plain loop: `SetLogNumber` only when creating,
`SetCreationSeq` unconditionally.

**Tail.** Install the new memtable (`SetNextLogNumber` on the old
mem, `imm()->Add`, `new_mem->Ref()`, `SetMemtable` assigning
`last_memtable_id_.fetch_add(1)+1`,
`InstallSuperVersionAndScheduleWork` 0x5de3060,
`NotifyOnMemTableSealed` 0x5e87e10) and
`io_s.PermitUncheckedError()`.

**Layouts** (node #115, from the field accesses): DBImpl
`versions_` +0x68, `mutex_` +0x700, `error_handler_` +0x760,
`log_write_mutex_` +0x9c8, `logfile_number_` +0xa60,
`log_empty_` +0xab9, `log_dir_synced_` +0xab8,
`log_recycle_files_` +0xa78, `recycle_log_file_num` +0x400
(immutable), `logs_` +0xb20, `alive_log_files_` +0xb00,
`directories_` +0xd08, `two_write_queues_` +0x17b0,
`track_and_verify` +0x335, `allow_2pc` +0x4a3, `info_log` +0x360,
`max_total_wal_size` (mutable) +0x5c0, `db_write_buffer_size`
(immutable) +0x440, `write_buffer_manager` +0x448.
ColumnFamilyData: `mem_` +0x8e8, `imm_` +0x8f0, `log_number_`
+0x948, `last_memtable_id_` +0x980, `dropped_` +0x3d, `next_`
+0x938, `mutable_cf_options_` +0x6c0. MemTable: `first_seqno`
+0xc18, `earliest_seqno` +0xc20, `creation_seq` +0xc28,
`next_log_number` +0xc30, `id` +0xcc0, size 0xd20. SuperVersion
0x290, log::Writer 0x58.

**The .cold FDE** (0x5e8a7ae, entered from the 9 `endbr64` stubs at
0x5e8c4ac..0x5e8c50c): 1-entry LSDA at 0x41124a. The main FDE's LSDA
at 0x4111c4 has 21 call-site entries, all cleanup, entry [0] (the
AssertHeld no-op call) with no landing pad. The chains are a
partial-destruction ladder for the `MutableCFOptions` copy
(shared_ptr only, +0xc0 vector, +0x1c8 vector, or the completed copy
dtor), except the WriteBuffer pads (0x5e8c50c), which unlock
`log_write_mutex_` first, and the LogAndApply pads (0x5e8c4dc),
which destroy the `VersionEdit` and the `empty_cfs` autovector
first. A throw with a bad canary becomes `StackCheckFailed` after
cleanup.

**Findings (verified against the binary + upstream v8.1.1).**

- *Caller census:* exactly 6 direct calls, 0 tail jumps, 0 LEA refs
  -- two in `DBImpl::FlushMemtable` (0x5ddfb4a, 0x5de0835), one in
  `DBImpl::AtomicFlushMemTables` (0x5de189a), one in
  `DBImpl::SwitchWAL` (0x5e8c901), one in
  `DBImpl::HandleWriteBufferManagerFlush` (0x5e8d404) and one in
  `DBImpl::ScheduleFlushes` (0x5e8dd1c). The upstream source calls
  SwitchMemtable from WriteImpl variants
  (`db_impl_write.cc:1666, 1757, 2035`); the binary's callers differ
  -- recorded as observed. `SwitchWAL` itself calls SwitchMemtable
  once per column family (`db_impl_write.cc:1660`).
- *Log-line skew:* the binary's format strings sit at source lines
  2146/2178 vs 2147/2179 in the v8.1.1 tag -- a one-line skew in the
  vendored file.
- *`0x60d52f0` is `Mutex::Unlock`, not `Lock`:* the census lists 9
  identical candidate symbols for that 149-byte body; the
  disassembly calls `pthread_mutex_unlock` (PLT 0x63f0b70). The Lock
  copy is 0x60d5230, reached through the `InstrumentedMutexLock`
  wrapper 0x606ca40 (not in the vendor census).
- *`0x5d5b080` is a `std::vector` buffer free* (the `_M_deallocate`
  of a vector destructor), NOT a `std::string` destructor: the string
  dtor shape (SSO check, capacity+1) is different, as a g++ -O2
  control compile shows; it frees the `empty_cfs` overflow vector
  buffer. The sibling SetDBOptions packet's "string dtor" label for
  this address is a misread; this packet does not repeat it.
- *`GetWalPreallocateBlockSize` has a third term* the v8.1.1 tag
  source lacks: max with `write_buffer_manager->buffer_size_` when
  the manager is non-null and its size is non-zero.
- *`0x5e85ea0` is the Status move-assign* (copies the 16 bytes,
  zeroes the source; not in the vendor census). `0x5d8ce80` is a
  6-byte getter returning `*(ColumnFamilySet+0x118)` -- the default
  ColumnFamilyData\* passed as the first LogAndApply argument (not in
  the vendor census). `0x5d67c10` is the `empty_cfs` autovector
  overflow-buffer growth (not in the vendor census).
- *The Status ctor's trailing `delete[]` is dead:* `state_` is
  zeroed before the read, so it never fires. The ctor writes bytes
  +0x3..+0x5 zero; bytes +0x6..+0x7 are NEVER written by any path in
  this FDE -- modelled as zero, recorded as unwritten.
- *In-cycle corrections:* the draft model took the min-WAL over
  empty CFs' log numbers (the binary and `version_set.h` take the
  minimum over `empty ? new logfile_number_ : cf->log_number_` for
  non-dropped CFs); gated the plain-loop `SetCreationSeq` on
  creating a new log (it is unconditional for empty CFs); nested the
  record step inside the `!logs_.empty()` check (it runs whenever
  `s` is OK); listed five caller sites (there are six, the sixth in
  SwitchWAL); and had one space before WAL in the warn string
  (there are two) and 49 bytes for the deque-length-error string
  (there are 47). The packet as submitted has all of these right.
- *Live engine check:* a real `run_case` replay of the 2,400 cases
  plus 160 binary legs (`--live`) -- both FDE hashes, both source
  hashes, both FDE records, the 21+1 LSDA entries, the 9 pad
  mappings, the engine-call counts, the field cmps, the message
  bytes and the 6-site census -- all pass.

**Engine callees.** `WriteRecoverableState` 0x5e8a4e0, `CreateWAL`
0x5e5c270, `ConstructNewMemtable` 0x5d8ca00,
`GetWalPreallocateBlockSize` 0x5e87d60, `NotifyOnMemTableSealed`
0x5e87e10, `InstallSuperVersionAndScheduleWork` 0x5de3060,
`LogAndApply` 0x5d68760, `SetBGError` 0x5ead310 (reason 3 =
kMemTable), Status ctor 0x61cf670, Status copy-assign 0x5e86040,
Status move-assign 0x5e85ea0, `Mutex::Unlock` 0x60d52f0,
`AssertHeld` 0x60d5390 (empty body), `IsEmpty`/`NumNotFlushed`
helper 0x5f12a10, SuperVersion dtor 0x5d8d820, MemTable dtor
0x5f10d40, log::Writer dtor 0x5f04800. See `records.json` for the
full list with the census status of each.

## Cases

2,400 deterministic cases in `cases.tsv`, generated by
`tools/switch_memtable115.py` (`--write-cases`) and replayed by
`tests/test_switch_memtable115.py` (26 tests pass) and by the tool's
own `--verify-cases` (0 mismatches):

- 600 checks (25 modes: recoverable-fail, no-create, create-ok,
  create-fail, two-write-queues, two-write-queues-no-create,
  recycle-hit, recycle-empty, recycle-num-zero, write-buffer-fail,
  write-buffer-ok, logs-empty, recovery-in-progress,
  track-min-apply, track-min-no-apply, track-allow-2pc,
  track-no-create, log-and-apply-fail-ioerror,
  log-and-apply-fail-other, dropped-cf-excluded, plain-loop-multi,
  preallocate-max-total, preallocate-db-wbs, preallocate-wbm,
  mixed) -- the recoverable-state direct return, the no-create plain
  loop, the record step with empty `logs_`, the recycle reuse/pop,
  the WriteBuffer warn (two spaces) and error path, the min-WAL
  branch (empty CFs contribute the new log number, non-empty CFs
  their own, dropped CFs excluded) and the LogAndApply manifest
  failure, and the three-term preallocate formula.
- 600 status (6 kinds: ok, error, image, tostring, copy-assign,
  alloc-fail) -- the Status byte layout the ctor proves, the
  `': '` join, the ToString human phrases (never the `k` enum
  names), the copy-assign state_ steal, and the copy-ctor alloc
  failure raising BadAlloc.
- 600 throw (one armed fail_at per case across all 32 THROW_SITES,
  in 5 modes: throw, throw-bad-canary, badalloc-bad-canary,
  canary-return, alloc-false) -- each throwing call with its
  landing-pad stub and its .cold cleanup chain, the bad-canary
  StackCheckFailed, the AssertHeld no-pad propagation, and the
  alloc-site BadAlloc.
- 600 bindings (caller-site independence across the 6 caller sites,
  both FDE hashes as expected values).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The tool models the switch in Python from its whole-FDE
disassembly; the Status ctor, ToString, move-assign and
GetWalPreallocateBlockSize behaviors are pinned from their own
disassemblies. Status `state_` buffers are deterministic heap ids,
not real pointers; the subcode padding bytes (+0x6..+0x7) the binary
never writes are modelled as zero. The live check (`--live`) reads
the binary: both FDE body hashes, both source hashes, both FDE
records (lengths 0x4c/0x20, ranges 0x1c88/0xd4, aug_len 4, LSDA
pointers 0x4111c4/0x41124a), the LSDA call-site tables (21 + 1
entries, all cleanup), the 9 landing-pad stub mappings, the
engine-call counts, the field cmp instructions, the message bytes
and the 6-site caller census. `make verify/test/catalogue-check` in
a tooled environment is still owed upstream.

## Unknowns

- `WriteRecoverableState` (0x5e8a4e0), `CreateWAL` (0x5e5c270),
  `ConstructNewMemtable` (0x5d8ca00) and `LogAndApply` (0x5d68760)
  are taken as oracles -- only their status results are inputs to
  the model, their bodies are not modelled here.
- The exact `MemTableInfo` fields the binary copies at
  0x5e8ae91..0x5e8b05c (the copy-alloc ladder region) beyond
  `cf_name`/`first_seqno`/`earliest_seqno`/`num_entries`/
  `num_deletes`: the three vectors reallocated are modelled as the
  `MutableCFOptions` copy, but their individual element types were
  not all traced.
- Whether any caller other than the six found can reach this
  routine: the whole-.text scan finds exactly six validated sites,
  and the upstream source's WriteImpl call sites do not appear in
  this binary -- recorded as observed.
- The exact `VersionEdit` payload the track-and-verify branch builds
  (DeleteWalsBefore + the WalSet minimum): the edit is constructed
  and passed to LogAndApply, but its serialized bytes were not
  traced.
